package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	bolt "go.etcd.io/bbolt"

	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/clients"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/pin"
	"github.com/DreadpiratePickles/rover/internal/state"
)

// Tamper watch (M7). `rover install` puts every stdio server behind
// `rover wrap`; an agent (or anything else running as the user) can undo
// that by editing the client's config, and the next time the client starts
// the server runs with no gateway at all. roverd cannot prevent the edit,
// but it can notice it: it watches the config files, and when a server that
// was wrapped is no longer wrapped, or now runs a different rover binary, it
// writes an audit entry, shows a desktop notification and remembers the
// alert (in memory and in the state database) for `rover doctor`.
const (
	// AuditKindTamper is the audit "kind" of tamper alerts.
	AuditKindTamper = "tamper"
	// AuditTamperAlert is their action.
	AuditTamperAlert = "alert"
	// TamperUnwrapped: the server no longer runs through rover wrap.
	TamperUnwrapped = "unwrapped"
	// TamperRoverPathChanged: it still says `rover wrap`, but through a
	// different binary (a look-alike path, or a stale install).
	TamperRoverPathChanged = "rover_path_changed"
	// DefaultTamperDebounce lets a burst of writes settle before re-reading.
	DefaultTamperDebounce = 500 * time.Millisecond

	tamperSession = "tamper"
)

// metaTamper is the key of the alerts in the state bucket "meta".
var metaTamper = []byte("tamper")

// TamperAlert is one server found unwrapped.
type TamperAlert struct {
	File    string    `json:"file"`
	Server  string    `json:"server"` // scope/key
	Kind    string    `json:"kind"`
	Command string    `json:"command,omitempty"` // what it runs now
	At      time.Time `json:"at"`
}

type tamperState struct {
	mu       sync.Mutex
	files    map[string]clients.ConfigFile
	baseline map[string]map[string]string // file -> server -> rover command
	alerts   map[string]TamperAlert       // file + "\x00" + server
	timers   map[string]*time.Timer
	watcher  *fsnotify.Watcher
	notes    *pin.Coalescer
}

// startTamperWatch reads every watched file once (the baseline of wrapped
// servers), restores earlier alerts from the state database, and starts
// watching. A file that cannot be watched is logged and skipped: the watch
// is an alarm, not a gate, and doctor reports the config as it is anyway.
func (s *Server) startTamperWatch() error {
	if len(s.o.TamperFiles) == 0 {
		return nil
	}
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("tamper watch: %w", err)
	}
	t := &s.tamper
	t.mu.Lock()
	t.files, t.baseline, t.alerts, t.timers, t.watcher = map[string]clients.ConfigFile{}, map[string]map[string]string{}, map[string]TamperAlert{}, map[string]*time.Timer{}, w
	t.notes = pin.NewCoalescer(tamperNotifier{s.o.Notifier}, s.o.Now)
	for _, a := range s.loadTamperAlerts() {
		t.alerts[a.File+"\x00"+a.Server] = a
	}
	t.mu.Unlock()
	for _, cf := range s.o.TamperFiles {
		t.mu.Lock()
		t.files[cf.Path] = cf
		t.mu.Unlock()
		if err := w.Add(cf.Path); err != nil {
			s.o.Logf("tamper watch: cannot watch %s: %v", cf.Path, err)
			continue
		}
		s.checkTamper(cf.Path)
	}
	go s.tamperLoop(w)
	return nil
}

func (s *Server) tamperLoop(w *fsnotify.Watcher) {
	debounce := s.o.TamperDebounce
	if debounce <= 0 {
		debounce = DefaultTamperDebounce
	}
	for {
		select {
		case ev, ok := <-w.Events:
			if !ok {
				return
			}
			s.tamper.mu.Lock()
			if _, watched := s.tamper.files[ev.Name]; watched {
				if tm := s.tamper.timers[ev.Name]; tm != nil {
					tm.Stop()
				}
				name := ev.Name
				s.tamper.timers[name] = time.AfterFunc(debounce, func() { s.checkTamper(name) })
			}
			s.tamper.mu.Unlock()
		case err, ok := <-w.Errors:
			if !ok {
				return
			}
			s.o.Logf("tamper watch: %v", err)
		}
	}
}

func (s *Server) stopTamperWatch() {
	t := &s.tamper
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, tm := range t.timers {
		tm.Stop()
	}
	if t.watcher != nil {
		_ = t.watcher.Close()
		t.watcher = nil
	}
}

// checkTamper re-reads one file and compares it with the baseline.
func (s *Server) checkTamper(path string) {
	t := &s.tamper
	t.mu.Lock()
	defer t.mu.Unlock()
	cf, ok := t.files[path]
	if !ok || t.watcher == nil {
		return
	}
	// An atomic replace (rename over the file) ends the old watch; watch the
	// new file before reading it, so no later change is missed.
	_ = t.watcher.Remove(path)
	_ = t.watcher.Add(path)
	doc, err := clients.ReadConfig(cf)
	if errors.Is(err, os.ErrNotExist) {
		return // a removed config starts no servers at all
	}
	if err != nil {
		s.o.Logf("tamper watch: %s does not parse (%v); its servers are not checked until it does", path, err)
		return
	}
	now := map[string]clients.Server{}
	for _, sv := range doc.Servers {
		now[sv.Label()] = sv
	}
	base := t.baseline[path]
	if base == nil {
		base = map[string]string{}
		t.baseline[path] = base
	}
	var fresh []TamperAlert
	changed := false
	for label, cmd := range base {
		sv, ok := now[label]
		key := path + "\x00" + label
		switch {
		case !ok:
			delete(base, label) // removed: nothing runs, nothing to alert
		case sv.Status == clients.StatusWrapped && sv.Command == cmd:
			if _, had := t.alerts[key]; had {
				delete(t.alerts, key)
				changed = true
				s.o.Logf("tamper watch: %s in %s is wrapped again", label, path)
			}
		default:
			kind := TamperUnwrapped
			if sv.Status == clients.StatusWrapped {
				kind = TamperRoverPathChanged
			}
			if a, had := t.alerts[key]; had && a.Kind == kind && a.Command == sv.Command {
				continue
			}
			a := TamperAlert{File: path, Server: label, Kind: kind, Command: sv.Command, At: s.o.Now().UTC()}
			t.alerts[key] = a
			fresh = append(fresh, a)
			changed = true
		}
	}
	for label, sv := range now {
		if _, known := base[label]; !known && sv.Status == clients.StatusWrapped {
			base[label] = sv.Command
		}
	}
	if changed {
		s.saveTamperAlerts(t.alertList())
	}
	for _, a := range fresh {
		s.reportTamper(a)
	}
}

// reportTamper logs, audits and notifies one alert. Names in the config are
// the user's file, but an agent may have written them: the log and the
// notification get them sanitised.
func (s *Server) reportTamper(a TamperAlert) {
	key := a.Server[strings.IndexByte(a.Server, '/')+1:]
	s.o.Logf("TAMPER: %s in %s is %s (command %q); run `rover doctor`", pin.TerminalSafe(a.Server), a.File, a.Kind, pin.TerminalSafe(a.Command))
	e := audit.Entry{Time: a.At, Session: tamperSession, Server: ipc.SanitizeServerName(key), Kind: AuditKindTamper,
		Action: AuditTamperAlert, Reason: a.Kind + ":" + a.File, Findings: []string{a.Server}}
	if err := s.writeAudit(e); err != nil {
		s.o.Logf("tamper watch: audit write failed: %v", err)
	}
	msg := fmt.Sprintf("%s in %s is no longer wrapped by rover (%s). run `rover doctor`.", ipc.SanitizeServerName(key), a.File, a.Kind)
	s.tamper.notes.Add("tamper:"+a.File, 1, msg)
}

// alertList returns the alerts sorted (t.mu held).
func (t *tamperState) alertList() []TamperAlert {
	out := make([]TamperAlert, 0, len(t.alerts))
	for _, a := range t.alerts {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].File+out[i].Server < out[j].File+out[j].Server })
	return out
}

// TamperAlerts returns the current alerts (for doctor and tests).
func (s *Server) TamperAlerts() []TamperAlert {
	s.tamper.mu.Lock()
	defer s.tamper.mu.Unlock()
	return s.tamper.alertList()
}

func (s *Server) saveTamperAlerts(as []TamperAlert) {
	if s.o.State == nil {
		return
	}
	b, err := json.Marshal(as)
	if err == nil {
		err = s.o.State.Update(func(tx *bolt.Tx) error { return tx.Bucket(state.BucketMeta).Put(metaTamper, b) })
	}
	if err != nil {
		s.o.Logf("tamper watch: saving alerts: %v", err)
	}
}

func (s *Server) loadTamperAlerts() []TamperAlert {
	if s.o.State == nil {
		return nil
	}
	var as []TamperAlert
	err := s.o.State.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(state.BucketMeta).Get(metaTamper); b != nil {
			return json.Unmarshal(b, &as)
		}
		return nil
	})
	if err != nil {
		s.o.Logf("tamper watch: reading saved alerts: %v", err)
	}
	return as
}

// DoctorState is the doctor_state admin result.
type DoctorState struct {
	Mode          string        `json:"mode"`
	PolicyLoaded  bool          `json:"policy_loaded"`
	WatchedFiles  int           `json:"watched_files"`
	TamperAlerts  []TamperAlert `json:"tamper_alerts"`
	AuditHealthy  bool          `json:"audit_healthy"`
	ServerVersion int           `json:"protocol_version"`
}

func (s *Server) doctorState() ipc.Frame {
	l := s.pol.Load()
	s.mu.Lock()
	healthy := !s.unhealthy
	s.mu.Unlock()
	s.tamper.mu.Lock()
	n := len(s.tamper.files)
	alerts := s.tamper.alertList()
	s.tamper.mu.Unlock()
	if alerts == nil && n == 0 {
		alerts = s.loadTamperAlerts() // no watch running: report what was saved
	}
	return adminResult(DoctorState{Mode: string(l.cfg.Mode), PolicyLoaded: l.pol != nil, WatchedFiles: n,
		TamperAlerts: alerts, AuditHealthy: healthy, ServerVersion: ipc.Version}, "")
}

// tamperNotifier gives tamper notifications their own title. The pin
// coalescer's summary text ("N tools changed on ...") is about tools, so a
// coalesced burst is replaced with a tamper summary.
type tamperNotifier struct{ next pin.Notifier }

const tamperTitle = "rover: client config changed"

func (n tamperNotifier) Notify(_, msg string) {
	if !strings.Contains(msg, "no longer wrapped by rover") {
		msg = "several mcp servers are no longer wrapped by rover. run `rover doctor`."
	}
	n.next.Notify(tamperTitle, msg)
}
