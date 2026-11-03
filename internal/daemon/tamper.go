package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/clients"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/pin"
)

// Tamper watch (M7). `rover install` puts every stdio server behind
// `rover wrap`; anything running as the user (the agent included) can undo
// that by editing the client's config, and the next time the client starts
// the server runs with no gateway at all. roverd cannot prevent the edit,
// but it notices: it watches the DIRECTORY of each config rover installed
// into (so a file that is replaced, or removed and written again, is still
// seen), and on every change, and at start, it checks every server:
//
//   - a stdio server not running through RoverPath: "unwrapped" if it was
//     wrapped before, "unwrapped_server_added" if it is new (a rename is a
//     removal plus an addition);
//   - a server wrapped by another binary called rover: "rover_path_changed";
//   - a server rover cannot parse: "not_understood";
//   - a wrapped server that is gone: "server_removed".
//
// The baseline (which servers were wrapped, by which command) is saved in
// the state database, so an edit made while roverd was down is reported
// when it starts. Each alert is written to the audit log, notified once,
// and kept (in memory and in state meta/tamper) for `rover doctor` until
// the condition is gone or `rover install`/`uninstall` resolves it.
const (
	// AuditKindTamper is the audit "kind" of tamper events.
	AuditKindTamper = "tamper"
	// Audit actions of tamper events.
	AuditTamperAlert   = "alert"
	AuditTamperResolve = "resolve"
	AuditTamperForget  = "forget"

	TamperUnwrapped        = "unwrapped"
	TamperAdded            = "unwrapped_server_added"
	TamperRemoved          = "server_removed"
	TamperRoverPathChanged = "rover_path_changed"
	TamperNotUnderstood    = "not_understood"

	// DefaultTamperDebounce lets a burst of writes settle before re-reading.
	DefaultTamperDebounce = 500 * time.Millisecond
	// TamperRetryEvery re-adds the watch of a directory that was deleted
	// (no event will ever come from it again) and re-checks its files.
	TamperRetryEvery = 10 * time.Second
	// TamperWholeFile is the Server of a not_understood alert about a file
	// rover cannot parse at all.
	TamperWholeFile = "(whole file)"

	tamperSession = "tamper"
)

// TamperAlert is one server in a state rover did not leave it in.
type TamperAlert struct {
	File    string    `json:"file"`
	Server  string    `json:"server"` // scope/key
	Kind    string    `json:"kind"`
	Command string    `json:"command,omitempty"` // what it runs now
	Detail  string    `json:"detail,omitempty"`  // why a file is not understood
	At      time.Time `json:"at"`
}

type tamperState struct {
	mu       sync.Mutex
	files    map[string]clients.ConfigFile // by path
	dirs     map[string]bool               // watched directory -> watch added
	baseline map[string]map[string]string  // path -> server -> sha256 of its rover command
	alerts   map[string]TamperAlert        // path + "\x00" + server
	timers   map[string]*time.Timer
	watcher  *fsnotify.Watcher
	notes    *pin.Coalescer
}

func digest(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// startTamperWatch restores the saved baseline and alerts, watches every
// config's directory and checks every config once.
//
// The watcher exists even with no files: `rover install` adds the first one
// to a running roverd (tamper_resolve).
func (s *Server) startTamperWatch() error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("tamper watch: %w", err)
	}
	t := &s.tamper
	t.mu.Lock()
	t.files, t.dirs, t.timers, t.watcher = map[string]clients.ConfigFile{}, map[string]bool{}, map[string]*time.Timer{}, w
	t.baseline, t.alerts = s.loadTamper()
	t.notes = pin.NewCoalescer(tamperNotifier{s.o.Notifier}, s.o.Now)
	for _, cf := range s.o.TamperFiles {
		s.watchFileLocked(cf)
	}
	paths := make([]string, 0, len(t.files))
	for p := range t.files {
		paths = append(paths, p)
	}
	t.mu.Unlock()
	sort.Strings(paths)
	for _, p := range paths {
		s.checkTamper(p)
	}
	go s.tamperLoop(w)
	return nil
}

// watchFileLocked adds cf and its directory to the watch (t.mu held). A
// directory that cannot be watched is logged and retried on every later
// event and check, never silently dropped.
func (s *Server) watchFileLocked(cf clients.ConfigFile) {
	t := &s.tamper
	path := filepath.Clean(cf.Path)
	cf.Path = path
	t.files[path] = cf
	dir := filepath.Dir(path)
	if _, known := t.dirs[dir]; !known {
		t.dirs[dir] = false
	}
	s.retryDirsLocked()
}

// retryDirsLocked re-adds every directory whose watch is missing and
// returns the ones that came back (t.mu held).
func (s *Server) retryDirsLocked() []string {
	t := &s.tamper
	var back []string
	for dir, ok := range t.dirs {
		if ok || t.watcher == nil {
			continue
		}
		if err := t.watcher.Add(dir); err != nil {
			s.o.Logf("tamper watch: cannot watch %s (will retry): %v", dir, err)
			continue
		}
		t.dirs[dir] = true
		back = append(back, dir)
	}
	return back
}

// retryTick re-adds missing directory watches and re-checks the files in
// the directories that came back: a directory deleted and recreated sends
// no event to a watch that no longer exists.
func (s *Server) retryTick() {
	t := &s.tamper
	t.mu.Lock()
	back := map[string]bool{}
	for _, d := range s.retryDirsLocked() {
		back[d] = true
	}
	var recheck []string
	for p := range t.files {
		if back[filepath.Dir(p)] {
			recheck = append(recheck, p)
		}
	}
	t.mu.Unlock()
	sort.Strings(recheck)
	for _, p := range recheck {
		s.checkTamper(p)
	}
}

func (s *Server) tamperLoop(w *fsnotify.Watcher) {
	debounce := s.o.TamperDebounce
	if debounce <= 0 {
		debounce = DefaultTamperDebounce
	}
	retry := s.o.TamperRetry
	if retry == nil {
		tk := time.NewTicker(TamperRetryEvery)
		defer tk.Stop()
		retry = tk.C
	}
	for {
		select {
		case <-retry:
			s.retryTick()
		case ev, ok := <-w.Events:
			if !ok {
				return
			}
			name := filepath.Clean(ev.Name)
			t := &s.tamper
			t.mu.Lock()
			if ev.Has(fsnotify.Remove) || ev.Has(fsnotify.Rename) {
				if _, isDir := t.dirs[name]; isDir {
					t.dirs[name] = false // the directory itself went away
				}
			}
			s.retryDirsLocked()
			if _, watched := t.files[name]; watched {
				if tm := t.timers[name]; tm != nil {
					tm.Stop()
				}
				t.timers[name] = time.AfterFunc(debounce, func() { s.checkTamper(name) })
			}
			t.mu.Unlock()
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

// checkTamper re-reads one config and updates its alerts and baseline.
func (s *Server) checkTamper(path string) {
	t := &s.tamper
	t.mu.Lock()
	defer t.mu.Unlock()
	cf, ok := t.files[path]
	if !ok || t.watcher == nil {
		return
	}
	s.retryDirsLocked()
	doc, err := clients.ReadConfig(cf)
	if errors.Is(err, os.ErrNotExist) {
		doc, err = clients.Doc{File: cf}, nil // no file: every wrapped server is gone
	}
	var want map[string]TamperAlert
	var base map[string]string
	if err != nil {
		// A file rover cannot read is not "no servers": a client may still
		// load it (taking the last of two duplicate keys, say). One alert for
		// the whole file; the baseline is kept for when it parses again.
		want = map[string]TamperAlert{TamperWholeFile: {File: path, Server: TamperWholeFile, Kind: TamperNotUnderstood, Detail: capDetail(err.Error())}}
		base = t.baseline[path]
	} else {
		want, base = s.evaluate(path, doc)
	}
	t.baseline[path] = base
	var fresh []TamperAlert
	for k, a := range t.alerts {
		if a.File != path {
			continue
		}
		if n, still := want[a.Server]; !still || n.Kind != a.Kind || n.Command != a.Command || n.Detail != a.Detail {
			delete(t.alerts, k)
			if !still {
				s.o.Logf("tamper watch: %s in %s is fine again", pin.TerminalSafe(a.Server), path)
			}
		}
	}
	for server, a := range want {
		k := path + "\x00" + server
		if _, had := t.alerts[k]; !had {
			a.At = s.o.Now().UTC()
			t.alerts[k] = a
			fresh = append(fresh, a)
		}
	}
	s.saveTamperLocked()
	sort.Slice(fresh, func(i, j int) bool { return fresh[i].Server < fresh[j].Server })
	for _, a := range fresh {
		s.reportTamper(a)
	}
}

// evaluate returns the alerts doc deserves and its new baseline (t.mu held).
func (s *Server) evaluate(path string, doc clients.Doc) (map[string]TamperAlert, map[string]string) {
	old := s.tamper.baseline[path]
	want := map[string]TamperAlert{}
	base := map[string]string{}
	present := map[string]bool{}
	alert := func(sv clients.Server, kind string) {
		want[sv.Label()] = TamperAlert{File: path, Server: sv.Label(), Kind: kind, Command: sv.Command}
	}
	for _, sv := range doc.Servers {
		label := sv.Label()
		present[label] = true
		_, wasWrapped := old[label]
		if wasWrapped {
			base[label] = old[label] // stays in the baseline while it exists
		}
		switch {
		case sv.Status == clients.StatusWrapped && s.expectedRover(sv.Command, old[label]):
			base[label] = digest(sv.Command)
		case sv.Status == clients.StatusWrapped:
			alert(sv, TamperRoverPathChanged)
		case sv.Status == clients.StatusUnknown:
			alert(sv, TamperNotUnderstood)
		case sv.Status == clients.StatusStdio && !wasWrapped:
			alert(sv, TamperAdded)
		case sv.Status == clients.StatusStdio, wasWrapped: // stdio, or a wrapped server turned remote
			alert(sv, TamperUnwrapped)
		}
	}
	// A removed server stays in the baseline (and reported) until it is
	// back or install/uninstall resolves it, so a later re-add of it
	// unwrapped is "unwrapped", not a new server.
	for label, d := range old {
		if !present[label] {
			want[label] = TamperAlert{File: path, Server: label, Kind: TamperRemoved}
			base[label] = d
		}
	}
	return want, base
}

// expectedRover: the command is RoverPath, or with no RoverPath configured
// (tests, offline admin) the command the baseline recorded.
func (s *Server) expectedRover(cmd, baseDigest string) bool {
	if s.o.RoverPath != "" {
		return cmd == s.o.RoverPath
	}
	return baseDigest == "" || baseDigest == digest(cmd)
}

// reportTamper logs, audits and notifies one alert. Names in a config may
// have been written by an agent: the log and notification get them
// sanitised.
func (s *Server) reportTamper(a TamperAlert) {
	key := a.Server[strings.IndexByte(a.Server, '/')+1:]
	why := fmt.Sprintf("command %q", a.Command)
	if a.Detail != "" {
		why = a.Detail
	}
	s.o.Logf("TAMPER: %s in %s: %s (%s); run `rover doctor`", pin.TerminalSafe(a.Server), a.File, a.Kind, pin.TerminalSafe(why))
	e := audit.Entry{Time: a.At, Session: tamperSession, Server: ipc.SanitizeServerName(key), Kind: AuditKindTamper,
		Action: AuditTamperAlert, Reason: a.Kind + ":" + a.File, Findings: []string{a.Server}}
	if err := s.writeAudit(e); err != nil {
		s.o.Logf("tamper watch: audit write failed: %v", err)
	}
	msg := fmt.Sprintf("%s in %s is no longer wrapped by rover (%s). run `rover doctor`.", ipc.SanitizeServerName(key), a.File, a.Kind)
	s.tamper.notes.Add("tamper:"+a.File, 1, msg)
}

// capDetail bounds the parse error kept in an alert (it can quote keys).
func capDetail(s string) string {
	if len(s) > 300 {
		return s[:300] + "..."
	}
	return s
}
