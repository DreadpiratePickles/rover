package daemon

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"

	bolt "go.etcd.io/bbolt"

	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/clients"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/pin"
	"github.com/DreadpiratePickles/rover/internal/state"
)

// Keys of the tamper watch in the state bucket "meta".
var (
	metaTamper         = []byte("tamper")          // []TamperAlert
	metaTamperBaseline = []byte("tamper_baseline") // path -> server -> digest
)

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

// saveTamperLocked writes alerts and baseline in one transaction (t.mu held).
func (s *Server) saveTamperLocked() {
	if s.o.State == nil {
		return
	}
	alerts, err := json.Marshal(s.tamper.alertList())
	if err != nil {
		s.o.Logf("tamper watch: saving alerts: %v", err)
		return
	}
	base, err := json.Marshal(s.tamper.baseline)
	if err != nil {
		s.o.Logf("tamper watch: saving baseline: %v", err)
		return
	}
	err = s.o.State.Update(func(tx *bolt.Tx) error {
		m := tx.Bucket(state.BucketMeta)
		if perr := m.Put(metaTamper, alerts); perr != nil {
			return perr
		}
		return m.Put(metaTamperBaseline, base)
	})
	if err != nil {
		s.o.Logf("tamper watch: saving state: %v", err)
	}
}

// loadTamper reads the saved baseline and alerts. A value that does not
// decode is logged and treated as empty: every stdio server still alerts,
// only "removed" needs the baseline.
func (s *Server) loadTamper() (map[string]map[string]string, map[string]TamperAlert) {
	base, alerts := map[string]map[string]string{}, map[string]TamperAlert{}
	if s.o.State == nil {
		return base, alerts
	}
	var list []TamperAlert
	err := s.o.State.View(func(tx *bolt.Tx) error {
		m := tx.Bucket(state.BucketMeta)
		if b := m.Get(metaTamperBaseline); b != nil {
			if err := json.Unmarshal(b, &base); err != nil {
				return err
			}
		}
		if b := m.Get(metaTamper); b != nil {
			return json.Unmarshal(b, &list)
		}
		return nil
	})
	if err != nil {
		s.o.Logf("tamper watch: reading saved state: %v", err)
		return map[string]map[string]string{}, alerts
	}
	for _, a := range list {
		alerts[a.File+"\x00"+a.Server] = a
	}
	if base == nil {
		base = map[string]map[string]string{}
	}
	return base, alerts
}

// tamperAdmin handles tamper_resolve and tamper_forget.
func (s *Server) tamperAdmin(f ipc.Frame) ipc.Frame {
	path := filepath.Clean(f.Path)
	t := &s.tamper
	t.mu.Lock()
	running := t.watcher != nil
	cf, known := t.files[path]
	t.mu.Unlock()
	if f.Op == ipc.OpTamperResolve && !known {
		if _, err := clients.Get(f.Adapter, clients.Env{}); err != nil {
			return ipc.Frame{Type: ipc.TypeError, Message: err.Error()}
		}
		cf = clients.ConfigFile{Adapter: f.Adapter, Path: path, Scope: f.Scope}
	}
	if !running {
		return adminResult(map[string]bool{"watching": false}, "roverd is not watching client configs")
	}
	t.mu.Lock()
	for k, a := range t.alerts {
		if a.File == path {
			delete(t.alerts, k)
		}
	}
	delete(t.baseline, path)
	action := AuditTamperForget
	if f.Op == ipc.OpTamperResolve {
		action = AuditTamperResolve
		s.watchFileLocked(cf)
		t.baseline[path] = map[string]string{}
		if doc, err := clients.ReadConfig(cf); err == nil {
			for _, sv := range doc.Servers {
				if sv.Status == clients.StatusWrapped && s.expectedRover(sv.Command, "") {
					t.baseline[path][sv.Label()] = digest(sv.Command)
				}
			}
		}
	} else {
		delete(t.files, path)
	}
	s.saveTamperLocked()
	t.mu.Unlock()
	s.o.Logf("tamper watch: %s %s by the CLI", action, path)
	if err := s.writeAudit(audit.Entry{Time: s.o.Now().UTC(), Session: adminSession, Kind: AuditKindTamper, Action: action, Reason: path}); err != nil {
		return ipc.Frame{Type: ipc.TypeError, Message: err.Error()}
	}
	t.mu.Lock()
	known = t.files[path].Path != ""
	t.mu.Unlock()
	if known {
		s.checkTamper(path)
	}
	return adminResult(map[string]bool{"watching": known}, "")
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
	if len(alerts) == 0 && n == 0 {
		_, saved := s.loadTamper() // no watch running: report what was saved
		for _, a := range saved {
			alerts = append(alerts, a)
		}
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
