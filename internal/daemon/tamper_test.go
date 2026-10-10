package daemon

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/clients"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/state"
)

const tamperRover = "/opt/rover/bin/rover"

func wrappedConfig(cmd string) string {
	return `{"mcpServers": {"fs": {"command": "` + cmd + `", "args": ["wrap", "--name", "fs", "--", "npx", "fs"]}, "other": {"url": "https://x"}}}`
}

// waitAlerts polls until n alerts exist (the watch is asynchronous).
func waitAlerts(t *testing.T, s *Server, n int) []TamperAlert {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if as := s.TamperAlerts(); len(as) == n {
			return as
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("want %d tamper alerts, have %v", n, s.TamperAlerts())
	return nil
}

// Acceptance (M7): a hand edit that unwraps a server is noticed (real
// fsnotify, a fixture config in a temp dir), audited, notified and saved
// for `rover doctor`; a look-alike rover path is noticed too; re-wrapping
// clears the alert.
func TestTamperWatchDetectsUnwrap(t *testing.T) {
	dir := shortTempDir(t)
	cfg := filepath.Join(dir, "mcp.json")
	if err := os.WriteFile(cfg, []byte(wrappedConfig(tamperRover)), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := state.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var log bytes.Buffer
	lw := &lockedWriter{w: &log}
	notes := &recordingNotifier{}
	s := start(t, Options{Audit: audit.New(lw), State: db, Notifier: notes,
		TamperFiles:    []clients.ConfigFile{{Adapter: clients.NameCursor, Path: cfg, Scope: "global"}},
		TamperDebounce: 50 * time.Millisecond})

	// Unwrap by hand, in place.
	if err := os.WriteFile(cfg, []byte(`{"mcpServers": {"fs": {"command": "npx", "args": ["fs"]}, "other": {"url": "https://x"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	as := waitAlerts(t, s, 1)
	if as[0].Kind != TamperUnwrapped || as[0].Server != "global/fs" || as[0].File != cfg {
		t.Fatalf("alert %+v", as[0])
	}
	if !strings.Contains(lw.String(), `"kind":"tamper"`) || !strings.Contains(lw.String(), `"action":"alert"`) {
		t.Fatalf("no tamper audit entry:\n%s", lw.String())
	}
	if m := notes.all(); len(m) != 1 || !strings.Contains(m[0], "no longer wrapped") {
		t.Fatalf("notifications %v", m)
	}
	// doctor_state reports it, and so does the state database.
	r := s.Admin(ipc.Frame{Type: ipc.TypeAdmin, Op: ipc.OpDoctorState})
	var ds DoctorState
	if err := json.Unmarshal(r.Result, &ds); err != nil || len(ds.TamperAlerts) != 1 || ds.WatchedFiles != 1 {
		t.Fatalf("doctor_state %s %v", r.Result, err)
	}
	if saved := s.loadTamperAlerts(); len(saved) != 1 {
		t.Fatalf("saved alerts %v", saved)
	}

	// Re-wrap with an atomic replace: the alert clears.
	writeReplace(t, cfg, wrappedConfig(tamperRover))
	waitAlerts(t, s, 0)

	// A look-alike rover binary is an alert of its own kind.
	writeReplace(t, cfg, wrappedConfig("/tmp/evil/rover"))
	as = waitAlerts(t, s, 1)
	if as[0].Kind != TamperRoverPathChanged || as[0].Command != "/tmp/evil/rover" {
		t.Fatalf("alert %+v", as[0])
	}
}

// writeReplace writes like an editor or rover install: temp file + rename.
func writeReplace(t *testing.T, path, content string) {
	t.Helper()
	if err := clients.WriteAtomic(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

type lockedWriter struct {
	mu sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func (l *lockedWriter) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.String()
}
