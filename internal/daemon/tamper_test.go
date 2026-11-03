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

func wrappedServer(key, cmd string) string {
	return `"` + key + `": {"command": "` + cmd + `", "args": ["wrap", "--name", "` + key + `", "--", "npx", "fs"]}`
}

func mcpConfig(servers ...string) string {
	return `{"mcpServers": {` + strings.Join(append(servers, `"other": {"type": "http", "url": "https://x"}`), ", ") + `}}`
}

const unwrappedFS = `"fs": {"command": "npx", "args": ["fs"]}`

// tamperRig is a roverd with a tamper watch on one config in a temp dir.
type tamperRig struct {
	cfg   string
	db    *state.DB
	log   *lockedWriter
	notes *recordingNotifier
	s     *Server
}

func newTamperRig(t *testing.T, content string) *tamperRig {
	t.Helper()
	dir := shortTempDir(t)
	r := &tamperRig{cfg: filepath.Join(dir, "mcp.json"), log: &lockedWriter{w: &bytes.Buffer{}}, notes: &recordingNotifier{}}
	if err := os.WriteFile(r.cfg, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := state.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	r.db = db
	r.s = start(t, r.options())
	return r
}

func (r *tamperRig) options() Options {
	return Options{Audit: audit.New(r.log), State: r.db, Notifier: r.notes, RoverPath: tamperRover,
		TamperFiles:    []clients.ConfigFile{{Adapter: clients.NameCursor, Path: r.cfg, Scope: "global"}},
		TamperDebounce: 50 * time.Millisecond}
}

// waitKinds polls until the alerts have exactly these kinds (sorted by server).
func waitKinds(t *testing.T, s *Server, kinds ...string) []TamperAlert {
	t.Helper()
	var as []TamperAlert
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		as = s.TamperAlerts()
		got := make([]string, len(as))
		for i, a := range as {
			got[i] = a.Kind
		}
		if strings.Join(got, ",") == strings.Join(kinds, ",") {
			return as
		}
	}
	t.Fatalf("want tamper alerts %v, have %+v", kinds, as)
	return nil
}

// Acceptance (M7): a hand edit that unwraps a server is noticed (real
// fsnotify), audited, notified and saved for `rover doctor`; re-wrapping
// clears it; a look-alike rover path is its own kind.
func TestTamperWatchDetectsUnwrap(t *testing.T) {
	r := newTamperRig(t, mcpConfig(wrappedServer("fs", tamperRover)))
	writeInPlace(t, r.cfg, mcpConfig(unwrappedFS))
	as := waitKinds(t, r.s, TamperUnwrapped)
	if as[0].Server != "global/fs" || as[0].File != r.cfg {
		t.Fatalf("alert %+v", as[0])
	}
	if l := r.log.String(); !strings.Contains(l, `"kind":"tamper"`) || !strings.Contains(l, `"action":"alert"`) {
		t.Fatalf("no tamper audit entry:\n%s", l)
	}
	if m := r.notes.all(); len(m) != 1 || !strings.Contains(m[0], "no longer wrapped") {
		t.Fatalf("notifications %v", m)
	}
	res := r.s.Admin(ipc.Frame{Type: ipc.TypeAdmin, Op: ipc.OpDoctorState})
	var ds DoctorState
	if err := json.Unmarshal(res.Result, &ds); err != nil || len(ds.TamperAlerts) != 1 || ds.WatchedFiles != 1 {
		t.Fatalf("doctor_state %s %v", res.Result, err)
	}
	writeReplace(t, r.cfg, mcpConfig(wrappedServer("fs", tamperRover)))
	waitKinds(t, r.s)
	writeReplace(t, r.cfg, mcpConfig(wrappedServer("fs", "/tmp/evil/rover")))
	if as := waitKinds(t, r.s, TamperRoverPathChanged); as[0].Command != "/tmp/evil/rover" {
		t.Fatalf("alert %+v", as[0])
	}
}

// H1a: deleting a wrapped server, then adding it back unwrapped, alerts
// both times; so does renaming its key.
func TestTamperDeleteThenReAdd(t *testing.T) {
	r := newTamperRig(t, mcpConfig(wrappedServer("fs", tamperRover)))
	writeInPlace(t, r.cfg, mcpConfig())
	waitKinds(t, r.s, TamperRemoved)
	writeInPlace(t, r.cfg, mcpConfig(unwrappedFS))
	waitKinds(t, r.s, TamperUnwrapped)
}

func TestTamperKeyRename(t *testing.T) {
	r := newTamperRig(t, mcpConfig(wrappedServer("fs", tamperRover)))
	writeReplace(t, r.cfg, mcpConfig(`"fs2": {"command": "npx", "args": ["fs"]}`))
	as := waitKinds(t, r.s, TamperRemoved, TamperAdded)
	if as[0].Server != "global/fs" || as[1].Server != "global/fs2" {
		t.Fatalf("%+v", as)
	}
}

// H1b: removing the file and writing it again later is still watched.
func TestTamperRemoveThenRewrite(t *testing.T) {
	r := newTamperRig(t, mcpConfig(wrappedServer("fs", tamperRover)))
	if err := os.Remove(r.cfg); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	writeInPlace(t, r.cfg, mcpConfig(unwrappedFS))
	waitKinds(t, r.s, TamperUnwrapped)
}

// H1: a new stdio server in a watched config is an alert of its own.
func TestTamperNewUnwrappedServer(t *testing.T) {
	r := newTamperRig(t, mcpConfig(wrappedServer("fs", tamperRover)))
	writeInPlace(t, r.cfg, mcpConfig(wrappedServer("fs", tamperRover), `"sneaky": {"command": "sh"}`))
	waitKinds(t, r.s, TamperAdded)
}

// H1: a server unwrapped while roverd was down is alerted at start, from
// the saved baseline.
func TestTamperWhileDown(t *testing.T) {
	r := newTamperRig(t, mcpConfig(wrappedServer("fs", tamperRover)))
	r.s.Close()
	writeInPlace(t, r.cfg, mcpConfig())
	o := r.options()
	o.SocketPath = filepath.Join(shortTempDir(t), "d2.sock")
	s2 := New(o)
	if err := s2.Listen(); err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if as := s2.TamperAlerts(); len(as) != 1 || as[0].Kind != TamperRemoved {
		t.Fatalf("alerts at start: %+v", as)
	}
}

// LOW: install and uninstall tell roverd, which re-baselines (or stops
// watching) and clears the alerts they cause; both are audited.
func TestTamperResolveAndForget(t *testing.T) {
	r := newTamperRig(t, mcpConfig(wrappedServer("fs", tamperRover)))
	writeInPlace(t, r.cfg, mcpConfig(unwrappedFS))
	waitKinds(t, r.s, TamperUnwrapped)
	writeInPlace(t, r.cfg, mcpConfig(wrappedServer("fs", tamperRover)))
	if f := r.s.Admin(ipc.Frame{Type: ipc.TypeAdmin, Op: ipc.OpTamperResolve, Path: r.cfg, Adapter: clients.NameCursor, Scope: "global"}); f.Type != ipc.TypeAdminResult {
		t.Fatalf("resolve: %+v", f)
	}
	waitKinds(t, r.s)
	if f := r.s.Admin(ipc.Frame{Type: ipc.TypeAdmin, Op: ipc.OpTamperForget, Path: r.cfg}); f.Type != ipc.TypeAdminResult {
		t.Fatalf("forget: %+v", f)
	}
	writeInPlace(t, r.cfg, mcpConfig(unwrappedFS)) // what uninstall does
	time.Sleep(300 * time.Millisecond)
	if as := r.s.TamperAlerts(); len(as) != 0 {
		t.Fatalf("alerts after forget: %+v", as)
	}
	if l := r.log.String(); !strings.Contains(l, `"action":"resolve"`) || !strings.Contains(l, `"action":"forget"`) {
		t.Fatalf("not audited:\n%s", l)
	}
}

func writeInPlace(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
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

// N1: a config Rover cannot parse (a client may read it anyway, taking the
// last of two duplicate keys) is an alert for the whole file.
func TestTamperUnparsableFile(t *testing.T) {
	r := newTamperRig(t, mcpConfig(wrappedServer("c", tamperRover)))
	writeReplace(t, r.cfg, `{"mcpServers": {`+wrappedServer("c", tamperRover)+`, "c": {"command": "npx"}}}`)
	as := waitKinds(t, r.s, TamperNotUnderstood)
	if as[0].Server != TamperWholeFile || !strings.Contains(as[0].Detail, "duplicate") {
		t.Fatalf("%+v", as[0])
	}
	if l := r.log.String(); !strings.Contains(l, `"reason":"not_understood:`) {
		t.Fatalf("not audited:\n%s", l)
	}
	writeReplace(t, r.cfg, mcpConfig(wrappedServer("c", tamperRover)))
	waitKinds(t, r.s)
	big := mcpConfig(wrappedServer("c", tamperRover)) + strings.Repeat(" ", clients.MaxConfig)
	writeReplace(t, r.cfg, big)
	if as := waitKinds(t, r.s, TamperNotUnderstood); !strings.Contains(as[0].Detail, "larger than") {
		t.Fatalf("%+v", as[0])
	}
}

// N2: a roverd started before anything was installed still watches the
// first config `rover install` reports.
func TestTamperWatchStartsEmpty(t *testing.T) {
	r := newTamperRig(t, mcpConfig(wrappedServer("fs", tamperRover)))
	o := r.options()
	o.TamperFiles = nil
	o.SocketPath = filepath.Join(shortTempDir(t), "e.sock")
	s := start(t, o)
	res := s.Admin(ipc.Frame{Type: ipc.TypeAdmin, Op: ipc.OpTamperResolve, Path: r.cfg, Adapter: clients.NameCursor, Scope: "global"})
	if res.Type != ipc.TypeAdminResult || !strings.Contains(string(res.Result), `"watching":true`) {
		t.Fatalf("resolve: %+v %s", res, res.Result)
	}
	writeInPlace(t, r.cfg, mcpConfig(unwrappedFS))
	waitKinds(t, s, TamperUnwrapped)
}

// N3: a config directory that is deleted and recreated is watched again on
// the periodic retry (an injected tick), and its file is re-checked.
func TestTamperDirectoryRecreated(t *testing.T) {
	dir := filepath.Join(shortTempDir(t), "cursor")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "mcp.json")
	writeInPlace(t, cfg, mcpConfig(wrappedServer("fs", tamperRover)))
	tick := make(chan time.Time)
	db, err := state.Open(filepath.Join(filepath.Dir(dir), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := start(t, Options{Audit: audit.New(&lockedWriter{w: &bytes.Buffer{}}), State: db, Notifier: &recordingNotifier{}, RoverPath: tamperRover,
		TamperFiles:    []clients.ConfigFile{{Adapter: clients.NameCursor, Path: cfg, Scope: "global"}},
		TamperDebounce: 50 * time.Millisecond, TamperRetry: tick})
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	waitKinds(t, s, TamperRemoved)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeInPlace(t, cfg, mcpConfig(unwrappedFS, `"new": {"command": "sh"}`))
	tick <- time.Now()
	waitKinds(t, s, TamperUnwrapped, TamperAdded)
}
