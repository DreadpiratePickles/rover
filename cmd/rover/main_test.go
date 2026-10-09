//go:build unix

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/paths"
)

// The binaries under test, built once by TestMain.
var roverBin, echoBin string

func TestMain(m *testing.M) {
	os.Exit(buildAndRun(m))
}

func buildAndRun(m *testing.M) int {
	dir, err := os.MkdirTemp("", "rover-e2e-bin")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = os.RemoveAll(dir) }()
	roverBin = filepath.Join(dir, "rover")
	echoBin = filepath.Join(dir, "echo-server")
	for bin, pkg := range map[string]string{roverBin: ".", echoBin: "../../examples/echo-server"} {
		if out, err := exec.Command("go", "build", "-o", bin, pkg).CombinedOutput(); err != nil { //nolint:gosec // G204: test builds fixed packages into a temp dir
			fmt.Fprintf(os.Stderr, "build %s: %v\n%s", pkg, err, out)
			return 1
		}
	}
	return m.Run()
}

// roverEnv makes a private ROVER_DIR for one test and returns it with the
// environment to run rover in. Nothing touches the real home directory. It
// registers a cleanup that stops any roverd started under that dir and
// fails the test if one is still running afterwards.
func roverEnv(t *testing.T, extra ...string) (string, []string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: a directory needs its x bit; 0700 is owner-only, which rover requires of ROVER_DIR
		t.Fatal(err)
	}
	if len(filepath.Join(dir, "run", "roverd.sock")) > paths.MaxSocketPath {
		// A long TMPDIR (macOS) would push the socket into the shared
		// fallback dir; use a short private dir instead.
		short, err := os.MkdirTemp("", "rv")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(short) })
		dir = short
	}
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "ROVER_") {
			env = append(env, kv)
		}
	}
	env = append(env, "ROVER_DIR="+dir)
	env = append(env, extra...)
	t.Cleanup(func() { stopDaemon(t, dir) })
	return dir, env
}

// daemonRunning reports whether a roverd holds run/roverd.pid's lock, and
// the pid written in it.
func daemonRunning(t *testing.T, dir string) (bool, int) {
	t.Helper()
	path := filepath.Join(dir, "run", "roverd.pid")
	f, err := os.OpenFile(path, os.O_RDWR, 0) //nolint:gosec // G304: inside the test's ROVER_DIR
	if errors.Is(err, os.ErrNotExist) {
		return false, 0
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	b, _ := io.ReadAll(f)
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	fd := int(f.Fd())
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return true, pid // locked: roverd is alive
	}
	_ = unix.Flock(fd, unix.LOCK_UN)
	return false, pid
}

// stopDaemon sends SIGTERM to the roverd of dir (if any) and waits until it
// has let go of its pid file lock.
func stopDaemon(t *testing.T, dir string) {
	t.Helper()
	running, pid := daemonRunning(t, dir)
	if !running {
		return
	}
	if pid <= 0 {
		// Locked but no pid yet: roverd is between flock and write.
		time.Sleep(200 * time.Millisecond)
		if running, pid = daemonRunning(t, dir); !running {
			return
		}
	}
	_ = syscall.Kill(pid, syscall.SIGTERM)
	if waitUntil(10*time.Second, func() bool { r, _ := daemonRunning(t, dir); return !r }) {
		return
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	if !waitUntil(10*time.Second, func() bool { r, _ := daemonRunning(t, dir); return !r }) {
		t.Errorf("roverd (pid %d) for %s is still running", pid, dir)
	}
}

func waitUntil(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
	return true
}

// rover runs a rover command to completion and returns stdout, stderr and
// the exit code.
func rover(t *testing.T, env []string, args ...string) (string, string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, roverBin, args...) //nolint:gosec // G204: test runs the binary it just built
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		code = ee.ExitCode()
	case err != nil:
		t.Fatalf("rover %v: %v", args, err)
	}
	return stdout.String(), stderr.String(), code
}

// lockedBuffer is a bytes.Buffer that a test can read while exec copies a
// child's output into it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// wrapper is one running `rover wrap` with pipes to its stdio.
type wrapper struct {
	t      *testing.T
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	out    *bufio.Reader
	stderr *lockedBuffer
	cancel context.CancelFunc
}

func startWrap(t *testing.T, env []string, args ...string) *wrapper {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	cmd := exec.CommandContext(ctx, roverBin, append([]string{"wrap"}, args...)...) //nolint:gosec // G204: test runs the binary it just built
	cmd.Env = env
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	w := &wrapper{t: t, cmd: cmd, stdin: stdin, out: bufio.NewReader(stdout), stderr: &lockedBuffer{}, cancel: cancel}
	cmd.Stderr = w.stderr
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})
	return w
}

func (w *wrapper) send(s string) {
	w.t.Helper()
	if _, err := fmt.Fprintln(w.stdin, s); err != nil {
		w.t.Fatalf("write: %v", err)
	}
}

func (w *wrapper) recv() map[string]any {
	w.t.Helper()
	line, err := w.out.ReadBytes('\n')
	if err != nil {
		w.t.Fatalf("read: %v (stderr: %s)", err, w.stderr.String())
	}
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		w.t.Fatalf("bad json %q", line)
	}
	return m
}

// finish closes the wrapper's stdin and returns its exit code.
func (w *wrapper) finish() int {
	w.t.Helper()
	_ = w.stdin.Close()
	err := w.cmd.Wait()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	if err != nil {
		w.t.Fatalf("wrapper: %v", err)
	}
	return 0
}

const initialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}`

func (w *wrapper) initialize() {
	w.t.Helper()
	w.send(initialize)
	if r := w.recv(); r["result"] == nil {
		w.t.Fatalf("initialize failed: %v", r)
	}
	w.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
}

// handshake is A1's end-to-end exchange: initialize, then one tool call.
func (w *wrapper) handshake() {
	w.t.Helper()
	w.initialize()
	w.send(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi rover"}}}`)
	if r := w.recv(); !strings.Contains(fmt.Sprint(r["result"]), "hi rover") {
		w.t.Fatalf("echo failed: %v", r)
	}
}

func readEntries(t *testing.T, dir string) []audit.Entry {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "state", "audit.jsonl")) //nolint:gosec // G304: inside the test's ROVER_DIR
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.Entry
	for _, line := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		var e audit.Entry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("bad audit line %q: %v", line, err)
		}
		out = append(out, e)
	}
	return out
}

func checkPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != want {
		t.Errorf("%s: mode %o, want %o", path, got, want)
	}
}

// A1's end-to-end test, now through roverd: no daemon is running, so the
// wrapper must start one, and every message must be in roverd's audit log.
func TestEndToEndThroughAutoStartedDaemon(t *testing.T) {
	dir, env := roverEnv(t, "ROVER_LOG_BODIES=1")
	w := startWrap(t, env, "--", echoBin)
	w.handshake()
	if code := w.finish(); code != 0 {
		t.Fatalf("wrapper exit %d; stderr:\n%s", code, w.stderr.String())
	}

	if running, pid := daemonRunning(t, dir); !running || pid <= 0 {
		t.Fatalf("expected an auto-started roverd (running=%v pid=%d)", running, pid)
	}
	var kinds []string
	for _, e := range readEntries(t, dir) {
		kinds = append(kinds, e.Dir+":"+e.Kind+":"+e.Method+e.ReplyTo)
		if e.Server != "echo-server" || e.Session == "" || e.Hash == "" || len(e.Body) == 0 {
			t.Errorf("entry missing server/session/hash/body: %+v", e)
		}
	}
	want := []string{
		"c2s:request:initialize", "s2c:result:initialize",
		"c2s:notification:notifications/initialized",
		"c2s:request:tools/call", "s2c:result:tools/call",
	}
	if strings.Join(kinds, ",") != strings.Join(want, ",") {
		t.Fatalf("log =\n%v\nwant\n%v", kinds, want)
	}

	checkPerm(t, filepath.Join(dir, "state", "audit.jsonl"), 0o600)
	checkPerm(t, filepath.Join(dir, "state", "roverd.log"), 0o600)
	checkPerm(t, filepath.Join(dir, "state", "rover.db"), 0o600)
	checkPerm(t, filepath.Join(dir, "run", "roverd.sock"), 0o600)
	for _, d := range []string{dir, filepath.Join(dir, "state"), filepath.Join(dir, "run")} {
		checkPerm(t, d, 0o700)
	}
}

// Without roverd, and with auto-start disabled, the wrapper must refuse:
// exit 3, a clear message, and the server command never runs.
func TestFailClosedWithoutDaemon(t *testing.T) {
	dir, env := roverEnv(t, "ROVER_TEST_NO_AUTOSTART=1")
	marker := filepath.Join(dir, "marker")
	stdout, stderr, code := rover(t, env, "wrap", "--", "sh", "-c", "touch "+marker)
	if code != 3 {
		t.Fatalf("exit %d, want 3; stderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "fail closed") || !strings.Contains(stderr, "roverd is not reachable") {
		t.Fatalf("stderr does not explain the refusal:\n%s", stderr)
	}
	if stdout != "" {
		t.Fatalf("wrote to stdout (the MCP channel): %q", stdout)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the server command ran (marker: %v)", err)
	}
	if running, _ := daemonRunning(t, dir); running {
		t.Fatal("a roverd was started although auto-start is disabled")
	}
}

// Two wrappers started by the same parent (this test process, so the same
// os.Getppid()) share one roverd session. They start at the same moment, so
// both may find roverd missing: the auto-start lock must leave exactly one.
func TestTwoWrappersShareSession(t *testing.T) {
	dir, env := roverEnv(t)
	a := startWrap(t, env, "--name", "alpha", "--", echoBin)
	b := startWrap(t, env, "--name", "beta", "--", echoBin)
	a.initialize()
	b.initialize() // both connected at once: the session lives while either is
	if code := a.finish(); code != 0 {
		t.Fatalf("alpha exit %d:\n%s", code, a.stderr.String())
	}
	if code := b.finish(); code != 0 {
		t.Fatalf("beta exit %d:\n%s", code, b.stderr.String())
	}

	sessions := map[string]map[string]bool{} // server -> session ids
	for _, e := range readEntries(t, dir) {
		if sessions[e.Server] == nil {
			sessions[e.Server] = map[string]bool{}
		}
		sessions[e.Server][e.Session] = true
		if len(e.Body) != 0 {
			t.Errorf("body logged although --log-bodies is off: %+v", e)
		}
	}
	if len(sessions["alpha"]) != 1 || len(sessions["beta"]) != 1 {
		t.Fatalf("want one session per server, got %v", sessions)
	}
	for id := range sessions["alpha"] {
		if !sessions["beta"][id] {
			t.Fatalf("alpha and beta are in different sessions: %v", sessions)
		}
	}
	if running, _ := daemonRunning(t, dir); !running {
		t.Fatal("no roverd running")
	}
}

// `rover log` shows the timeline; `rover log --verify` accepts the chain and
// then pinpoints a one-byte edit.
func TestLogAndVerify(t *testing.T) {
	dir, env := roverEnv(t)
	w := startWrap(t, env, "--", echoBin)
	w.handshake()
	if code := w.finish(); code != 0 {
		t.Fatalf("wrapper exit %d:\n%s", code, w.stderr.String())
	}
	stopDaemon(t, dir) // nothing writes to the log from here on

	out, stderr, code := rover(t, env, "log")
	if code != 0 {
		t.Fatalf("rover log: exit %d\n%s", code, stderr)
	}
	for _, want := range []string{"agent -> echo-server", "echo-server -> agent", "initialize", "reply to tools/call [echo]"} {
		if !strings.Contains(out, want) {
			t.Errorf("timeline lacks %q:\n%s", want, out)
		}
	}

	out, stderr, code = rover(t, env, "log", "--verify")
	if code != 0 || !strings.HasPrefix(out, "ok: 5 entries") {
		t.Fatalf("verify: exit %d, out %q, stderr %q", code, out, stderr)
	}

	// Change one byte in the middle of line 2.
	logPath := filepath.Join(dir, "state", "audit.jsonl")
	b, err := os.ReadFile(logPath) //nolint:gosec // G304: inside the test's ROVER_DIR
	if err != nil {
		t.Fatal(err)
	}
	start := bytes.IndexByte(b, '\n') + 1
	end := start + bytes.IndexByte(b[start:], '\n')
	mid := (start + end) / 2
	if b[mid] == '0' {
		b[mid] = '1'
	} else {
		b[mid] = '0'
	}
	if err := os.WriteFile(logPath, b, 0o600); err != nil {
		t.Fatal(err)
	}

	out, _, code = rover(t, env, "log", "--verify")
	if code != 1 || !strings.HasPrefix(out, "BROKEN at "+logPath+":2:") {
		t.Fatalf("verify after tampering: exit %d, out %q", code, out)
	}
}

// A server that prints something other than JSON on stdout stops the
// session: nothing reaches the agent, and the wrapper says why.
func TestNonJSONFromServerStopsSession(t *testing.T) {
	_, env := roverEnv(t)
	w := startWrap(t, env, "--", "sh", "-c", "echo not-json; exec cat >/dev/null")
	if line, err := w.out.ReadBytes('\n'); err != io.EOF || len(line) != 0 {
		t.Fatalf("agent received %q (err %v)", line, err)
	}
	if code := w.finish(); code == 0 {
		t.Fatal("wrapper exited 0")
	}
	if !strings.Contains(w.stderr.String(), "the server sent a line that is not JSON") {
		t.Fatalf("stderr does not say why:\n%s", w.stderr.String())
	}
}

// A second roverd for the same directories refuses to start, and SIGTERM
// stops the first one cleanly (socket removed, pid lock released).
func TestDaemonSingleInstanceAndShutdown(t *testing.T) {
	dir, env := roverEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	d := exec.CommandContext(ctx, roverBin, "daemon") //nolint:gosec // G204: test runs the binary it just built
	d.Env = env
	var dErr lockedBuffer
	d.Stderr = &dErr
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "run", "roverd.sock")
	if !waitUntil(10*time.Second, func() bool { _, err := os.Stat(sock); return err == nil }) {
		t.Fatalf("roverd never created its socket; stderr:\n%s", dErr.String())
	}

	_, stderr, code := rover(t, env, "daemon")
	if code != 1 || !strings.Contains(stderr, "roverd already running") {
		t.Fatalf("second daemon: exit %d, stderr %q", code, stderr)
	}

	if err := d.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := d.Wait(); err != nil {
		t.Fatalf("roverd exit: %v\n%s", err, dErr.String())
	}
	if _, err := os.Stat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket left behind: %v", err)
	}
	if running, _ := daemonRunning(t, dir); running {
		t.Fatal("pid lock still held after shutdown")
	}
}

// The A1 flags moved to the daemon; using them is a usage error.
func TestWrapRejectsRemovedFlags(t *testing.T) {
	dir, env := roverEnv(t)
	marker := filepath.Join(dir, "marker")
	for _, args := range [][]string{
		{"wrap", "--log", "x.jsonl", "--", "sh", "-c", "touch " + marker},
		{"wrap", "--no-bodies", "--", "sh", "-c", "touch " + marker},
	} {
		_, stderr, code := rover(t, env, args...)
		if code != 2 || !strings.Contains(stderr, "the daemon owns the audit log now; see `rover daemon --log-bodies`") {
			t.Errorf("%v: exit %d, stderr %q", args, code, stderr)
		}
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the server command ran")
	}
}
