package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/DreadpiratePickles/rover/internal/audit"
)

// bins builds rover and echo-server once per test binary.
var bins struct{ rover, echo string }

func TestMain(m *testing.M) {
	if os.Getenv("ROVER_TEST_DRIVER") == "1" { // trifecta_test.go: this process is an agent
		os.Exit(runTrifectaDriver())
	}
	dir, err := os.MkdirTemp("", "rover-bins-")
	if err != nil {
		panic(err)
	}
	bins.rover = filepath.Join(dir, "rover")
	bins.echo = filepath.Join(dir, "echo-server")
	for bin, pkg := range map[string]string{bins.rover: ".", bins.echo: "../../examples/echo-server"} {
		if out, err := exec.Command("go", "build", "-o", bin, pkg).CombinedOutput(); err != nil { //nolint:gosec // G204: test builds fixed packages into a temp dir
			panic(fmt.Sprintf("build %s: %v\n%s", pkg, err, out))
		}
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// roverDir gives each test its own ROVER_DIR under /tmp (short enough for a
// Unix socket on macOS) and returns it.
func roverDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "rover-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// env runs a test binary with its own ROVER_DIR and its own HOME (M7: the
// client adapters and roverd's tamper watch read configs under HOME; a test
// must never see, let alone edit, the developer's real ones).
func env(dir string, extra ...string) []string {
	return append(append(os.Environ(), "ROVER_DIR="+dir, "HOME="+filepath.Join(dir, "home")), extra...)
}

// lockedBuf collects a subprocess's stderr; tests read it while it runs.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// startDaemon runs `rover daemon` as a subprocess, waits for its socket and
// returns its stderr.
func startDaemon(t *testing.T, dir string, args ...string) *lockedBuf {
	t.Helper()
	cmd := exec.Command(bins.rover, append([]string{"daemon"}, args...)...) //nolint:gosec // G204: test runs the binary it just built
	cmd.Env = env(dir)
	stderr := &lockedBuf{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("daemon stderr:\n%s", stderr.String())
		}
	})
	sock := filepath.Join(dir, "run", "roverd.sock")
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(sock); err == nil {
			return stderr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("daemon did not create %s:\n%s", sock, stderr.String())
	return nil
}

// Acceptance (M1): the A1 end-to-end test passes through roverd.
func TestEndToEndThroughDaemon(t *testing.T) {
	dir := roverDir(t)
	// From M2 an unpoliced tools/call is blocked (no_policy); permit echo.
	usePolicy(t, dir, `@id("echo") permit (principal, action == Action::"call_tool", resource == Tool::"echo/echo");`, "enforce")
	startDaemon(t, dir)

	cmd := exec.Command(bins.rover, "wrap", "--name", "echo", "--", bins.echo) //nolint:gosec // G204: test runs the binaries it just built
	cmd.Env = env(dir, "ROVER_TEST_NO_AUTOSTART=1")
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	out := bufio.NewReader(stdout)
	send := func(s string) {
		if _, err := fmt.Fprintln(stdin, s); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	recv := func() map[string]any {
		line, err := out.ReadBytes('\n')
		if err != nil {
			t.Fatalf("read: %v (stderr: %s)", err, stderr.String())
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("bad json %q: %v", line, err)
		}
		return m
	}

	send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}`)
	if r := recv(); r["id"] != float64(1) || r["result"] == nil {
		t.Fatalf("initialize failed: %v", r)
	}
	send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	send(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi rover"}}}`)
	r := recv()
	if !strings.Contains(fmt.Sprint(r["result"]), "hi rover") {
		t.Fatalf("echo failed: %v", r)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("gateway exit: %v\n%s", err, stderr.String())
	}
	if !strings.Contains(stderr.String(), "session ") {
		t.Fatalf("wrapper should report its session on stderr: %q", stderr.String())
	}

	logPath := filepath.Join(dir, "state", "audit.jsonl")
	if perm := mode(t, logPath); perm != 0o600 {
		t.Fatalf("audit log perms = %o, want 600", perm)
	}
	f, err := os.Open(logPath) //nolint:gosec // G304: path is inside the test's ROVER_DIR
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var kinds []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e audit.Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		if e.Kind == "session" { // M8: the last wrapper left, the session lingers
			if e.Action != "session_lingering" {
				t.Fatalf("session entry: %+v", e)
			}
			continue
		}
		if e.Server != "echo" || e.Action != "forward" {
			t.Fatalf("entry missing server/action: %+v", e)
		}
		if e.Body != nil {
			t.Fatalf("bodies must be off by default (M1), got %s", e.Body)
		}
		kinds = append(kinds, e.Dir+":"+e.Kind)
	}
	want := []string{"c2s:request", "s2c:result", "c2s:notification", "c2s:request", "s2c:result"}
	if strings.Join(kinds, ",") != strings.Join(want, ",") {
		t.Fatalf("audit kinds = %v, want %v", kinds, want)
	}

	// --verify passes on the real file and fails after a one-byte edit.
	if out, err := run(dir, "log", "--verify"); err != nil || !strings.Contains(out, "chain intact") {
		t.Fatalf("verify: %v\n%s", err, out)
	}
	data, _ := os.ReadFile(logPath) //nolint:gosec // G304: test's own file
	data = bytes.Replace(data, []byte(`"method":"tools/call"`), []byte(`"method":"tools/cull"`), 1)
	if err := os.WriteFile(logPath, data, 0o600); err != nil { //nolint:gosec // G703: a path the test built under its own temp directory
		t.Fatal(err)
	}
	vout, verr := run(dir, "log", "--verify")
	if verr == nil || !strings.Contains(vout, "line 4") {
		t.Fatalf("tampered log must fail --verify at line 4: err=%v\n%s", verr, vout)
	}
}

// Acceptance (M1): with no daemon and auto-start disabled, the wrapper exits
// non-zero and the child server is never started.
func TestWrapperRefusesToStartServerWithoutDaemon(t *testing.T) {
	dir := roverDir(t)
	marker := filepath.Join(dir, "server-ran")
	script := filepath.Join(dir, "server.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ntouch \""+marker+"\"\ncat\n"), 0o700); err != nil { //nolint:gosec // G306: test script must be executable
		t.Fatal(err)
	}
	cmd := exec.Command(bins.rover, "wrap", "--", script) //nolint:gosec // G204: test runs its own script
	cmd.Env = env(dir, "ROVER_TEST_NO_AUTOSTART=1")
	cmd.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("wrapper must exit non-zero without roverd; output:\n%s", out)
	}
	if !strings.Contains(string(out), "refusing to start") {
		t.Fatalf("expected a clear refusal, got:\n%s", out)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the MCP server was started even though roverd was unreachable")
	}
}

// Auto-start (plan §4.4): the first wrapper launches roverd and talks to it.
func TestWrapperAutoStartsDaemon(t *testing.T) {
	dir := roverDir(t)
	cmd := exec.Command(bins.rover, "wrap", "--", bins.echo) //nolint:gosec // G204: test runs the binaries it just built
	cmd.Env = env(dir)
	cmd.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("wrap: %v\n%s", err, stderr.String())
	}
	if !strings.Contains(string(out), `"id":1`) {
		t.Fatalf("no reply through auto-started daemon: %q\n%s", out, stderr.String())
	}
	pidBytes, err := os.ReadFile(filepath.Join(dir, "run", "roverd.pid")) //nolint:gosec // G304: test's ROVER_DIR
	if err != nil {
		t.Fatalf("pid file: %v", err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	if pid <= 0 {
		t.Fatalf("bad pid %q", pidBytes)
	}
	proc, _ := os.FindProcess(pid)
	t.Cleanup(func() { _ = proc.Signal(syscall.SIGTERM) })
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("auto-started daemon (pid %d) is not running: %v", pid, err)
	}
	logData, _ := os.ReadFile(filepath.Join(dir, "state", "roverd.log")) //nolint:gosec // G304: test's ROVER_DIR
	if !strings.Contains(string(logData), "listening on") {
		t.Fatalf("daemon log missing: %q", logData)
	}
	if perm := mode(t, filepath.Join(dir, "run", "roverd.sock")); perm != 0o600 {
		t.Fatalf("socket perms = %o, want 600", perm)
	}
}

func run(dir string, args ...string) (string, error) {
	cmd := exec.Command(bins.rover, args...) //nolint:gosec // G204: test runs the binary it just built
	cmd.Env = env(dir)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// Review L4: a server name with "/" would make "<server>/<tool>" ambiguous,
// so `rover wrap --name` refuses it before contacting roverd or starting
// the server.
func TestWrapRejectsBadServerName(t *testing.T) {
	dir := roverDir(t)
	marker := filepath.Join(dir, "server-ran")
	script := filepath.Join(dir, "server.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ntouch \""+marker+"\"\ncat\n"), 0o700); err != nil { //nolint:gosec // G306: test script must be executable
		t.Fatal(err)
	}
	for _, name := range []string{"evil/echo", "has space"} {
		cmd := exec.Command(bins.rover, "wrap", "--name", name, "--", script) //nolint:gosec // G204: test runs its own script
		cmd.Env = env(dir)
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "invalid --name") || !strings.Contains(string(out), "A-Za-z0-9_.-") {
			t.Fatalf("--name %q: want an early error, got %v:\n%s", name, err, out)
		}
		if _, err := os.Stat(marker); err == nil {
			t.Fatal("the MCP server was started despite a bad --name")
		}
		if _, err := os.Stat(filepath.Join(dir, "run", "roverd.pid")); err == nil {
			t.Fatal("roverd was auto-started despite a bad --name")
		}
	}
}
