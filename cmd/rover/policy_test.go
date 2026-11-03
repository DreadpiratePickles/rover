package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// e2ePolicy permits echo and listing for the echo server and hides read_file.
const e2ePolicy = `
@id("echo-list") permit (principal, action == Action::"list_tools", resource == Server::"echo");
@id("echo-call") permit (principal, action == Action::"call_tool", resource == Tool::"echo/echo");
@id("hide-read-file") @rover_hide("true")
forbid (principal, action == Action::"call_tool", resource == Tool::"echo/read_file");
`

// usePolicy runs `rover policy init` in dir, then replaces the starter
// policy with src and sets the mode.
func usePolicy(t *testing.T, dir, src, mode string) {
	t.Helper()
	if out, err := run(dir, "policy", "init"); err != nil {
		t.Fatalf("policy init: %v\n%s", err, out)
	}
	cfgDir := filepath.Join(dir, "config")
	if err := os.WriteFile(filepath.Join(cfgDir, "policy.cedar"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(cfgDir, "config.yaml")
	cfg, err := os.ReadFile(cfgPath) //nolint:gosec // G304: test's ROVER_DIR
	if err != nil {
		t.Fatal(err)
	}
	cfg = bytes.Replace(cfg, []byte("\nmode: observe\n"), []byte("\nmode: "+mode+"\n"), 1)
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil { //nolint:gosec // G703: a path the test built under its own temp directory
		t.Fatal(err)
	}
}

// mcp drives one `rover wrap` process like an agent would.
type mcp struct {
	t      *testing.T
	cmd    *exec.Cmd
	in     io.WriteCloser
	out    *bufio.Reader
	stderr bytes.Buffer
}

func wrapEcho(t *testing.T, dir string) *mcp {
	t.Helper()
	m := &mcp{t: t, cmd: exec.Command(bins.rover, "wrap", "--name", "echo", "--", bins.echo)} //nolint:gosec // G204: test runs the binaries it just built
	m.cmd.Env = env(dir, "ROVER_TEST_NO_AUTOSTART=1")
	m.in, _ = m.cmd.StdinPipe()
	stdout, _ := m.cmd.StdoutPipe()
	m.out = bufio.NewReader(stdout)
	m.cmd.Stderr = &m.stderr
	if err := m.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return m
}

func (m *mcp) call(line string) map[string]any {
	m.t.Helper()
	if _, err := fmt.Fprintln(m.in, line); err != nil {
		m.t.Fatalf("write: %v", err)
	}
	resp, err := m.out.ReadBytes('\n')
	if err != nil {
		m.t.Fatalf("read: %v (stderr: %s)", err, m.stderr.String())
	}
	var r map[string]any
	if err := json.Unmarshal(resp, &r); err != nil {
		m.t.Fatalf("bad json %q: %v", resp, err)
	}
	return r
}

func (m *mcp) close() {
	m.t.Helper()
	_ = m.in.Close()
	if err := m.cmd.Wait(); err != nil {
		m.t.Fatalf("wrap exit: %v\n%s", err, m.stderr.String())
	}
}

// Acceptance (M2): policy init/validate/test and a hidden, blocked tool
// through the real daemon and wrapper.
func TestPolicyEndToEnd(t *testing.T) {
	// Arrange
	dir := roverDir(t)
	usePolicy(t, dir, e2ePolicy, "enforce")
	if out, err := run(dir, "policy", "init"); err == nil || !strings.Contains(out, "refusing to overwrite") || !strings.Contains(out, "policy.cedar") {
		t.Fatalf("second init must refuse and list files: %v\n%s", err, out)
	}
	if out, err := run(dir, "policy", "validate"); err != nil || !strings.Contains(out, "hide-read-file  forbid") || !strings.Contains(out, "ok: 3 policies") {
		t.Fatalf("validate: %v\n%s", err, out)
	}
	startDaemon(t, dir, "--log-bodies")
	m := wrapEcho(t, dir)

	// Act
	m.call(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}`)
	list := m.call(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	read := m.call(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/passwd"}}}`)
	echo := m.call(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi rover"}}}`)
	m.close()

	// Assert
	listed := fmt.Sprint(list["result"])
	if !strings.Contains(listed, "echo") || strings.Contains(listed, "read_file") {
		t.Fatalf("tools/list must show echo and hide read_file: %v", list)
	}
	res, _ := read["result"].(map[string]any)
	if res == nil || res["isError"] != true || !strings.Contains(fmt.Sprint(res["content"]), "hide-read-file") {
		t.Fatalf("read_file must get an isError result naming the rule: %v", read)
	}
	if !strings.Contains(fmt.Sprint(echo["result"]), "hi rover") {
		t.Fatalf("echo failed: %v", echo)
	}
	logPath := filepath.Join(dir, "state", "audit.jsonl")
	if out, err := run(dir, "log", "--verify"); err != nil || !strings.Contains(out, "chain intact") {
		t.Fatalf("verify: %v\n%s", err, out)
	}
	if out, err := run(dir, "log"); err != nil || !strings.Contains(out, "block") || !strings.Contains(out, "replace") {
		t.Fatalf("log must show the block and the replaced list: %v\n%s", err, out)
	}
	out, err := run(dir, "policy", "test", logPath)
	if err != nil || !strings.Contains(out, "enforce mode") || !strings.Contains(out, "tools/call read_file") ||
		!strings.Contains(out, "rules=hide-read-file") || !strings.Contains(out, "3 replayed: 2 forward, 1 block") {
		t.Fatalf("policy test: %v\n%s", err, out)
	}
	if out, err := run(dir, "policy", "apply"); err != nil || !strings.Contains(out, "TODO(M9)") {
		t.Fatalf("policy apply: %v\n%s", err, out)
	}
}

// Fail closed (M2): with no policy file, roverd blocks tools/call.
func TestNoPolicyBlocksToolCalls(t *testing.T) {
	// Arrange
	dir := roverDir(t)
	startDaemon(t, dir)
	m := wrapEcho(t, dir)

	// Act
	m.call(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}`)
	r := m.call(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"x"}}}`)
	m.close()

	// Assert
	if !strings.Contains(fmt.Sprint(r["result"]), "no_policy") {
		t.Fatalf("want a no_policy block, got %v", r)
	}
}

func TestPolicyValidateRejectsBadPolicy(t *testing.T) {
	// Arrange
	dir := roverDir(t)
	bad := filepath.Join(dir, "bad.cedar")
	if err := os.WriteFile(bad, []byte(`permit (principal, action == Action::"call_tool", resource) when { context.nope };`), 0o600); err != nil {
		t.Fatal(err)
	}

	// Act
	out, err := run(dir, "policy", "validate", "--policy", bad)

	// Assert
	if err == nil || !strings.Contains(out, "error:") {
		t.Fatalf("a policy that does not match the schema must fail: %v\n%s", err, out)
	}
}

func TestPolicyApplyWithoutDaemonFails(t *testing.T) {
	out, err := run(roverDir(t), "policy", "apply")
	if err == nil || !strings.Contains(out, "not running") {
		t.Fatalf("apply without roverd must exit 1: %v\n%s", err, out)
	}
}

func TestPolicyTestCountsBodylessEntriesAsSkipped(t *testing.T) {
	// Arrange
	dir := roverDir(t)
	usePolicy(t, dir, e2ePolicy, "observe")
	logPath := filepath.Join(dir, "log.jsonl")
	if err := os.WriteFile(logPath, []byte(`{"ts":"2026-10-07T14:30:00Z","session":"s","dir":"c2s","kind":"request","method":"tools/call","bytes":10,"prev":""}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Act
	out, err := run(dir, "policy", "test", logPath)

	// Assert
	if err != nil || !strings.Contains(out, "1 skipped (no body)") || !strings.Contains(out, "--log-bodies") || !strings.Contains(out, "config.yaml says observe") {
		t.Fatalf("policy test: %v\n%s", err, out)
	}
}

// waitFor polls the daemon's stderr for want (the reload is asynchronous).
func waitFor(t *testing.T, logs *lockedBuf, want string) {
	t.Helper()
	for i := 0; i < 150; i++ {
		if strings.Contains(logs.String(), want) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("daemon never logged %q:\n%s", want, logs.String())
}

// SIGHUP (M2): apply loads a new policy; a broken one keeps the old.
func TestApplyReloadsAndKeepsPreviousOnError(t *testing.T) {
	// Arrange: start with no policy file at all.
	dir := roverDir(t)
	logs := startDaemon(t, dir)
	usePolicy(t, dir, e2ePolicy, "enforce")
	echoCall := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"reloaded"}}}`

	// Act: a good policy, then a broken one.
	if out, err := run(dir, "policy", "apply"); err != nil {
		t.Fatalf("apply: %v\n%s", err, out)
	}
	waitFor(t, logs, "policy reloaded (mode enforce)")
	if err := os.WriteFile(filepath.Join(dir, "config", "policy.cedar"), []byte("permit (oops"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := run(dir, "policy", "apply"); err != nil {
		t.Fatalf("apply: %v\n%s", err, out)
	}
	waitFor(t, logs, "policy reload FAILED")
	m := wrapEcho(t, dir)
	r := m.call(echoCall)
	m.close()

	// Assert: the good policy is still in force.
	if !strings.Contains(fmt.Sprint(r["result"]), "reloaded") || strings.Contains(fmt.Sprint(r["result"]), "isError:true") {
		t.Fatalf("echo must still be permitted by the previous policy: %v", r)
	}
}
