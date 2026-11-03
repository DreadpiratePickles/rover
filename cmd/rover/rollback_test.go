package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src) //nolint:gosec // G304: the test's ROVER_DIR
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil { //nolint:gosec // G703: the test's ROVER_DIR
		t.Fatal(err)
	}
}

// Review M9 NEW-1: the agent saves state.db + policy files while policy A
// is approved; the human later approves a stricter B; the agent restores
// the old files. The approved hash in state.db no longer matches the
// latest `policy approved` audit entry, so roverd loads nothing.
func TestRollbackToAnOlderApprovalIsRefused(t *testing.T) {
	// Arrange: A approved, roverd ran, the agent saves the files.
	dir := roverDir(t)
	usePolicy(t, dir, `permit (principal, action, resource);`, "enforce")
	stop, _ := daemonProc(t, dir, "allow")
	stop()
	save := filepath.Join(dir, "saved")
	_ = os.MkdirAll(save, 0o700)
	for _, f := range []string{"state/state.db", "config/policy.cedar", "config/config.yaml"} {
		copyFile(t, filepath.Join(dir, f), filepath.Join(save, filepath.Base(f)))
	}
	// The human approves the stricter B.
	if err := os.WriteFile(filepath.Join(dir, "config", "policy.cedar"), []byte(e2ePolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	applyPolicy(t, dir)

	// Act: the agent puts A back and roverd restarts.
	for _, f := range []string{"state/state.db", "config/policy.cedar", "config/config.yaml"} {
		copyFile(t, filepath.Join(save, filepath.Base(f)), filepath.Join(dir, f))
	}
	logs := startDaemon(t, dir)
	m := wrapEcho(t, dir)
	r := m.call(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/hosts"}}}`)
	m.close()
	doctor, derr := run(dir, "doctor")

	// Assert
	waitFor(t, logs, "STATE LOST")
	if !strings.Contains(logs.String(), "latest `policy approved` audit entry") || strings.Contains(logs.String(), "policy loaded (") {
		t.Fatalf("daemon log:\n%s", logs.String())
	}
	if !strings.Contains(fmt.Sprint(r["result"]), "no_policy") {
		t.Fatalf("the rolled-back policy must not load: %v", r)
	}
	if derr == nil || !strings.Contains(doctor, "FAIL  policy-approval") || !strings.Contains(doctor, "latest `policy approved` audit entry") {
		t.Fatalf("doctor (NEW-4) must say what roverd says:\n%s", doctor)
	}
}

// Review M9 NEW-2: a fresh install whose init dialog was declined has only
// a `policy refused` audit entry: that is not history, so roverd starts
// with no policy and no false STATE LOST.
func TestDeclinedInitIsNotHistory(t *testing.T) {
	dir := roverDir(t)
	if out, err := run(dir, "--test-auth=deny", "policy", "init"); err != nil || !strings.Contains(out, "nothing was recorded") {
		t.Fatalf("%v\n%s", err, out)
	}
	logs := startDaemon(t, dir)
	waitFor(t, logs, "listening on")
	time.Sleep(200 * time.Millisecond)
	if strings.Contains(logs.String(), "STATE LOST") || strings.Contains(logs.String(), "[test-notify]") || hasStateReset(t, dir) {
		t.Fatalf("a declined init is not lost state:\n%s", logs.String())
	}
	doctor, _ := run(dir, "doctor")
	if !strings.Contains(doctor, "no policy (enforce)") {
		t.Fatalf("doctor:\n%s", doctor)
	}
}

// Review M9 NEW-3: the CLI waits for roverd's tamper dialog instead of
// giving up after 10 s while roverd later applies the change.
func TestInstallWaitsForASlowTamperDialog(t *testing.T) {
	if testing.Short() {
		t.Skip("waits 12 s for the fake dialog")
	}
	dir := roverDir(t)
	writeFile(t, filepath.Join(dir, "home", ".cursor", "mcp.json"), `{"mcpServers":{"fs":{"command":"npx","args":["fs"]}}}`)
	startDaemonFlags(t, dir, "--test-auth=allow", "--test-auth-delay=12s")
	out, err := run(dir, "install", "--client", "cursor", "--yes")
	if err != nil || !strings.Contains(out, "ok    roverd is watching this file") {
		t.Fatalf("install (err %v):\n%s", err, out)
	}
}
