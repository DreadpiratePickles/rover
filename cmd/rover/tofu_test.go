package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/rover/internal/audit"
)

// Review M9 HIGH: `kill roverd; rm state/state.db; rover policy init
// --force` must not hand the agent a freshly "approved" policy. init now
// needs the OS dialog; without its yes nothing is recorded, and roverd
// starts with no policy in enforce, audits a state reset and doctor fails.
func TestTOFUResetNeedsTheDialog(t *testing.T) {
	for _, answer := range []string{"deny", "allow"} {
		t.Run(answer, func(t *testing.T) {
			// Arrange: an approved enforcing policy and a roverd that ran.
			dir := roverDir(t)
			usePolicy(t, dir, e2ePolicy, "enforce")
			stop, _ := daemonProc(t, dir, "allow")
			stop()

			// Act: the verifier's sequence, the dialog answering answer.
			if err := os.Remove(filepath.Join(dir, "state", "state.db")); err != nil {
				t.Fatal(err)
			}
			out, ierr := run(dir, "--test-auth="+answer, "policy", "init", "--force")
			logs := startDaemon(t, dir)
			m := wrapEcho(t, dir)
			r := m.call(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/hosts"}}}`)
			m.close()
			doctor, derr := run(dir, "doctor")

			// Assert
			if ierr != nil {
				t.Fatalf("init: %v\n%s", ierr, out)
			}
			if answer == "allow" {
				// Even a yes cannot approve over a lost state.db: roverd
				// must see (and report) the loss first; then apply works.
				if !strings.Contains(out, "state.db is missing") {
					t.Fatalf("init must not recreate a lost state.db:\n%s", out)
				}
				waitFor(t, logs, "STATE LOST")
				if applied, aerr := run(dir, "policy", "apply"); aerr != nil || !strings.Contains(applied, "osauth:test") {
					t.Fatalf("apply after the loss was reported: %v\n%s", aerr, applied)
				}
				waitFor(t, logs, "policy reloaded (mode observe)")
				return
			}
			if !strings.Contains(out, "nothing was recorded") || !strings.Contains(out, "enforce with no policy") {
				t.Fatalf("init without the dialog must say nothing was recorded:\n%s", out)
			}
			waitFor(t, logs, "STATE LOST")
			if !strings.Contains(fmt.Sprint(r["result"]), "no_policy") {
				t.Fatalf("roverd must run with no policy: %v", r)
			}
			if !strings.Contains(logs.String(), "POLICY NOT LOADED") || strings.Contains(logs.String(), "policy loaded (mode observe)") {
				t.Fatalf("daemon log:\n%s", logs.String())
			}
			if derr == nil || !strings.Contains(doctor, "FAIL  policy-approval") {
				t.Fatalf("doctor must fail (err %v):\n%s", derr, doctor)
			}
			if !hasStateReset(t, dir) {
				t.Fatal("no state reset audit entry")
			}
		})
	}
}

// A state.db that has no approval while the audit log has history, and
// one whose approval is newer than the log, are both distrusted.
func TestApprovalRecordWithoutAuditIsDistrusted(t *testing.T) {
	dir := roverDir(t)
	usePolicy(t, dir, e2ePolicy, "enforce")
	stop, _ := daemonProc(t, dir, "allow")
	stop()
	// Forge: approve the current files directly in the database (as an
	// attacker with file access could), without any audit entry.
	if err := os.WriteFile(filepath.Join(dir, "config", "policy.cedar"), []byte(`permit (principal, action, resource);`), 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := loadedHash(dirsOf(dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := forgeApproval(dir, h); err != nil {
		t.Fatal(err)
	}
	logs := startDaemon(t, dir)
	waitFor(t, logs, "after the newest audit entry")
	if strings.Contains(logs.String(), "policy loaded (") {
		t.Fatalf("a forged approval must not load:\n%s", logs.String())
	}
	if !hasStateReset(t, dir) {
		t.Fatal("no state reset audit entry")
	}
}

func hasStateReset(t *testing.T, dir string) bool {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "state", "audit.jsonl")) //nolint:gosec // G304: the test's ROVER_DIR
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var e audit.Entry
		if json.Unmarshal([]byte(l), &e) == nil && e.Kind == "state" && e.Action == "reset" {
			return true
		}
	}
	return false
}

func TestDoctorSaysNoPolicyEnforce(t *testing.T) {
	dir := roverDir(t)
	if out, err := run(dir, "policy", "init"); err != nil { // the dialog says no
		t.Fatalf("%v\n%s", err, out)
	}
	startDaemon(t, dir)
	out, _ := run(dir, "doctor")
	if !strings.Contains(out, "FAIL  policy           no policy (enforce)") {
		t.Fatalf("doctor:\n%s", out)
	}
}
