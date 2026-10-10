package main

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// approvalPolicy permits echo only with a human's approval.
const approvalPolicy = `
@id("echo-list") permit (principal, action == Action::"list_tools", resource == Server::"echo");
@id("ask-echo") @rover_require("approval")
permit (principal, action == Action::"call_tool", resource == Tool::"echo/echo");
`

const echoText = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"approved"}}}`

// startDaemonAuth is startDaemon with the fake dialog answering answer.
func startDaemonAuth(t *testing.T, dir, answer string) *lockedBuf {
	t.Helper()
	return startDaemonFlags(t, dir, "--test-auth="+answer)
}

// Acceptance (M9 manual demo, scripted): the dialog's yes forwards the
// held call; its no returns the §5.1 isError body "approval denied". The
// notification carries a details page link that GET can read and POST
// cannot touch.
func TestApprovalEndToEnd(t *testing.T) {
	for _, answer := range []string{"allow", "deny"} {
		t.Run(answer, func(t *testing.T) {
			// Arrange
			dir := roverDir(t)
			usePolicy(t, dir, approvalPolicy, "enforce")
			logs := startDaemonAuth(t, dir, answer)
			m := wrapEcho(t, dir)
			defer m.close()
			m.call(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)

			// Act
			r := m.call(echoText)

			// Assert
			got := fmt.Sprint(r["result"])
			if answer == "allow" && (!strings.Contains(got, "approved") || strings.Contains(got, "isError:true")) {
				t.Fatalf("allow must forward: %v", r)
			}
			if answer == "deny" && (!strings.Contains(got, "isError:true") || !strings.Contains(got, "approval denied") || !strings.Contains(got, "ask-echo")) {
				t.Fatalf("deny must block with approval denied: %v", r)
			}
			waitFor(t, logs, "[test-auth] dialog: Rover: allow an unknown client to run echo.echo (args: text)?")
			link := regexp.MustCompile(`\[test-notify\] rover: approval needed: (http://127\.0\.0\.1:\d+/approval/[0-9a-f-]+\?t=[0-9a-f]{32}) `).FindStringSubmatch(logs.String())
			if link == nil {
				t.Fatalf("no notification with a details link:\n%s", logs.String())
			}
			assertPageReadOnly(t, link[1], map[string]string{"allow": "state allowed", "deny": "state denied"}[answer])
		})
	}
}

func assertPageReadOnly(t *testing.T, link, state string) {
	t.Helper()
	resp, err := http.Get(link) //nolint:gosec,noctx // G107: the test's own loopback link
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	_, _ = body.ReadFrom(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(body.String(), state) || strings.Contains(body.String(), "<form") {
		t.Fatalf("GET %d:\n%s", resp.StatusCode, body.String())
	}
	post, err := http.Post(link, "application/x-www-form-urlencoded", strings.NewReader("approve=1")) //nolint:gosec,noctx // G107: as above
	if err != nil {
		t.Fatal(err)
	}
	_ = post.Body.Close()
	if post.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d, want 405", post.StatusCode)
	}
}

// Acceptance (M9): a tampered policy file is not loaded, and doctor
// reports it. The agent edits policy.cedar to permit everything and sends
// SIGHUP without `rover policy apply`; then roverd restarts on it.
func TestTamperedPolicyIsNotLoadedAndDoctorReportsIt(t *testing.T) {
	// Arrange
	dir := roverDir(t)
	usePolicy(t, dir, e2ePolicy, "enforce")
	stop := startDaemonStoppable(t, dir)
	readFile := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/hosts"}}}`

	// Act
	if err := os.WriteFile(filepath.Join(dir, "config", "policy.cedar"), []byte(`permit (principal, action, resource);`), 0o600); err != nil {
		t.Fatal(err)
	}
	hup(t, dir)
	m := wrapEcho(t, dir)
	afterHUP := m.call(readFile)
	m.close()
	doctor, derr := run(dir, "doctor")
	stop()
	logs := startDaemon(t, dir)
	m2 := wrapEcho(t, dir)
	afterRestart := m2.call(readFile)
	m2.close()

	// Assert
	if !strings.Contains(fmt.Sprint(afterHUP["result"]), "isError:true") {
		t.Fatalf("after a bare SIGHUP the approved policy must still apply: %v", afterHUP)
	}
	if derr == nil || !strings.Contains(doctor, "FAIL  policy-approval") || !strings.Contains(doctor, "TAMPERED") {
		t.Fatalf("doctor must report the tampered policy (err %v):\n%s", derr, doctor)
	}
	waitFor(t, logs, "POLICY NOT LOADED: the policy files changed")
	if !strings.Contains(fmt.Sprint(afterRestart["result"]), "no_policy") {
		t.Fatalf("after a restart the tampered policy must not load: %v", afterRestart)
	}
}

// Review M2 / M9: enforce -> observe needs an authenticated apply.
func TestModeDowngradeNeedsAuthenticatedApply(t *testing.T) {
	// Arrange
	dir := roverDir(t)
	usePolicy(t, dir, e2ePolicy, "enforce")
	logs := startDaemon(t, dir)
	cfgPath := filepath.Join(dir, "config", "config.yaml")
	cfg, err := os.ReadFile(cfgPath) //nolint:gosec // G304: the test's ROVER_DIR
	if err != nil {
		t.Fatal(err)
	}

	// Act
	if err := os.WriteFile(cfgPath, bytes.Replace(cfg, []byte("\nmode: enforce\n"), []byte("\nmode: observe\n"), 1), 0o600); err != nil { //nolint:gosec // G703: a path the test built under its own temp directory
		t.Fatal(err)
	}
	hup(t, dir)
	waitFor(t, logs, "policy reload REFUSED")
	denied, derr := run(dir, "--test-auth=deny", "policy", "apply")
	applied, aerr := run(dir, "--test-auth=allow", "policy", "apply")

	// Assert
	if derr == nil || !strings.Contains(denied, "OS authentication did not succeed") {
		t.Fatalf("apply without the dialog's yes: %v\n%s", derr, denied)
	}
	if aerr != nil || !strings.Contains(applied, "mode observe") {
		t.Fatalf("apply: %v\n%s", aerr, applied)
	}
	waitFor(t, logs, "policy reloaded (mode observe)")
}

// Acceptance (M9): concurrent calls flow while one is held, end to end
// through a real wrapper. The dialog takes a second to answer; pings sent
// after the held call come back first, then the held call's result.
func TestPingsFlowWhileACallIsHeld(t *testing.T) {
	// Arrange
	dir := roverDir(t)
	usePolicy(t, dir, approvalPolicy, "enforce")
	startDaemonFlags(t, dir, "--test-auth=allow", "--test-auth-delay=1s")
	m := wrapEcho(t, dir)
	defer m.close()
	m.call(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)

	// Act
	for _, line := range []string{echoText, `{"jsonrpc":"2.0","id":"p1","method":"ping"}`, `{"jsonrpc":"2.0","id":"p2","method":"ping"}`} {
		if _, err := fmt.Fprintln(m.in, line); err != nil {
			t.Fatal(err)
		}
	}
	var order []string
	for i := 0; i < 3; i++ {
		line, err := m.out.ReadBytes('\n')
		if err != nil {
			t.Fatalf("read: %v (stderr %s)", err, m.stderr.String())
		}
		order = append(order, regexp.MustCompile(`"id":("?[^,}"]+"?)`).FindStringSubmatch(string(line))[1])
	}

	// Assert
	if strings.Join(order, " ") != `"p1" "p2" 2` {
		t.Fatalf("replies came back in order %v; the pings must not wait for the held call", order)
	}
}
