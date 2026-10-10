package main

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/DreadpiratePickles/rover/internal/paths"
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

// Review M2 / M9: enforce -> observe needs an approved apply, and the
// dialog that approves it is roverd's, not the CLI's: a CLI that "says"
// allow changes nothing while roverd's dialog says no.
func TestModeDowngradeNeedsRoverdsDialog(t *testing.T) {
	// Arrange
	dir := roverDir(t)
	usePolicy(t, dir, e2ePolicy, "enforce")
	stop, logs := daemonProc(t, dir, "deny")
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
	denied, derr := run(dir, "--test-auth=allow", "policy", "apply") // the CLI's fake says allow; roverd's says deny
	stop()
	_, logs2 := daemonProc(t, dir, "allow")
	applied, aerr := run(dir, "policy", "apply") // the CLI's (testauth default) says deny; roverd's says allow

	// Assert
	if derr == nil || !strings.Contains(denied, "not applied: deny") || strings.Contains(logs.String(), "policy reloaded (mode observe)") {
		t.Fatalf("roverd's deny must win: %v\n%s\n%s", derr, denied, logs.String())
	}
	if aerr != nil || !strings.Contains(applied, "applied policy") || !strings.Contains(applied, "mode observe") {
		t.Fatalf("apply: %v\n%s", aerr, applied)
	}
	waitFor(t, logs2, "policy reloaded (mode observe)")
}

// daemonProc starts roverd with the fake dialog answering answer and
// returns a stop function and its stderr.
func daemonProc(t *testing.T, dir, answer string) (func(), *lockedBuf) {
	t.Helper()
	cmd := exec.Command(bins.rover, "--test-auth="+answer, "daemon") //nolint:gosec // G204: test runs the binary it just built
	cmd.Env = env(dir)
	logs := &lockedBuf{}
	cmd.Stderr = logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			_ = cmd.Process.Signal(syscall.SIGTERM)
			_ = cmd.Wait()
		}
	}
	t.Cleanup(stop)
	waitFor(t, logs, "listening on")
	return stop, logs
}

// Acceptance (M9 change): no nonce file exists any more, and a forged one
// does nothing. The agent writes run/apply.nonce naming the hash of its own
// policy and sends SIGHUP: refused; the policy is not loaded.
func TestForgedNonceFileDoesNothing(t *testing.T) {
	// Arrange
	dir := roverDir(t)
	usePolicy(t, dir, e2ePolicy, "enforce")
	logs := startDaemon(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "config", "policy.cedar"), []byte(`permit (principal, action, resource);`), 0o600); err != nil {
		t.Fatal(err)
	}
	hash, err := loadedHash(paths.Dirs{Config: filepath.Join(dir, "config"), Run: filepath.Join(dir, "run")})
	if err != nil {
		t.Fatal(err)
	}
	forged := `{"nonce":"` + strings.Repeat("a", 32) + `","hash":"` + hash + `","method":"osauth:macos_local_authentication","created":"` + time.Now().UTC().Format(time.RFC3339) + `"}`
	if err := os.WriteFile(filepath.Join(dir, "run", "apply.nonce"), []byte(forged), 0o600); err != nil {
		t.Fatal(err)
	}

	// Act
	hup(t, dir)
	waitFor(t, logs, "policy reload REFUSED")
	m := wrapEcho(t, dir)
	r := m.call(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/hosts"}}}`)
	m.close()

	// Assert
	if !strings.Contains(fmt.Sprint(r["result"]), "isError:true") {
		t.Fatalf("a forged nonce must not load the agent's policy: %v", r)
	}
	if _, err := os.Stat(filepath.Join(dir, "run", "apply.nonce")); err != nil {
		t.Fatalf("nothing reads the nonce file any more, so it must still be there untouched: %v", err)
	}
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
