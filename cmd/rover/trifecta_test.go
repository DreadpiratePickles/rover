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
	"regexp"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
	policyfiles "github.com/DreadpiratePickles/rover/policy"
)

// trifectaConfig labels three echo-server instances like a real setup:
// files.read_file reads private data, web.echo brings in untrusted text,
// mail.echo sends data out.
const trifectaConfig = `mode: enforce
labels:
  files: { read_file: [reads_private] }
  web:   { echo: [reads_untrusted] }
  mail:  { echo: [egress] }
`

const trifectaPermits = `
@id("permit-files") permit (principal, action == Action::"call_tool", resource in Server::"files");
@id("permit-web")   permit (principal, action == Action::"call_tool", resource in Server::"web");
@id("permit-mail")  permit (principal, action == Action::"call_tool", resource in Server::"mail");
`

func toolCall(id int, tool, args string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, id, tool, args)
}

var sessionRE = regexp.MustCompile(`session ([0-9a-f]+): wrapping`)

// driverResult is what the driver process prints: the last reply and the
// session id of every wrapper it started.
type driverResult struct {
	Last     json.RawMessage `json:"last"`
	Sessions []string        `json:"sessions"`
}

// trifectaSession runs one agent: a separate driver process (this test
// binary, re-executed; see TestMain) that starts files, web and mail as its
// children, so they share one agent pid and one roverd session, and a new
// driver is a new session. order is phases separated by "|": each phase
// starts fresh wrappers under the same driver, runs its calls ("files"
// reads secretPath, the others echo) and closes them.
func trifectaSession(t *testing.T, dir, secretPath, order string) (last map[string]any, sessions []string) {
	t.Helper()
	cmd := exec.Command(os.Args[0]) //nolint:gosec // G204: the test binary itself, as a driver
	cmd.Env = env(dir, "ROVER_TEST_NO_AUTOSTART=1", "ROVER_TEST_DRIVER=1", "DRIVER_ROVER="+bins.rover,
		"DRIVER_ECHO="+bins.echo, "DRIVER_SECRET="+secretPath, "DRIVER_ORDER="+order)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("driver %s: %v\n%s", order, err, stderr.String())
	}
	var r driverResult
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("driver output %q: %v", out, err)
	}
	if err := json.Unmarshal(r.Last, &last); err != nil {
		t.Fatal(err)
	}
	return last, r.Sessions
}

// runTrifectaDriver is the driver process (ROVER_TEST_DRIVER=1).
func runTrifectaDriver() int {
	var r driverResult
	for _, phase := range strings.Split(os.Getenv("DRIVER_ORDER"), "|") {
		last, ids, err := driverPhase(strings.Split(phase, ","))
		if err != nil {
			fmt.Fprintln(os.Stderr, "driver:", err)
			return 1
		}
		r.Last, r.Sessions = last, append(r.Sessions, ids...)
	}
	b, _ := json.Marshal(r)
	fmt.Println(string(b))
	return 0
}

type driverWrap struct {
	cmd    *exec.Cmd
	in     io.WriteCloser
	out    *bufio.Reader
	stderr bytes.Buffer
}

func (w *driverWrap) call(line string) (json.RawMessage, error) {
	if _, err := fmt.Fprintln(w.in, line); err != nil {
		return nil, err
	}
	return w.out.ReadBytes('\n')
}

func driverPhase(order []string) (last json.RawMessage, sessions []string, err error) {
	ws := map[string]*driverWrap{}
	for _, n := range []string{"files", "web", "mail"} {
		w := &driverWrap{cmd: exec.Command(os.Getenv("DRIVER_ROVER"), "wrap", "--name", n, "--", os.Getenv("DRIVER_ECHO"))} //nolint:gosec // G204: binaries the test built
		w.in, _ = w.cmd.StdinPipe()
		stdout, _ := w.cmd.StdoutPipe()
		w.out = bufio.NewReader(stdout)
		w.cmd.Stderr = &w.stderr
		if err = w.cmd.Start(); err != nil {
			return nil, nil, err
		}
		if _, err = w.call(`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}`); err != nil {
			return nil, nil, err
		}
		ws[n] = w
	}
	for i, n := range order {
		line := toolCall(i+1, "echo", `{"text":"hello from `+n+`"}`)
		if n == "files" {
			line = toolCall(i+1, "read_file", fmt.Sprintf(`{"path":%q}`, os.Getenv("DRIVER_SECRET")))
		}
		if last, err = ws[n].call(line); err != nil {
			return nil, nil, err
		}
		if n == "files" && !strings.Contains(string(last), "s3cret") {
			return nil, nil, fmt.Errorf("files.read_file failed: %s", last)
		}
	}
	for _, n := range []string{"files", "web", "mail"} {
		_ = ws[n].in.Close()
		if err = ws[n].cmd.Wait(); err != nil {
			return nil, nil, fmt.Errorf("%s: %w\n%s", n, err, ws[n].stderr.String())
		}
		m := sessionRE.FindStringSubmatch(ws[n].stderr.String())
		if m == nil {
			return nil, nil, fmt.Errorf("%s: no session on stderr: %s", n, ws[n].stderr.String())
		}
		sessions = append(sessions, m[1])
	}
	return last, sessions, nil
}

func oneSession(t *testing.T, ids []string) string {
	t.Helper()
	for _, id := range ids {
		if id != ids[0] {
			t.Fatalf("the wrappers of one driver must share one session: %v", ids)
		}
	}
	return ids[0]
}

// Acceptance (M8): a private read on one server, an untrusted read on a
// second, then egress on a third is blocked by trifecta-no-egress; in a
// fresh session the same egress before the untrusted read is allowed.
func TestTrifectaEndToEnd(t *testing.T) {
	// Arrange
	dir := roverDir(t)
	usePolicy(t, dir, string(policyfiles.Starter)+trifectaPermits, "enforce")
	if err := os.WriteFile(filepath.Join(dir, "config", "config.yaml"), []byte(trifectaConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	applyPolicy(t, dir)
	secret := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(secret, []byte("s3cret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := run(dir, "policy", "labels", "mail"); err != nil || !regexp.MustCompile(`mail\s+echo\s+egress\s+config`).MatchString(out) ||
		!regexp.MustCompile(`mail\s+\(any other tool\)\s+egress,reads_untrusted\s+default`).MatchString(out) {
		t.Fatalf("policy labels: %v\n%s", err, out)
	}
	startDaemon(t, dir)

	// Act: A and B are two agents (two driver processes). C is one agent
	// whose wrappers all exit after the two reads and come back for mail.
	blocked, sessA := trifectaSession(t, dir, secret, "files,web,mail")
	allowed, sessB := trifectaSession(t, dir, secret, "files,mail")
	restarted, sessC := trifectaSession(t, dir, secret, "files,web|mail")

	// Assert
	res, _ := blocked["result"].(map[string]any)
	if res == nil || res["isError"] != true || !strings.Contains(fmt.Sprint(res["content"]), "rule trifecta-no-egress)") {
		t.Fatalf("A: mail.echo after files and web must be blocked by trifecta-no-egress: %v", blocked)
	}
	if oneSession(t, sessA) == oneSession(t, sessB) {
		t.Fatalf("B must run in a fresh session (both %s)", sessA[0])
	}
	if !strings.Contains(fmt.Sprint(allowed["result"]), "hello from mail") {
		t.Fatalf("B: mail.echo before any untrusted read must be allowed: %v", allowed)
	}
	oneSession(t, sessC) // the restarted wrappers rejoined the lingering session
	res, _ = restarted["result"].(map[string]any)
	if res == nil || res["isError"] != true || !strings.Contains(fmt.Sprint(res["content"]), "rule trifecta-no-egress)") {
		t.Fatalf("C: restarting the servers must not wash out the taint: %v", restarted)
	}
}

// `rover policy test` replays the M8 flags: a request alone does not taint,
// its logged result does, and a blocked result does not.
func TestReplayResultSetsFlags(t *testing.T) {
	// Arrange
	st := &replaySession{pending: map[string][]string{"files:1": {"reads_private"}, "files:2": {"reads_private"}, "web:3": {"reads_untrusted"}}}
	ok := jsonrpc.Parse([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`))
	blocked := jsonrpc.Parse([]byte(`{"jsonrpc":"2.0","id":2,"result":{"content":[]}}`))
	failed := jsonrpc.Parse([]byte(`{"jsonrpc":"2.0","id":3,"result":{"content":[],"isError":true}}`))

	// Act
	replayResult(st, audit.Entry{Server: "files", Action: ipc.ActionBlock}, blocked)
	afterBlocked := st.flags
	replayResult(st, audit.Entry{Server: "files", Action: ipc.ActionForward}, ok)
	replayResult(st, audit.Entry{Server: "web", Action: ipc.ActionForward}, failed)

	// Assert
	if afterBlocked.TouchedPrivate || !st.flags.TouchedPrivate || !st.flags.SawUntrusted || len(st.pending) != 0 {
		t.Fatalf("after blocked %+v, final %+v, pending %v", afterBlocked, st.flags, st.pending)
	}
}
