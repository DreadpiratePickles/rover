package main

import (
	"bufio"
	"fmt"
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

// wrapAs starts `rover wrap --name name -- echo-server` as a child of the
// test process, so every wrapper it starts shares one agent pid (the test)
// and so one roverd session.
func wrapAs(t *testing.T, dir, name string) *mcp {
	t.Helper()
	m := &mcp{t: t, cmd: exec.Command(bins.rover, "wrap", "--name", name, "--", bins.echo)} //nolint:gosec // G204: test runs the binaries it just built
	m.cmd.Env = env(dir, "ROVER_TEST_NO_AUTOSTART=1")
	m.in, _ = m.cmd.StdinPipe()
	stdout, _ := m.cmd.StdoutPipe()
	m.out = bufio.NewReader(stdout)
	m.cmd.Stderr = &m.stderr
	if err := m.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	m.call(`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}`)
	return m
}

func toolCall(id int, tool, args string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, id, tool, args)
}

var sessionRE = regexp.MustCompile(`session ([0-9a-f]+): wrapping`)

// trifectaSession starts files, web and mail, runs calls ("files" reads
// secretPath, the others echo), closes them and returns the last reply and
// the session id the three shared.
func trifectaSession(t *testing.T, dir, secretPath string, order ...string) (last map[string]any, session string) {
	t.Helper()
	ms := map[string]*mcp{}
	for _, n := range []string{"files", "web", "mail"} {
		ms[n] = wrapAs(t, dir, n)
	}
	for i, n := range order {
		if n == "files" {
			last = ms[n].call(toolCall(i+1, "read_file", fmt.Sprintf(`{"path":%q}`, secretPath)))
			if !strings.Contains(fmt.Sprint(last["result"]), "s3cret") {
				t.Fatalf("files.read_file must succeed: %v", last)
			}
			continue
		}
		last = ms[n].call(toolCall(i+1, "echo", `{"text":"hello from `+n+`"}`))
	}
	ids := map[string]bool{}
	for _, n := range []string{"files", "web", "mail"} {
		ms[n].close()
		match := sessionRE.FindStringSubmatch(ms[n].stderr.String())
		if match == nil {
			t.Fatalf("%s: no session on stderr: %s", n, ms[n].stderr.String())
		}
		ids[match[1]] = true
	}
	if len(ids) != 1 {
		t.Fatalf("the three wrappers must share one session: %v", ids)
	}
	for id := range ids {
		session = id
	}
	return last, session
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
	secret := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(secret, []byte("s3cret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := run(dir, "policy", "labels", "mail"); err != nil || !regexp.MustCompile(`mail\s+echo\s+egress\s+config`).MatchString(out) ||
		!regexp.MustCompile(`mail\s+\(any other tool\)\s+egress,reads_untrusted\s+default`).MatchString(out) {
		t.Fatalf("policy labels: %v\n%s", err, out)
	}
	daemonErr := startDaemon(t, dir)

	// Act: sequence A, then (after roverd closed that session) sequence B.
	blocked, sessA := trifectaSession(t, dir, secret, "files", "web", "mail")
	waitFor(t, daemonErr, "session "+sessA+": closed")
	allowed, sessB := trifectaSession(t, dir, secret, "files", "mail")

	// Assert
	res, _ := blocked["result"].(map[string]any)
	if res == nil || res["isError"] != true || !strings.Contains(fmt.Sprint(res["content"]), "rule trifecta-no-egress)") {
		t.Fatalf("A: mail.echo after files and web must be blocked by trifecta-no-egress: %v", blocked)
	}
	if sessA == sessB {
		t.Fatalf("B must run in a fresh session (both %s)", sessA)
	}
	if !strings.Contains(fmt.Sprint(allowed["result"]), "hello from mail") {
		t.Fatalf("B: mail.echo before any untrusted read must be allowed: %v", allowed)
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
