package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/DreadpiratePickles/rover/internal/dlp"
)

var leaky struct {
	once sync.Once
	path string
	err  error
}

// leakyBin builds the lab-only leaky server (build tag "lab") once.
func leakyBin(t *testing.T) string {
	t.Helper()
	leaky.once.Do(func() {
		leaky.path = filepath.Join(filepath.Dir(bins.rover), "leaky")
		out, err := exec.Command("go", "build", "-tags", "lab", "-o", leaky.path, "../../testdata/servers/leaky").CombinedOutput() //nolint:gosec // G204: test builds a fixed package into its temp dir
		if err != nil {
			leaky.err = fmt.Errorf("build leaky: %w\n%s", err, out)
		}
	})
	if leaky.err != nil {
		t.Fatal(leaky.err)
	}
	return leaky.path
}

const leakyPolicy = `
@id("list") permit (principal, action == Action::"list_tools", resource);
@id("calls") permit (principal, action == Action::"call_tool", resource);
`

const leakyConfig = `mode: observe
labels:
  leaky: { leak: [reads_untrusted], leak_split: [reads_untrusted], fail: [reads_untrusted], leak_key: [reads_untrusted], fail_key: [reads_untrusted], send: [egress] }
`

// startDaemonLogged runs roverd with its stderr in state/roverd.log, as an
// auto-started roverd has it, so the grep sees the daemon log too.
func startDaemonLogged(t *testing.T, dir string, args ...string) func() {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	logf, err := os.OpenFile(filepath.Join(dir, "state", "roverd.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // G304: the test's ROVER_DIR
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bins.rover, append([]string{"--test-auth=allow", "daemon"}, args...)...) //nolint:gosec // G204: test runs the binary it just built
	cmd.Env, cmd.Stderr = env(dir), logf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			_ = cmd.Wait()
			_ = logf.Close()
		})
	}
	t.Cleanup(stop)
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(filepath.Join(dir, "run", "roverd.sock")); err == nil {
			return stop
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("daemon did not start")
	return nil
}

func wrapLeaky(t *testing.T, dir string) *mcp {
	t.Helper()
	m := &mcp{t: t, cmd: exec.Command(bins.rover, "wrap", "--name", "leaky", "--", leakyBin(t))} //nolint:gosec // G204: test runs the binaries it built
	m.cmd.Env = env(dir, "ROVER_TEST_NO_AUTOSTART=1")
	m.in, _ = m.cmd.StdinPipe()
	stdout, _ := m.cmd.StdoutPipe()
	m.out = bufio.NewReader(stdout)
	m.cmd.Stderr = &m.stderr
	if err := m.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	m.call(`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}`)
	m.call(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	return m
}

// needles are the forms of a secret that must not appear anywhere: the
// secret, its JSON-escaped form, and each line of 16+ bytes (key bodies).
func needles(secret string) []string {
	esc, _ := json.Marshal(secret)
	out := []string{secret, strings.Trim(string(esc), `"`)}
	for _, l := range strings.Split(secret, "\n") {
		if len(l) >= 16 {
			out = append(out, l)
		}
	}
	return out
}

// Acceptance (plan M10): every fixture secret goes through a result (text
// block, structuredContent, resource), two split text blocks, an error and
// an egress argument, with bodies logged and learn mode on; afterwards no
// file under ROVER_DIR holds any of them. The egress calls are blocked; the
// non-egress calls carrying the same text are forwarded (redaction is for
// what the model sees, not what a tool receives).
func TestNoFixtureSecretReachesRoverDir(t *testing.T) {
	// Arrange
	cases, err := dlp.LoadCorpus(filepath.Join("..", "..", "testdata", "corpus", "dlp"))
	if err != nil {
		t.Fatal(err)
	}
	dir := roverDir(t)
	usePolicy(t, dir, leakyPolicy, "observe")
	writeFile(t, filepath.Join(dir, "config", "config.yaml"), leakyConfig)
	applyPolicy(t, dir)
	stop := startDaemonLogged(t, dir)
	m := wrapLeaky(t, dir)

	// Act
	id := 10
	for _, c := range cases {
		if c.Label != dlp.LabelSecrets {
			continue
		}
		arg, _ := json.Marshal(map[string]string{"text": c.Text})
		calls := [][2]string{{"leak", string(arg)}, {"leak_split", string(arg)}, {"fail", string(arg)}, {"send", string(arg)}}
		if ms := dlp.New().Find([]byte(c.Secret)); len(ms) > 0 {
			// The bare secret, as a value (learn mode keeps short
			// literals) and as a member NAME: in a result, structured
			// content, an error's data and in arguments (review H1).
			bare, _ := json.Marshal(map[string]string{"text": c.Secret})
			asName, _ := json.Marshal(map[string]string{c.Secret: "v"})
			calls = append(calls, [2]string{"leak", string(bare)}, [2]string{"leak_key", string(bare)},
				[2]string{"fail_key", string(bare)}, [2]string{"leak", string(asName)}, [2]string{"send", string(asName)})
		}
		for _, call := range calls {
			id++
			tool := call[0]
			r := m.call(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, id, tool, call[1]))
			got, _ := json.Marshal(r)
			for _, n := range needles(c.Secret) {
				if strings.Contains(string(got), n) {
					t.Errorf("%s via %s reached the agent: %s", c.ID, tool, got)
				}
			}
			res, _ := r["result"].(map[string]any)
			switch {
			case tool == "send" && (res["isError"] != true || !strings.Contains(string(got), "secret_in_egress_args:")):
				t.Errorf("%s: egress with a secret must be blocked: %s", c.ID, got)
			case (tool == "leak" || tool == "leak_split") && (res == nil || res["isError"] == true):
				t.Errorf("%s: a non-egress call carrying a secret must be forwarded: %s", c.ID, got)
			}
		}
	}
	m.close()
	stop() // flushes learn observations and closes state.db

	// Assert: no file under ROVER_DIR holds any fixture secret.
	files := 0
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p) //nolint:gosec // G304: the test's ROVER_DIR
		if err != nil {
			return err
		}
		files++
		for _, c := range cases {
			for _, n := range needles(c.Secret) {
				if c.Label == dlp.LabelSecrets && bytes.Contains(b, []byte(n)) {
					t.Errorf("%s: %s found in %s", c.ID, strings.SplitN(n, "\n", 2)[0], p)
				}
			}
		}
		return nil
	})
	if err != nil || files < 4 {
		t.Fatalf("walk: %v (%d files)", err, files)
	}
	audit, _ := os.ReadFile(filepath.Join(dir, "state", "audit.jsonl")) //nolint:gosec // G304: the test's ROVER_DIR
	if !bytes.Contains(audit, []byte(`"body":`)) || !bytes.Contains(audit, []byte("[REDACTED:")) || !bytes.Contains(audit, []byte("dlp:")) {
		t.Fatal("bodies must be logged by default, redacted, with dlp findings")
	}
	if out, err := run(dir, "log", "--verify"); err != nil {
		t.Fatalf("the redacted log must verify: %v\n%s", err, out)
	}
}

func TestNoBodiesFlagLogsMetadataOnly(t *testing.T) {
	for _, flag := range []string{"--no-bodies", "--log-bodies=false"} {
		dir := roverDir(t)
		usePolicy(t, dir, leakyPolicy, "observe")
		stop := startDaemonLogged(t, dir, flag)
		m := wrapLeaky(t, dir)
		m.close()
		stop()
		audit, err := os.ReadFile(filepath.Join(dir, "state", "audit.jsonl")) //nolint:gosec // G304: the test's ROVER_DIR
		if err != nil || bytes.Contains(audit, []byte(`"body":`)) || !bytes.Contains(audit, []byte(`"method":"tools/list"`)) {
			t.Fatalf("%s: %v\n%s", flag, err, audit)
		}
	}
}

// Acceptance (plan M10 via M9): with approvals.show_args on, the details
// page of a held call shows its arguments with the secret redacted.
func TestApprovalPageShowsRedactedArgs(t *testing.T) {
	dir := roverDir(t)
	usePolicy(t, dir, approvalPolicy, "enforce")
	writeFile(t, filepath.Join(dir, "config", "config.yaml"), "mode: enforce\nlabels:\n  echo: { echo: [] }\napprovals:\n  show_args: true\n")
	applyPolicy(t, dir)
	logs := startDaemonAuth(t, dir, "deny")
	m := wrapEcho(t, dir)
	defer m.close()
	m.call(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)

	r := m.call(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"key AKIAEXAMPLE000000001"}}}`)

	if !strings.Contains(fmt.Sprint(r["result"]), "approval denied") {
		t.Fatalf("%v", r)
	}
	link := regexp.MustCompile(`(http://127\.0\.0\.1:\d+/approval/[0-9a-f-]+\?t=[0-9a-f]{32})`).FindStringSubmatch(logs.String())
	if link == nil {
		t.Fatalf("no details link:\n%s", logs.String())
	}
	resp, err := http.Get(link[1]) //nolint:noctx // the test's own loopback link
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	_, _ = body.ReadFrom(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(body.String(), "[REDACTED:aws-access-key]") || strings.Contains(body.String(), "000000001") {
		t.Fatalf("page:\n%s", body.String())
	}
}
