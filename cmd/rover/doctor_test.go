package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/DreadpiratePickles/rover/internal/clients"
	"github.com/DreadpiratePickles/rover/internal/daemon"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/paths"
)

func TestDoctorCheckFunctions(t *testing.T) {
	dir := t.TempDir()
	st := &daemon.DoctorState{Mode: "observe", AuditHealthy: true, ServerVersion: 1}
	cases := []struct {
		got  check
		want string
	}{
		{checkDaemon(st, nil), statusPass},
		{checkDaemon(nil, fmt.Errorf("%w: x", ipc.ErrNoDaemon)), statusWarn},
		{checkDaemon(nil, errors.New("timeout")), statusFail},
		{checkDaemon(&daemon.DoctorState{}, nil), statusFail}, // audit unhealthy
		{checkSocket(filepath.Join(dir, "none.sock"), 0), statusWarn},
		{checkSocket(junkFile(t, dir, "notsock", 0o600), 0), statusFail},
		{checkDirs(paths.Dirs{Config: mkdir(t, dir, "c", 0o700), State: mkdir(t, dir, "s", 0o700), Run: mkdir(t, dir, "r", 0o700)}), statusPass},
		{checkDirs(paths.Dirs{Config: mkdir(t, dir, "open", 0o755), State: dir, Run: dir}), statusFail},
		{checkPolicy(func() (string, string, error) { return "", "", errors.New("no policy") })[0], statusFail},
		{checkPolicy(func() (string, string, error) { return "enforce", "", nil })[0], statusPass},
		{checkPolicy(func() (string, string, error) { return "enforce", "", nil })[1], statusWarn},
		{checkAudit(filepath.Join(dir, "none.jsonl")), statusWarn},
		{checkAudit(junkFile(t, dir, "bad.jsonl", 0o600)), statusFail},
		{checkTLS(func() (tls.CurveID, error) { return tls.X25519, nil }), statusFail},
		{checkTLS(func() (tls.CurveID, error) { return 0, errors.New("boom") }), statusFail},
		{checkTLS(probeTLS), statusPass}, // the real thing: Go 1.24+ defaults
		{checkNet(), statusWarn},
		{checkTamper(nil, errors.New("down")), statusWarn},
		{checkTamper(st, nil), statusPass},
		{checkTamper(&daemon.DoctorState{TamperAlerts: []daemon.TamperAlert{{Server: "user/fs", Kind: "unwrapped", File: "/x"}}}, nil), statusFail},
	}
	for i, c := range cases {
		if c.got.Status != c.want {
			t.Errorf("case %d (%s): %s %q, want %s", i, c.got.Name, c.got.Status, c.got.Detail, c.want)
		}
	}
}

func junkFile(t *testing.T, dir, name string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("{not json\n"), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func mkdir(t *testing.T, dir, name string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.Mkdir(p, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // umask
		t.Fatal(err)
	}
	return p
}

// Acceptance (M7): doctor detects a manually unwrapped server.
func TestDoctorClientsDetectsManualUnwrap(t *testing.T) {
	root := t.TempDir()
	env := clients.Env{Home: filepath.Join(root, "home"), GOOS: "darwin", BackupDir: filepath.Join(root, "backups")}
	cfg := filepath.Join(env.Home, ".cursor", "mcp.json")
	_ = os.MkdirAll(filepath.Dir(cfg), 0o700)
	const rover = "/opt/rover/bin/rover"
	write := func(s string) {
		if err := os.WriteFile(cfg, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"mcpServers":{"fs":{"command":"npx","args":["fs"]}}}`)
	a, _ := clients.Get(clients.NameCursor, env)
	files, _ := a.Detect()
	doc, _ := a.Read(files[0])
	p, _ := a.Plan(doc, rover)
	if err := a.Apply(p); err != nil {
		t.Fatal(err)
	}
	if c := checkClients(env, []clients.Adapter{a}, rover); c[0].Status != statusPass {
		t.Fatalf("after install: %+v", c)
	}
	write(`{"mcpServers":{"fs":{"command":"npx","args":["fs"]}}}`) // the agent's edit
	if c := checkClients(env, []clients.Adapter{a}, rover); c[0].Status != statusFail || !strings.Contains(c[0].Detail, "not wrapped: fs") {
		t.Fatalf("after manual unwrap: %+v", c)
	}
	write(`{"mcpServers":{"fs":{"command":"/tmp/x/rover","args":["wrap","--","npx","fs"]}}}`) // look-alike
	if c := checkClients(env, []clients.Adapter{a}, rover); c[0].Status != statusFail || !strings.Contains(c[0].Detail, "/tmp/x/rover") {
		t.Fatalf("look-alike: %+v", c)
	}
}

func TestDoctorOutputFormat(t *testing.T) {
	var b bytes.Buffer
	checks := []check{pass("daemon", "ok"), fail("tamper", "bad\x1b[2Jthing")}
	if err := writeDoctor(&b, checks, false); err != nil {
		t.Fatal(err)
	}
	want := "PASS  daemon           ok\nFAIL  tamper           bad\\u001b[2Jthing\n"
	if b.String() != want {
		t.Fatalf("got %q, want %q", b.String(), want)
	}
	b.Reset()
	_ = writeDoctor(&b, checks, true)
	if !strings.Contains(b.String(), "\x1b[38;2;252;136;20mFAIL\x1b[0m") || strings.Contains(b.String(), "\x1b[38;2;252;136;20mPASS") {
		t.Fatalf("colour: %q", b.String())
	}
}

// e2e: doctor against a running daemon in a throwaway ROVER_DIR and HOME,
// then with the daemon gone.
func TestDoctorEndToEnd(t *testing.T) {
	dir := roverDir(t)
	usePolicy(t, dir, `@id("p") permit (principal, action == Action::"call_tool", resource == Tool::"echo/echo");`, "observe")
	home := filepath.Join(dir, "home")
	cfg := filepath.Join(home, ".cursor", "mcp.json")
	_ = os.MkdirAll(filepath.Dir(cfg), 0o700)
	if err := os.WriteFile(cfg, []byte(`{"mcpServers":{"fs":{"command":"`+bins.rover+`","args":["wrap","--name","fs","--","npx","fs"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	stop := startDaemonStoppable(t, dir)
	out, err := run(dir, "doctor", "--json")
	var res struct {
		OK     bool
		Checks []check
	}
	if jerr := json.Unmarshal([]byte(out), &res); jerr != nil {
		t.Fatalf("doctor --json: %v\n%s", jerr, out)
	}
	status := map[string]string{}
	for _, c := range res.Checks {
		status[c.Name] = c.Status
	}
	for name, want := range map[string]string{"daemon": statusPass, "socket": statusPass, "dirs": statusPass, "policy": statusPass,
		"client": statusPass, "tls-pq": statusPass, "rover-net": statusWarn, "tamper": statusPass} {
		if status[name] != want {
			t.Errorf("%s = %s, want %s\n%s", name, status[name], want, out)
		}
	}
	if err != nil || !res.OK {
		t.Fatalf("doctor exit %v, ok %v\n%s", err, res.OK, out)
	}

	// The agent unwraps the server: roverd's watch alerts, doctor fails.
	if werr := os.WriteFile(cfg, []byte(`{"mcpServers":{"fs":{"command":"npx","args":["fs"]}}}`), 0o600); werr != nil {
		t.Fatal(werr)
	}
	var text string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if text, err = run(dir, "doctor"); strings.Contains(text, "FAIL  tamper") {
			break
		}
	}
	if err == nil || !strings.Contains(text, "FAIL  tamper") || !strings.Contains(text, "FAIL  client") {
		t.Fatalf("doctor after unwrap (err %v):\n%s", err, text)
	}

	stop()
	text, err = run(dir, "doctor")
	if err == nil || !strings.Contains(text, "WARN  daemon") || !strings.Contains(text, "WARN  tamper") {
		t.Fatalf("doctor with no daemon (err %v):\n%s", err, text)
	}
}

// startDaemonStoppable is startDaemon with a way to stop it mid-test.
func startDaemonStoppable(t *testing.T, dir string) func() {
	t.Helper()
	cmd := exec.Command(bins.rover, "daemon") //nolint:gosec // G204: test runs the binary it just built
	cmd.Env = env(dir)
	stderr := &lockedBuf{}
	cmd.Stderr = stderr
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
	t.Cleanup(func() {
		stop()
		if t.Failed() {
			t.Logf("daemon stderr:\n%s", stderr.String())
		}
	})
	sock := filepath.Join(dir, "run", "roverd.sock")
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(sock); err == nil {
			return stop
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("daemon did not start:\n%s", stderr.String())
	return nil
}
