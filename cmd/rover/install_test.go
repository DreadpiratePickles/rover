package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// e2e: `rover install` against a fixture config in a throwaway HOME: a dry
// run and a run without a terminal write nothing; --yes wraps every stdio
// server and adds the Claude Code deny rules; uninstall --yes gives back the
// original bytes of both files.
func TestInstallUninstallEndToEnd(t *testing.T) {
	dir := roverDir(t)
	home := filepath.Join(dir, "home")
	cfg := filepath.Join(home, ".claude.json")
	_ = os.MkdirAll(home, 0o700)
	orig, err := os.ReadFile("../../internal/clients/testdata/claude-code.user.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(cfg, orig, 0o600); err != nil { //nolint:gosec // G703: a path the test built under its own temp directory
		t.Fatal(err)
	}
	settings := filepath.Join(home, ".claude", "settings.json")
	_ = os.MkdirAll(filepath.Dir(settings), 0o700)
	settingsOrig := []byte("{\n  \"model\": \"opus\"\n}\n")
	if err = os.WriteFile(settings, settingsOrig, 0o600); err != nil {
		t.Fatal(err)
	}
	unchanged := func(when string) {
		t.Helper()
		if b, _ := os.ReadFile(cfg); //nolint:gosec // G304: the test's own temp file
		!bytes.Equal(b, orig) {
			t.Fatalf("%s changed the config:\n%s", when, b)
		}
		if b, _ := os.ReadFile(settings); //nolint:gosec // G304: the test's own temp file
		!bytes.Equal(b, settingsOrig) {
			t.Fatalf("%s changed settings.json:\n%s", when, b)
		}
	}

	out, err := run(dir, "install", "--client", "claude-code", "--dry-run")
	if err != nil || !strings.Contains(out, "+      \"command\": \""+bins.rover) || !strings.Contains(out, "stripe is a remote server") || !strings.Contains(out, "Edit(~/.claude.json)") {
		t.Fatalf("dry run (err %v):\n%s", err, out)
	}
	unchanged("--dry-run")
	if out, err = run(dir, "install", "--client", "claude-code"); err != nil || !strings.Contains(out, "not a terminal and no --yes") {
		t.Fatalf("no tty (err %v):\n%s", err, out)
	}
	unchanged("install without a terminal")

	if out, err = run(dir, "install", "--client", "claude-code", "--yes"); err != nil {
		t.Fatalf("install --yes: %v\n%s", err, out)
	}
	if b, _ := os.ReadFile(cfg); //nolint:gosec // G304: the test's own temp file
	bytes.Count(b, []byte(`"wrap", "--name`)) != 6 {
		t.Fatalf("not wrapped:\n%s", b)
	}
	if b, _ := os.ReadFile(settings); //nolint:gosec // G304: the test's own temp file
	!bytes.Contains(b, []byte(`"Edit(~/.cursor/mcp.json)"`)) || !bytes.Contains(b, []byte(`"model": "opus"`)) {
		t.Fatalf("settings:\n%s", b)
	}
	if out, err = run(dir, "install", "--client", "claude-code", "--yes"); err != nil || !strings.Contains(out, "nothing to do") || !strings.Contains(out, "already present") {
		t.Fatalf("second install (err %v):\n%s", err, out)
	}
	if out, err = run(dir, "uninstall", "--client", "claude-code", "--yes"); err != nil {
		t.Fatalf("uninstall: %v\n%s", err, out)
	}
	unchanged("install + uninstall")
}

func TestServiceFiles(t *testing.T) {
	plist := string(launchdPlist("/opt/a&b/rover", "/s/roverd.log", ""))
	for _, want := range []string{"<string>/opt/a&amp;b/rover</string>", "<key>RunAtLoad</key>\n\t<true/>", "<key>KeepAlive</key>\n\t<true/>", "net.rover.roverd"} {
		if !strings.Contains(plist, want) {
			t.Errorf("plist lacks %q:\n%s", want, plist)
		}
	}
	unit := string(systemdUnitFile("/opt/my rover/rover", "/s/roverd.log", "/r%d"))
	for _, want := range []string{`ExecStart="/opt/my rover/rover" daemon`, `Environment="ROVER_DIR=/r%%d"`, "WantedBy=default.target"} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit lacks %q:\n%s", want, unit)
		}
	}
}

// H2: install refuses a file with a server it cannot parse, writes nothing
// and says why. H3: install a, add b, install, uninstall leaves the
// original with b added and nothing wrapped. H4: --service without --yes
// writes nothing.
func TestInstallRefusesAndUninstallStacked(t *testing.T) {
	dir := roverDir(t)
	home := filepath.Join(dir, "home")
	cfg := filepath.Join(home, ".cursor", "mcp.json")
	_ = os.MkdirAll(filepath.Dir(cfg), 0o700)
	write := func(s string) {
		if err := os.WriteFile(cfg, []byte(s), 0o600); err != nil { //nolint:gosec // G703: a path the test built under its own temp directory
			t.Fatal(err)
		}
	}
	bad := `{"mcpServers": {"a": {"command": "x", "Command": "y"}, "b": {"command": "z"}}}`
	write(bad)
	out, err := run(dir, "install", "--client", "cursor", "--yes")
	if err == nil || !strings.Contains(out, "does not understand") || !strings.Contains(out, "global/a") {
		t.Fatalf("install of a bad file (err %v):\n%s", err, out)
	}
	if b, _ := os.ReadFile(cfg); string(b) != bad { //nolint:gosec // G304: the test's own temp file
		t.Fatalf("refused install wrote:\n%s", b)
	}

	orig := "{\n  \"mcpServers\": {\n    \"a\": {\"command\": \"x\"}\n  }\n}\n"
	write(orig)
	if out, err = run(dir, "install", "--client", "cursor", "--yes"); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	cur, _ := os.ReadFile(cfg) //nolint:gosec // G304: the test's own temp file
	write(strings.Replace(string(cur), "\n  }\n}", ",\n    \"b\": {\"command\": \"y\"}\n  }\n}", 1))
	if out, err = run(dir, "install", "--client", "cursor", "--yes"); err != nil {
		t.Fatalf("second install: %v\n%s", err, out)
	}
	if out, err = run(dir, "uninstall", "--client", "cursor", "--yes"); err != nil {
		t.Fatalf("uninstall: %v\n%s", err, out)
	}
	want := "{\n  \"mcpServers\": {\n    \"a\": {\"command\": \"x\"},\n    \"b\": {\"command\": \"y\"}\n  }\n}\n"
	if b, _ := os.ReadFile(cfg); string(b) != want { //nolint:gosec // G304: the test's own temp file
		t.Fatalf("after uninstall:\n%s\noutput:\n%s", b, out)
	}
	if !strings.Contains(out, "restored the newest backup") || !strings.Contains(out, "unwrapped in place") {
		t.Errorf("uninstall did not say what it did:\n%s", out)
	}

	out, err = run(dir, "install", "--service")
	if err != nil || !strings.Contains(out, "nothing written") {
		t.Fatalf("--service without --yes (err %v):\n%s", err, out)
	}
	for _, p := range []string{"Library/LaunchAgents/net.rover.roverd.plist", ".config/systemd/user/roverd.service"} {
		if _, err := os.Stat(filepath.Join(home, p)); !os.IsNotExist(err) {
			t.Fatalf("%s was written without --yes", p)
		}
	}
}
