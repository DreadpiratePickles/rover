package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// echoYAML allows echo, and denies read_file outside the root "lab".
const echoYAML = `version: 1
mode: enforce
defaults: deny
roots: { lab: /tmp }
rules:
  - id: echo-call
    allow: echo.echo
  - id: read-lab-only
    allow: echo.read_file
    when: { path_under: lab }
`

func writeConfigFile(t *testing.T, dir, name, src string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "config", name), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
}

func initYAML(t *testing.T, dir string) {
	t.Helper()
	out, err := run(dir, "policy", "init", "--yaml")
	if err != nil || !strings.Contains(out, "policy.yaml") {
		t.Fatalf("init --yaml: %v\n%s", err, out)
	}
}

// Acceptance (M3): init --yaml, compile, validate, and roverd compiling
// policy.yaml at load when there is no policy.cedar.
func TestPolicyYAMLEndToEnd(t *testing.T) {
	// Arrange
	dir := roverDir(t)
	initYAML(t, dir)
	if _, err := os.Stat(filepath.Join(dir, "config", "policy.cedar")); !os.IsNotExist(err) {
		t.Fatalf("init --yaml must not write policy.cedar: %v", err)
	}
	starter := filepath.Join(dir, "config", "policy.yaml")
	if out, err := run(dir, "policy", "compile", starter); err != nil || !strings.Contains(out, `@id("fs-read-projects")`) || !strings.Contains(out, "// from "+starter+":") {
		t.Fatalf("compile starter: %v\n%s", err, out)
	}
	if out, err := run(dir, "policy", "validate"); err != nil || !strings.Contains(out, "compiled "+starter+": 4 rules + 2 implied list_tools permits") || !strings.Contains(out, "trifecta  forbid") {
		t.Fatalf("validate starter: %v\n%s", err, out)
	}
	writeConfigFile(t, dir, "policy.yaml", echoYAML)
	applyPolicy(t, dir)
	logs := startDaemon(t, dir)
	waitFor(t, logs, "compiling policy.yaml")
	waitFor(t, logs, "policy loaded (mode enforce)")
	m := wrapEcho(t, dir)

	// Act
	m.call(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}`)
	list := m.call(`{"jsonrpc":"2.0","id":5,"method":"tools/list"}`)
	echo := m.call(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi yaml"}}}`)
	read := m.call(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/passwd"}}}`)
	m.close()

	// Assert
	if !strings.Contains(fmt.Sprint(list["result"]), "echo") || list["error"] != nil {
		t.Fatalf("the implied list_tools permit must let the agent list tools: %v", list)
	}
	if !strings.Contains(fmt.Sprint(echo["result"]), "hi yaml") {
		t.Fatalf("echo must be allowed: %v", echo)
	}
	res, _ := read["result"].(map[string]any)
	if res == nil || res["isError"] != true || !strings.Contains(fmt.Sprint(res["content"]), "no permit matched") {
		t.Fatalf("read_file outside lab must be blocked: %v", read)
	}
}

func TestPolicyCompileRefusesTypoWithPosition(t *testing.T) {
	// Arrange
	dir := roverDir(t)
	bad := filepath.Join(dir, "bad.yaml")
	src := "version: 1\ndefaults: deny\nrules:\n  - id: a\n    alow: echo.echo\n"
	if err := os.WriteFile(bad, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	// Act
	out, err := run(dir, "policy", "compile", bad)
	vout, verr := run(dir, "policy", "validate", bad)

	// Assert
	want := bad + `:5:5: a rule: unknown key "alow"`
	if err == nil || !strings.Contains(out, want) {
		t.Fatalf("compile must exit 1 naming line and column: %v\n%s", err, out)
	}
	if verr == nil || !strings.Contains(vout, want) {
		t.Fatalf("validate must exit 1 naming line and column: %v\n%s", verr, vout)
	}
}

func TestPolicyCedarWinsOverYAML(t *testing.T) {
	// Arrange
	dir := roverDir(t)
	usePolicy(t, dir, e2ePolicy, "enforce")
	writeConfigFile(t, dir, "policy.yaml", "this is not even yaml: [")

	// Act
	logs := startDaemon(t, dir)

	// Assert
	waitFor(t, logs, "using policy.cedar (it wins)")
	waitFor(t, logs, "policy loaded (mode enforce)")
}

func TestYAMLCompileErrorLeavesNoPolicy(t *testing.T) {
	// Arrange
	dir := roverDir(t)
	initYAML(t, dir)
	writeConfigFile(t, dir, "policy.yaml", strings.Replace(echoYAML, "allow: echo.echo", "alow: echo.echo", 1))

	// Act
	logs := startDaemon(t, dir)
	waitFor(t, logs, "POLICY NOT LOADED")
	m := wrapEcho(t, dir)
	r := m.call(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"x"}}}`)
	m.close()

	// Assert
	if !strings.Contains(logs.String(), "policy.yaml:7:5:") {
		t.Errorf("the log must name the YAML line and column:\n%s", logs.String())
	}
	if !strings.Contains(fmt.Sprint(r["result"]), "no_policy") {
		t.Fatalf("want a no_policy block, got %v", r)
	}
}

func TestValidatePrintSchemaUsesYAMLRoots(t *testing.T) {
	// Arrange
	dir := roverDir(t)
	initYAML(t, dir)
	writeConfigFile(t, dir, "policy.yaml", echoYAML)

	// Act
	out, err := run(dir, "policy", "validate", "--print-schema")

	// Assert
	if err != nil || !strings.Contains(out, "under_lab?: Bool") || strings.Contains(out, "under_projects?:") {
		t.Fatalf("print-schema: %v\n%s", err, out)
	}
}
