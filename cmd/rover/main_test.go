package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/rover/internal/audit"
)

// End-to-end: build both binaries, run a real MCP handshake through the gateway.
func TestEndToEnd(t *testing.T) {
	dir := t.TempDir()
	gate := filepath.Join(dir, "rover")
	echo := filepath.Join(dir, "echo-server")
	for bin, pkg := range map[string]string{gate: ".", echo: "../../examples/echo-server"} {
		if out, err := exec.Command("go", "build", "-o", bin, pkg).CombinedOutput(); err != nil { //nolint:gosec // G204: test builds fixed packages into t.TempDir()
			t.Fatalf("build %s: %v\n%s", pkg, err, out)
		}
	}
	logPath := filepath.Join(dir, "audit.jsonl")

	cmd := exec.Command(gate, "wrap", "--log", logPath, "--", echo) //nolint:gosec // G204: test runs the binaries it just built
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	out := bufio.NewReader(stdout)
	send := func(s string) {
		if _, err := fmt.Fprintln(stdin, s); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	recv := func() map[string]any {
		line, err := out.ReadBytes('\n')
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("bad json %q", line)
		}
		return m
	}

	send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}`)
	if r := recv(); r["result"] == nil {
		t.Fatalf("initialize failed: %v", r)
	}
	send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	send(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi rover"}}}`)
	r := recv()
	if !strings.Contains(fmt.Sprint(r["result"]), "hi rover") {
		t.Fatalf("echo failed: %v", r)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("gateway exit: %v", err)
	}

	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("audit log perms = %o, want 600", perm)
	}

	f, err := os.Open(logPath) //nolint:gosec // G304: path is inside t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var kinds []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e audit.Entry
		_ = json.Unmarshal(sc.Bytes(), &e)
		kinds = append(kinds, e.Dir+":"+e.Kind+":"+e.Method+e.ReplyTo)
	}
	want := []string{
		"c2s:request:initialize", "s2c:result:initialize",
		"c2s:notification:notifications/initialized",
		"c2s:request:tools/call", "s2c:result:tools/call",
	}
	if strings.Join(kinds, ",") != strings.Join(want, ",") {
		t.Fatalf("log =\n%v\nwant\n%v", kinds, want)
	}
}
