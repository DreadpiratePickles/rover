package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/bridge/bridgetest"
)

const bridgePolicy = `
@id("remote-list") permit (principal, action == Action::"list_tools", resource == Server::"remote");
@id("remote-echo") permit (principal, action == Action::"call_tool", resource == Tool::"remote/echo");
`

// Acceptance (M11): a bridge session goes through roverd exactly like a
// wrapped one. An allowed remote tool call reaches the remote over TLS
// (hybrid post-quantum key exchange, recorded in the audit log); a call
// the policy does not permit gets the isError result and never reaches
// the remote. `rover doctor --remote` shows the negotiated group.
func TestBridgeThroughDaemon(t *testing.T) {
	dir := roverDir(t)
	remote := &bridgetest.Remote{SSE: true}
	srv := httptest.NewTLSServer(remote)
	defer srv.Close()
	remote.Base = srv.URL
	ca := filepath.Join(dir, "remote-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	usePolicy(t, dir, bridgePolicy, "enforce")
	cfgPath := filepath.Join(dir, "config", "config.yaml")
	cfg, _ := os.ReadFile(cfgPath) //nolint:gosec // G304: test's ROVER_DIR
	cfg = append(cfg, fmt.Sprintf("bridges:\n  remote:\n    url: %s\n    pq_required: true\n    ca_file: %s\n    auth: {type: none}\n", remote.URL(), ca)...)
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil { //nolint:gosec // G703: test's own file
		t.Fatal(err)
	}
	applyPolicy(t, dir)
	startDaemon(t, dir)

	m := &mcp{t: t, cmd: exec.Command(bins.rover, "bridge", "--name", "remote", "--url", remote.URL())} //nolint:gosec // G204: test runs the binary it just built
	m.cmd.Env = env(dir, "ROVER_TEST_NO_AUTOSTART=1")
	m.in, _ = m.cmd.StdinPipe()
	stdout, _ := m.cmd.StdoutPipe()
	m.out = bufio.NewReader(stdout)
	m.cmd.Stderr = &m.stderr
	if err := m.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	reply := func(line string) map[string]any {
		t.Helper()
		r := m.call(line)
		for r["method"] != nil { // progress notifications from the SSE stream
			b, err := m.out.ReadBytes('\n')
			if err != nil {
				t.Fatalf("read: %v (%s)", err, m.stderr.String())
			}
			r = map[string]any{}
			_ = json.Unmarshal(b, &r)
		}
		return r
	}
	reply(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}`)
	reply(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	echo := reply(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"through the bridge"}}}`)
	del := reply(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"delete_file","arguments":{"path":"/etc/hosts"}}}`)
	m.close()

	if !strings.Contains(fmt.Sprint(echo["result"]), "through the bridge") {
		t.Fatalf("echo: %v\n%s", echo, m.stderr.String())
	}
	res, _ := del["result"].(map[string]any)
	if res == nil || res["isError"] != true {
		t.Fatalf("delete_file must get roverd's isError result: %v", del)
	}
	for _, b := range remote.Bodies() {
		if bytes.Contains(b, []byte("delete_file")) && bytes.Contains(b, []byte("tools/call")) {
			t.Fatal("the blocked call reached the remote")
		}
	}
	if !strings.Contains(m.stderr.String(), "negotiated X25519MLKEM768") {
		t.Errorf("stderr should log the TLS group:\n%s", m.stderr.String())
	}
	if remote.Deleted() != 1 {
		t.Error("the bridge must end the remote session on exit")
	}

	tlsFinding, blocked := false, false
	data, _ := os.ReadFile(filepath.Join(dir, "state", "audit.jsonl")) //nolint:gosec // G304: test's ROVER_DIR
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		var e audit.Entry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatal(err)
		}
		for _, f := range e.Findings {
			if f == "tls:X25519MLKEM768" && e.Server == "remote" {
				tlsFinding = true
			}
		}
		if e.Action == "block" && e.Method == "tools/call" && e.Server == "remote" {
			blocked = true
		}
	}
	if !tlsFinding || !blocked {
		t.Fatalf("audit: tls finding %v, block %v\n%s", tlsFinding, blocked, data)
	}

	out, err := run(dir, "doctor", "--remote")
	if !strings.Contains(out, "remote: "+strings.TrimPrefix(srv.URL, "https://")+" negotiated X25519MLKEM768") {
		t.Fatalf("doctor --remote (err %v):\n%s", err, out)
	}
}

// The url in the client config cannot override config.yaml's, and plain
// http to a non-loopback host is refused before anything starts.
func TestBridgeRefusesBadURL(t *testing.T) {
	dir := roverDir(t)
	for _, args := range [][]string{
		{"bridge", "--name", "x", "--url", "http://example.com/mcp"},
		{"bridge", "--name", "x", "--url", "http://127.0.0.1:1/mcp", "--pq-required"},
		{"bridge", "--name", "bad/name", "--url", "https://example.com/mcp"},
		{"bridge", "login", "--name", "x", "--token", "ghp_secret"},
	} {
		out, err := run(dir, args...)
		if err == nil {
			t.Errorf("%v: accepted:\n%s", args, out)
		}
		if _, err := os.Stat(filepath.Join(dir, "run", "roverd.pid")); err == nil {
			t.Fatalf("%v: roverd was started", args)
		}
	}
}
