package clients

import (
	"bytes"
	"strings"
	"testing"
)

// M11: remote entries become `rover bridge` entries; the conversion is
// byte-exact and its inverse gives back the original file.
func TestBridgeConversion(t *testing.T) {
	src := `{"mcpServers": {
  "plain": {"url": "https://a.example/mcp"},
  "legacy":   { "type" : "sse", "url":"https://b.example/sse" },
  "ws": {"type": "ws", "url": "wss://c.example"},
  "tok": {"url": "https://d.example/mcp", "headers": {"Authorization": "Bearer x"}}
}}`
	doc, err := parseDoc(cursorSpec, ConfigFile{Adapter: NameCursor, Path: "x"}, []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	p, err := planWrap(doc, testRover)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(p.Changed, ",") != "global/plain,global/legacy" {
		t.Fatalf("changed %v", p.Changed)
	}
	warn := strings.Join(p.Warnings, "\n")
	for _, w := range []string{"legacy HTTP+SSE", "WebSocket", "never forwards a client's headers"} {
		if !strings.Contains(warn, w) {
			t.Errorf("warnings lack %q:\n%s", w, warn)
		}
	}
	got := string(p.New)
	for _, want := range []string{
		`"plain": {"command": "/opt/rover/bin/rover", "args": ["bridge", "--name", "plain", "--url", "https://a.example/mcp"]}`,
		`"legacy":   { "type" : "stdio", "command":"/opt/rover/bin/rover", "args": ["bridge", "--name", "legacy", "--remote-type", "sse", "--url", "https://b.example/sse"] }`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks\n%s\nin\n%s", want, got)
		}
	}
	after, err := parseDoc(cursorSpec, doc.File, p.New)
	if err != nil {
		t.Fatal(err)
	}
	bridged := 0
	for _, s := range after.Servers {
		if s.Bridged && s.Status == StatusWrapped && s.WrappedBy(testRover) {
			bridged++
		}
	}
	if bridged != 2 {
		t.Fatalf("%d bridged entries after install", bridged)
	}
	if again, _ := planWrap(after, testRover); again.HasChanges() {
		t.Fatalf("second install changed something:\n%s", again.Diff)
	}
	up, err := PlanUnwrap(after)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(up.New, []byte(src)) {
		t.Fatalf("unbridge is not the inverse:\n%s", up.New)
	}
}

func TestUnbridgeRefusesHandEdits(t *testing.T) {
	src := `{"mcpServers": {"x": {"command": "/opt/rover/bin/rover", "env": {}, "args": ["bridge", "--name", "x", "--url", "https://a.example"]}}}`
	doc, err := parseDoc(cursorSpec, ConfigFile{Path: "x"}, []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if !doc.Servers[0].Bridged {
		t.Fatal("not recognised as bridged")
	}
	if _, err := PlanUnwrap(doc); err == nil {
		t.Fatal("a hand-edited bridge entry must not be unwrapped by guesswork")
	}
}
