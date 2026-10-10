package clients

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// M11: remote entries become `rover bridge` entries; the conversion is
// byte-exact and its inverse gives back the original file.
func TestBridgeConversion(t *testing.T) {
	src := `{"mcpServers": {
  "plain": {"type": "http", "url": "https://a.example/mcp"},
  "legacy":   { "type" : "sse", "url":"https://b.example/sse" },
  "ws": {"type": "ws", "url": "wss://c.example"},
  "tok": {"type": "http", "url": "https://d.example/mcp", "headers": {"Authorization": "Bearer x"}}
}}`
	doc, err := parseDoc(cursorSpec, ConfigFile{Adapter: NameCursor, Path: "x", Scope: "global"}, []byte(src))
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
		`"plain": {"type": "stdio", "command": "/opt/rover/bin/rover", "args": ["bridge", "--name", "plain", "--remote-type", "http", "--url", "https://a.example/mcp"]}`,
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

// M9's rule stands: a "url" without a "type" is a configuration error in
// Claude Code's words, reported, never guessed to be remote and converted.
func TestURLWithoutTypeIsReportedNotConverted(t *testing.T) {
	doc, err := parseDoc(cursorSpec, ConfigFile{Adapter: NameCursor, Path: "x"}, []byte(`{"mcpServers": {"notype": {"url": "https://a.example/mcp"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Servers[0].Status != StatusUnknown || !strings.Contains(doc.Servers[0].Problem, `"url" without a "type"`) {
		t.Fatalf("classified as %+v", doc.Servers[0])
	}
	if _, err := planWrap(doc, testRover); !errors.Is(err, ErrNotUnderstood) || !strings.Contains(err.Error(), `"url" without a "type"`) {
		t.Fatalf("planWrap: %v", err)
	}
}

const rover = `"/opt/rover/bin/rover"`

// Review HIGH-2: uninstall finds "command" and "args" wherever a client
// that rewrote its file has put them, and never panics on them.
func TestUnbridgeIsPositionIndependent(t *testing.T) {
	args := `["bridge", "--name", "x", "--remote-type", "http", "--url", "https://a.example/mcp"]`
	for _, c := range []struct{ name, in, want string }{
		{"install's own form", `{"mcpServers": {"x": {"type": "stdio", "command": ` + rover + `, "args": ` + args + `}}}`,
			`{"mcpServers": {"x": {"type": "http", "url": "https://a.example/mcp"}}}`},
		{"args before command", `{"mcpServers": {"x": {"type": "stdio", "args": ` + args + `, "command": ` + rover + `}}}`,
			`{"mcpServers": {"x": {"type": "http", "url": "https://a.example/mcp"}}}`},
		{"args first, type last", `{"mcpServers": {"x": {"args": ` + args + `, "command": ` + rover + `, "type": "stdio"}}}`,
			`{"mcpServers": {"x": {"url": "https://a.example/mcp", "type": "http"}}}`},
		{"a member between", `{"mcpServers": {"x": {"command": ` + rover + `, "env": {}, "args": ` + args + `, "type": "stdio"}}}`,
			`{"mcpServers": {"x": {"url": "https://a.example/mcp", "env": {}, "type": "http"}}}`},
		{"reformatted, 4 spaces, one member per line", "{\n    \"mcpServers\": {\n        \"x\": {\n            \"args\": " + args + ",\n            \"command\": " + rover + ",\n            \"type\": \"stdio\"\n        }\n    }\n}\n",
			"{\n    \"mcpServers\": {\n        \"x\": {\n            \"url\": \"https://a.example/mcp\",\n            \"type\": \"http\"\n        }\n    }\n}\n"},
		{"no spacing at all", `{"mcpServers":{"x":{"args":` + args + `,"command":` + rover + `,"type":"stdio"}}}`,
			`{"mcpServers":{"x":{"url":"https://a.example/mcp","type":"http"}}}`},
		{"five-element form, no type", `{"mcpServers": {"x": {"args": ["bridge", "--name", "x", "--url", "https://a.example"], "command": ` + rover + `}}}`,
			`{"mcpServers": {"x": {"url": "https://a.example"}}}`},
	} {
		doc, err := parseDoc(cursorSpec, ConfigFile{Adapter: NameCursor, Path: "x"}, []byte(c.in))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(doc.Servers) != 1 || !doc.Servers[0].Bridged {
			t.Fatalf("%s: not recognised as bridged: %+v", c.name, doc.Servers)
		}
		p, err := PlanUnwrap(doc)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if string(p.New) != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, p.New, c.want)
		}
	}
	if _, err := PlanUnwrap(Doc{Servers: []Server{{Bridged: true, Status: StatusWrapped}}}); err == nil {
		t.Fatal("a bridged server without offsets must be refused, not dereferenced")
	}
}

// install then uninstall gives the input back byte for byte, whatever the
// layout of the remote entry, when nothing else changed in between.
func TestInstallUninstallRemoteRoundTrip(t *testing.T) {
	for _, in := range []string{
		`{"mcpServers": {"r": {"type": "http", "url": "https://a.example/mcp"}}}`,
		`{"mcpServers": {"r": {"url": "https://a.example/mcp", "type": "http"}}}`,
		`{"mcpServers":{"r":{"url":"https://a.example/mcp","type":"sse"}}}`,
		"{\n    \"mcpServers\": {\n        \"r\": {\n            \"type\": \"http\",\n            \"url\": \"https://a.example/mcp\"\n        }\n    }\n}\n",
		"{\n\t\"mcpServers\": {\n\t\t\"r\": {\n\t\t\t\"url\" : \"https://a.example/mcp\" ,\n\t\t\t\"env\": {\"A\": \"b\"},\n\t\t\t\"type\" : \"http\"\n\t\t}\n\t}\n}\n",
		"// comments survive\n{\"mcpServers\": {\"r\": {\"type\": \"http\", /* here */ \"url\": \"https://a.example/mcp\",}}}",
	} {
		doc, err := parseDoc(cursorSpec, ConfigFile{Adapter: NameCursor, Path: "x"}, []byte(in))
		if err != nil {
			t.Fatal(err)
		}
		p, err := planWrap(doc, testRover)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if !p.HasChanges() {
			t.Fatalf("%s: nothing converted", in)
		}
		after, err := parseDoc(cursorSpec, doc.File, p.New)
		if err != nil {
			t.Fatalf("%s: after install: %v\n%s", in, err, p.New)
		}
		up, err := PlanUnwrap(after)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if string(up.New) != in {
			t.Errorf("not the inverse:\n in  %q\n out %q", in, up.New)
		}
	}
}

// FuzzUnbridge: the client config is a file an agent can write. Unbridging
// never panics and never edits outside the server's own object.
func FuzzUnbridge(f *testing.F) {
	args := `["bridge", "--name", "x", "--remote-type", "http", "--url", "https://a.example/mcp"]`
	f.Add(`{"mcpServers": {"x": {"type": "stdio", "command": ` + rover + `, "args": ` + args + `}}}`)
	f.Add(`{"mcpServers": {"x": {"args": ` + args + `, "command": ` + rover + `}}}`)
	f.Add(`{"mcpServers": {"x": {"command": ` + rover + `, "env": {}, "args": ["bridge", "--name", "x", "--url", "https://a.example"]}}}`)
	f.Add(`{"mcpServers": {"x": {"args": ["bridge","--name","x","--url","u"],"command":"rover"},"y":{"command":"rover","args":["bridge","--name","y","--url","v"]}}}`)
	f.Add(`{"mcpServers": {"x": {"command": "rover", "args": ["bridge", "--name", "x", "--url", "u"],}}}`)
	f.Fuzz(func(t *testing.T, in string) {
		doc, err := parseDoc(cursorSpec, ConfigFile{Adapter: NameCursor, Path: "x"}, []byte(in))
		if err != nil {
			return
		}
		for _, s := range doc.Servers {
			if !s.Bridged {
				continue
			}
			es, err := unwrapEdits(doc.Orig, s)
			if err != nil {
				continue
			}
			for _, e := range es {
				if e.start < s.obj[0] || e.end > s.obj[1] || e.end < e.start {
					t.Fatalf("edit [%d,%d) outside the object [%d,%d) in %q", e.start, e.end, s.obj[0], s.obj[1], in)
				}
			}
			out, err := applyEdits(doc.Orig, es)
			if err != nil {
				t.Fatalf("%v for %q", err, in)
			}
			if _, err := parseDoc(cursorSpec, doc.File, out); err != nil {
				t.Fatalf("unbridging %q gave an unreadable file %q: %v", in, out, err)
			}
		}
	})
}
