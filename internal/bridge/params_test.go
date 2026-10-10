package bridge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/rover/internal/bridge/bridgetest"
	"github.com/DreadpiratePickles/rover/internal/framing"
)

// Review HIGH-3: notifications/initialized must reach the remote before the
// first tools/call, whatever the scheduler does. Run with -count=50 -race.
func TestNotificationsKeepOrder(t *testing.T) {
	r := &bridgetest.Remote{}
	tr := remote(t, r, nil, nil)
	s := open(t, tr)
	s.send(initLine)
	s.recvReply()
	s.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	s.send(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"x"}}}`)
	s.recvReply()
	s.c.Close()
	init, call := -1, -1
	for i, b := range r.Bodies() {
		switch {
		case init < 0 && bytes.Contains(b, []byte(`"notifications/initialized"`)):
			init = i
		case call < 0 && bytes.Contains(b, []byte(`"tools/call"`)):
			call = i
		}
	}
	if init < 0 || call < 0 || init > call {
		t.Fatalf("arrival order: initialized at %d, tools/call at %d", init, call)
	}
}

const annotatedTools = `[
 {"name":"sql","inputSchema":{"type":"object","properties":{
   "region":{"type":"string","x-mcp-header":"Region"},
   "n":{"type":"integer","x-mcp-header":"Count"},
   "flag":{"type":"boolean","x-mcp-header":"Flag"},
   "nested":{"type":"object","properties":{"inner":{"type":"string","x-mcp-header":"Inner"}}},
   "note":{"type":"string","x-mcp-header":"Note"},
   "weird":{"type":"string","x-mcp-header":"Weird"},
   "query":{"type":"string"}}}},
 {"name":"bad-empty","inputSchema":{"type":"object","properties":{"a":{"type":"string","x-mcp-header":""}}}},
 {"name":"bad-items","inputSchema":{"type":"object","properties":{"a":{"type":"array","items":{"type":"string","x-mcp-header":"X"}}}}},
 {"name":"bad-dup","inputSchema":{"type":"object","properties":{"a":{"type":"string","x-mcp-header":"Same"},"b":{"type":"string","x-mcp-header":"same"}}}},
 {"name":"bad-number","inputSchema":{"type":"object","properties":{"a":{"type":"number","x-mcp-header":"N"}}}},
 {"name":"bad-oneof","inputSchema":{"type":"object","oneOf":[{"properties":{"a":{"type":"string","x-mcp-header":"A"}}}]}},
 {"name":"bad-chars","inputSchema":{"type":"object","properties":{"a":{"type":"string","x-mcp-header":"Re gion"}}}},
 {"name":"echo","description":"plain","inputSchema":{"type":"object"}}
]`

// MEDIUM-1 (MCP 2026-07-28, Streamable HTTP, "Custom Headers from Tool
// Parameters"): x-mcp-header parameters are mirrored into Mcp-Param-*
// headers with the spec's value encoding, and a tool whose annotations
// break the rules is removed from tools/list, the others kept byte for byte.
func TestParamHeaders(t *testing.T) {
	r := &bridgetest.Remote{ToolsJSON: annotatedTools}
	tr := remote(t, r, nil, nil)
	s := open(t, tr)
	s.send(initLine)
	s.recvReply()
	s.send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	raw, err := framing.ReadLine(s.in, MaxMessage+1)
	if err != nil {
		t.Fatal(err)
	}
	var list map[string]any
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatalf("%v: %s", err, raw)
	}
	tools, _ := list["result"].(map[string]any)["tools"].([]any)
	var names []string
	for _, tool := range tools {
		m, _ := tool.(map[string]any)
		names = append(names, fmt.Sprint(m["name"]))
	}
	if strings.Join(names, ",") != "sql,echo" {
		t.Fatalf("tools after the x-mcp-header check: %v", names)
	}
	for _, orig := range []string{`{"name":"echo","description":"plain","inputSchema":{"type":"object"}}`, `"x-mcp-header":"Region"`} {
		if !strings.Contains(string(raw), orig) {
			t.Errorf("a kept tool was re-encoded: %s", raw)
		}
	}

	s.send(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sql","arguments":{"region":"us-west1","n":42,"flag":true,"nested":{"inner":"Hello, 世界"},"note":null,"weird":"=?base64?literal?=","query":"SELECT 1"}}}`)
	s.recvReply()
	s.send(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{"region":"ignored"}}}`)
	s.recvReply()
	s.send(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"sql","arguments":{"region":"us-east1","n":4.0,"flag":"true","nested":[]}}}`)
	s.recvReply()
	s.c.Close()

	var calls []http.Header
	for _, h := range r.Headers() {
		if h.Get("Mcp-Method") == "tools/call" {
			calls = append(calls, h)
		}
	}
	if len(calls) != 3 {
		t.Fatalf("%d tools/call requests", len(calls))
	}
	want := map[string]string{"Mcp-Param-Region": "us-west1", "Mcp-Param-Count": "42", "Mcp-Param-Flag": "true",
		"Mcp-Param-Inner": "=?base64?SGVsbG8sIOS4lueVjA==?=", "Mcp-Param-Weird": "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=", "Mcp-Param-Note": ""}
	for k, v := range want {
		if got := calls[0][k]; strings.Join(got, "|") != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	for k := range calls[1] {
		if strings.HasPrefix(k, "Mcp-Param-") {
			t.Errorf("echo call carries %s", k)
		}
	}
	if got := calls[2]; got.Get("Mcp-Param-Region") != "us-east1" || got.Get("Mcp-Param-Count") != "4" || got.Get("Mcp-Param-Flag") != "true" || len(got.Values("Mcp-Param-Inner")) != 0 {
		t.Errorf("third call: %v", got)
	}
}

func TestToolHeadersLimits(t *testing.T) {
	deep := strings.Repeat(`{"type":"object","properties":{"a":`, maxSchemaDepth+2) + `{"type":"string","x-mcp-header":"A"}` + strings.Repeat("}}", maxSchemaDepth+2)
	if _, err := toolHeaders([]byte(deep)); err == nil || !strings.Contains(err.Error(), "deeper") {
		t.Fatalf("depth: %v", err)
	}
	var b strings.Builder
	b.WriteString(`{"type":"object","properties":{`)
	for i := 0; i <= maxParamHeaders; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"p%d":{"type":"string","x-mcp-header":"H%d"}`, i, i)
	}
	b.WriteString("}}")
	if _, err := toolHeaders([]byte(b.String())); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("count: %v", err)
	}
	if hs, err := toolHeaders([]byte(`{"type":"object","properties":{"a":{"type":"string","x-mcp-header":"A"},"b":{"type":"object","properties":{"c":{"type":"integer","x-mcp-header":"C"}}}}}`)); err != nil || len(hs) != 2 || hs[1].Name != "C" || strings.Join(hs[1].Path, "/") != "b/c" {
		t.Fatalf("paths: %+v %v", hs, err)
	}
	if _, err := toolHeaders([]byte(`{"type":"object","x-mcp-header":"Root"}`)); err == nil {
		t.Fatal("an annotation on the root schema must be refused")
	}
}

// FuzzToolHeaders: the schema is the remote's input; the walk never panics
// and never yields a header name outside the token syntax.
func FuzzToolHeaders(f *testing.F) {
	f.Add([]byte(annotatedTools))
	f.Add([]byte(`{"type":"object","properties":{"a":{"type":"string","x-mcp-header":"A"}}}`))
	f.Add([]byte(`{"properties":{"a":{"properties":{"b":{"type":"boolean","x-mcp-header":"B"}}}}}`))
	f.Add([]byte(`[1,{"x-mcp-header":"X"}]`))
	f.Add([]byte(`{"x-mcp-header":null}`))
	f.Fuzz(func(t *testing.T, schema []byte) {
		hs, err := toolHeaders(schema)
		if err != nil {
			return
		}
		seen := map[string]bool{}
		for _, h := range hs {
			if h.Name == "" || len(h.Name) > maxParamName || seen[strings.ToLower(h.Name)] {
				t.Fatalf("bad header %+v", h)
			}
			for i := 0; i < len(h.Name); i++ {
				if !isTchar(h.Name[i]) {
					t.Fatalf("header name %q is not a token", h.Name)
				}
			}
			seen[strings.ToLower(h.Name)] = true
		}
		if len(hs) > maxParamHeaders {
			t.Fatalf("%d headers", len(hs))
		}
		if _, _, out, lerr := learnToolsList([]byte(`{"tools":[{"name":"x","inputSchema":` + string(schema) + `}]}`)); lerr == nil && !json.Valid(out) {
			t.Fatalf("learnToolsList produced invalid JSON: %s", out)
		}
	})
}

// MCP-Protocol-Version goes on every request after initialize, including
// the GET stream and the DELETE (2025-11-25 "all subsequent requests").
func TestProtocolVersionOnEveryRequest(t *testing.T) {
	r := &bridgetest.Remote{GET: true}
	tr := remote(t, r, nil, nil)
	s := open(t, tr)
	s.send(initLine)
	s.recvReply()
	s.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	s.send(`{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	s.recvReply()
	s.c.Close()
	hs := r.Headers()
	if hs[0].Get("MCP-Protocol-Version") != "" {
		t.Errorf("initialize itself must not carry a version (2025-11-25 client): %v", hs[0])
	}
	for i, h := range hs[1:] {
		if h.Get("MCP-Protocol-Version") != "2025-11-25" {
			t.Errorf("request %d (%s %s) lacks MCP-Protocol-Version: %v", i+1, h.Get("Mcp-Method"), h.Get("Accept"), h)
		}
	}
	if r.Deleted() != 1 {
		t.Fatal("no DELETE")
	}
}
