package jsonrpc

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		name, in string
		kind     Kind
		method   string
		tool     string
	}{
		{"request", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}`, KindRequest, "tools/call", "echo"},
		{"string id", `{"jsonrpc":"2.0","id":"abc","method":"ping"}`, KindRequest, "ping", ""},
		{"notification", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, KindNotification, "notifications/initialized", ""},
		{"null id is a notification", `{"jsonrpc":"2.0","id":null,"method":"x"}`, KindNotification, "x", ""},
		{"result", `{"jsonrpc":"2.0","id":1,"result":{}}`, KindResult, "", ""},
		{"error", `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"nope"}}`, KindError, "", ""},
		{"error with null id", `{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse"}}`, KindError, "", ""},
		// Ambiguous / hostile shapes must never classify as something harmless.
		{"wrong version", `{"jsonrpc":"1.0","id":1,"method":"x"}`, KindInvalid, "", ""},
		{"method and result", `{"jsonrpc":"2.0","id":1,"method":"x","result":{}}`, KindInvalid, "", ""},
		{"result and error", `{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"m"}}`, KindInvalid, "", ""},
		{"not json", `hello`, KindInvalid, "", ""},
		{"batch array", `[{"jsonrpc":"2.0","id":1,"method":"x"}]`, KindInvalid, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := Parse([]byte(c.in))
			if m.Kind != c.kind {
				t.Fatalf("kind = %s, want %s", m.Kind, c.kind)
			}
			if m.Method != c.method {
				t.Fatalf("method = %q, want %q", m.Method, c.method)
			}
			if got := m.ToolName(); got != c.tool {
				t.Fatalf("tool = %q, want %q", got, c.tool)
			}
		})
	}
}

// FuzzParse: the parser sees attacker-controlled bytes, so it must never panic.
// Run with: go test ./internal/jsonrpc -fuzz=FuzzParse -fuzztime=30s
func FuzzParse(f *testing.F) {
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	f.Fuzz(func(_ *testing.T, b []byte) {
		m := Parse(b)
		_ = m.ToolName()
	})
}
