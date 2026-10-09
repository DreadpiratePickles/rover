package jsonrpc

import (
	"errors"
	"strings"
	"testing"
)

func TestObjectKeepsExactKeysAndOffsets(t *testing.T) {
	// Arrange
	raw := []byte(`{"a": 1 ,"b":{"c":[1,2]}, "d" :"x"}`)

	// Act
	fs, err := Object(raw)

	// Assert
	if err != nil {
		t.Fatalf("Object: %v", err)
	}
	want := []struct{ k, v string }{{"a", "1"}, {"b", `{"c":[1,2]}`}, {"d", `"x"`}}
	if len(fs) != len(want) {
		t.Fatalf("got %d fields, want %d", len(fs), len(want))
	}
	for i, w := range want {
		f := fs[i]
		if f.Key != w.k || string(f.Value) != w.v || string(raw[f.Start:f.End]) != w.v {
			t.Errorf("field %d = %q %s [%d:%d], want %q %s", i, f.Key, f.Value, f.Start, f.End, w.k, w.v)
		}
	}
	if v, ok := fs.Get("b"); !ok || string(v) != `{"c":[1,2]}` {
		t.Errorf("Get(b) = %s, %v", v, ok)
	}
	if _, ok := fs.Get("B"); ok {
		t.Error("Get must match keys exactly")
	}
}

func TestObjectRejectsAmbiguousOrBadInput(t *testing.T) {
	cases := []struct {
		name, in string
		want     error
	}{
		{"duplicate", `{"a":1,"a":2}`, ErrDuplicateKey},
		{"escaped duplicate", `{"a":1,"a":2}`, ErrDuplicateKey},
		{"case collision", `{"name":"echo","Name":"read_file"}`, ErrDuplicateKey},
		{"upper case collision", `{"METHOD":1,"method":2}`, ErrDuplicateKey},
		{"kelvin sign folds to k", "{\"k\":1,\"K\":2}", ErrDuplicateKey},
		{"long s folds to s", "{\"s\":1,\"ſ\":2}", ErrDuplicateKey},
		{"array", `[1]`, ErrNotObject},
		{"string", `"x"`, ErrNotObject},
		{"empty", ``, ErrInvalidJSON},
		{"truncated", `{"a":`, ErrInvalidJSON},
		{"unterminated", `{"a":1`, ErrInvalidJSON},
		{"trailing data", `{"a":1}x`, ErrInvalidJSON},
		{"second object", `{"a":1}{"b":2}`, ErrInvalidJSON},
		{"bad value", `{"a":nope}`, ErrInvalidJSON},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Object([]byte(c.in))
			if !errors.Is(err, c.want) {
				t.Fatalf("Object(%s) err = %v, want %v", c.in, err, c.want)
			}
		})
	}
}

// TestParseRejectsKeyDifferentials: encoding/json matches struct fields
// case-insensitively, last one wins. Cedar and most servers match exactly.
// Each of these shapes made the gateway judge one message while the server
// (or client) acted on another, so each must be KindInvalid.
func TestParseRejectsKeyDifferentials(t *testing.T) {
	cases := []struct {
		name, in, invalid string
	}{
		{"Name beside name", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","Name":"read_file","arguments":{}}}`, "params"},
		{"Method beside method", `{"jsonrpc":"2.0","id":1,"method":"tools/call","Method":"ping","params":{"name":"read_file"}}`, "duplicate key"},
		{"Method alone", `{"jsonrpc":"2.0","id":1,"Method":"tools/call","params":{"name":"read_file"}}`, `unknown member "Method"`},
		{"Result beside result", `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_file"}]},"Result":{"tools":[]}}`, "duplicate key"},
		{"duplicate params key", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","name":"read_file"}}`, "params"},
		{"Arguments beside arguments", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{},"Arguments":{}}}`, "params"},
		{"unknown member", `{"jsonrpc":"2.0","id":1,"method":"ping","extra":1}`, `unknown member "extra"`},
		{"duplicate id", `{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}`, "duplicate key"},
		{"object id", `{"jsonrpc":"2.0","id":{},"method":"ping"}`, "id"},
		{"non-string method", `{"jsonrpc":"2.0","id":1,"method":5}`, "method"},
		{"null error", `{"jsonrpc":"2.0","id":1,"error":null}`, "error"},
		{"error with Code collision", `{"jsonrpc":"2.0","id":1,"error":{"code":1,"Code":2,"message":"m"}}`, "error"},
		{"trailing data", `{"jsonrpc":"2.0","id":1,"method":"ping"} {}`, "invalid JSON"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := Parse([]byte(c.in))
			if m.Kind != KindInvalid {
				t.Fatalf("kind = %s (method %q tool %q), want invalid", m.Kind, m.Method, m.ToolName())
			}
			if !strings.Contains(m.Invalid, c.invalid) {
				t.Fatalf("Invalid = %q, want it to mention %q", m.Invalid, c.invalid)
			}
			if m.ToolName() != "" {
				t.Fatalf("ToolName = %q on an invalid message", m.ToolName())
			}
		})
	}
}

func TestParseKeepsIDOfInvalidRequest(t *testing.T) {
	m := Parse([]byte(`{"jsonrpc":"2.0","id":7,"method":"tools/call","Method":"ping"}`))
	if m.Kind != KindInvalid || string(m.ID) != "7" || m.Method != "tools/call" {
		t.Fatalf("got kind %s id %s method %q", m.Kind, m.ID, m.Method)
	}
	if !m.InvalidRequest() {
		t.Fatal("an invalid message with an id and a method is an invalid request")
	}
	r := Parse([]byte(`{"jsonrpc":"2.0","id":7,"result":{},"Result":{}}`))
	if r.InvalidRequest() {
		t.Fatal("an invalid response is not an invalid request")
	}
}

func TestToolArguments(t *testing.T) {
	m := Parse([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`))
	if got := string(m.ToolArguments()); got != `{"text":"hi"}` {
		t.Fatalf("ToolArguments = %s", got)
	}
	if got := Parse([]byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)).ToolArguments(); got != nil {
		t.Fatalf("ToolArguments of ping = %s", got)
	}
}

// clientInfo feeds the Cedar principal, so it is read as strictly as the
// envelope: exact "name"/"version" strings, no colliding keys.
func TestInitializeClientInfoIsStrict(t *testing.T) {
	ok := Parse([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"a","version":"1"}}}`))
	if n, v := ok.ClientInfo(); ok.Kind != KindRequest || n != "a" || v != "1" {
		t.Fatalf("well-formed: kind %s name %q version %q", ok.Kind, n, v)
	}
	for _, in := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"a","Name":"b"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"a","name":"b"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":1}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"a","version":null}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":"a"}}`,
	} {
		m := Parse([]byte(in))
		if n, _ := m.ClientInfo(); m.Kind != KindInvalid || !strings.Contains(m.Invalid, "clientInfo") || n != "" {
			t.Errorf("%s: kind %s invalid %q name %q", in, m.Kind, m.Invalid, n)
		}
	}
}
