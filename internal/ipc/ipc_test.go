package ipc

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
)

func sampleMessages() []Message {
	return []Message{
		{Type: TypeHello, Hello: &Hello{Version: 1, WrapperPID: 4242, ClientPID: 4200, ServerName: "echo", ServerCmdSHA256: strings.Repeat("ab", 32), Transport: "stdio"}},
		{Type: TypeWelcome, Welcome: &Welcome{SessionID: "a1b2c3d4e5f60718293a4b5c"}},
		{Type: TypeDecide, Decide: &Decide{SessionID: "a1b2c3d4e5f60718293a4b5c", Seq: 1, Dir: DirC2S, Raw: json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)}},
		{Type: TypeVerdict, Verdict: &Verdict{Seq: 1, Action: ActionForward, RuleIDs: []string{}}},
		{Type: TypeVerdict, Verdict: &Verdict{Seq: 2, Action: ActionBlock, ReplacementRaw: json.RawMessage(`{"jsonrpc":"2.0","id":2,"error":{"code":-32001,"message":"no"}}`), Reason: "audit_unavailable", RuleIDs: []string{"r1", "r2"}}},
		{Type: TypeRelease, Release: &Release{Seq: 7, Action: ActionBlock, ReplacementRaw: json.RawMessage(`{"jsonrpc":"2.0","id":3,"result":{}}`)}},
		{Type: TypeBye, Bye: &Bye{SessionID: "a1b2c3d4e5f60718293a4b5c"}},
	}
}

func TestRoundTripEveryType(t *testing.T) {
	for _, m := range sampleMessages() {
		t.Run(m.Type, func(t *testing.T) {
			line, err := Encode(m)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasSuffix(line, []byte("\n")) || bytes.Count(line, []byte("\n")) != 1 {
				t.Fatalf("not exactly one line: %q", line)
			}
			if !bytes.HasPrefix(line, []byte(`{"type":"`+m.Type+`",`)) {
				t.Fatalf("line does not lead with its type: %s", line)
			}
			got, err := Decode(line)
			if err != nil {
				t.Fatalf("decode %s: %v", line, err)
			}
			if !reflect.DeepEqual(got, m) {
				t.Fatalf("round trip changed the message:\n got %+v\nwant %+v", got, m)
			}
		})
	}
}

// roverd must inspect exactly the bytes the wrapper will forward, so the raw
// MCP message is not compacted or HTML-escaped on the way.
func TestDecideRawIsSplicedVerbatim(t *testing.T) {
	raw := `{ "jsonrpc" : "2.0", "id":1, "method":"tools/call", "params":{"q":"<a&b>", "n":1.50e+3, "s":"café"} }`
	line, err := Encode(Message{Type: TypeDecide, Decide: &Decide{SessionID: "s", Seq: 9, Dir: DirS2C, Raw: json.RawMessage(raw)}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"type":"decide","decide":{"session_id":"s","seq":9,"dir":"s2c","raw":` + raw + "}}\n"
	if string(line) != want {
		t.Fatalf("got  %s\nwant %s", line, want)
	}
	m, err := Decode(line)
	if err != nil {
		t.Fatal(err)
	}
	if string(m.Decide.Raw) != raw {
		t.Fatalf("decoded raw changed: %s", m.Decide.Raw)
	}
}

func TestEncodeRefusesBadDecideRaw(t *testing.T) {
	for name, raw := range map[string]string{
		"empty":   "",
		"invalid": `{"jsonrpc":`,
		"newline": "{\"a\":\n1}",
		"two":     `{} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Encode(Message{Type: TypeDecide, Decide: &Decide{SessionID: "s", Seq: 1, Dir: DirC2S, Raw: json.RawMessage(raw)}})
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("want ErrProtocol, got %v", err)
			}
		})
	}
}

func TestVerdictRuleIDsNeverNull(t *testing.T) {
	line, err := Encode(Message{Type: TypeVerdict, Verdict: &Verdict{Seq: 1, Action: ActionForward}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(line, []byte(`"rule_ids":[]`)) {
		t.Fatalf("rule_ids should be [] : %s", line)
	}
}

func TestDecodeRejects(t *testing.T) {
	cases := map[string]string{
		"unknown type":         `{"type":"shutdown","shutdown":{}}`,
		"missing type":         `{"hello":{"version":1}}`,
		"type without payload": `{"type":"hello"}`,
		"null payload":         `{"type":"hello","hello":null}`,
		"wrong payload":        `{"type":"hello","bye":{"session_id":"x"}}`,
		"two payloads":         `{"type":"bye","bye":{"session_id":"x"},"welcome":{"session_id":"x"}}`,
		"unknown field":        `{"type":"bye","bye":{"session_id":"x","admin":true}}`,
		"unknown top field":    `{"type":"bye","bye":{"session_id":"x"},"extra":1}`,
		"trailing data":        `{"type":"bye","bye":{"session_id":"x"}} {"type":"bye","bye":{"session_id":"y"}}`,
		"not json":             `hello roverd`,
		"empty":                ``,
		"array":                `[]`,
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode([]byte(line)); !errors.Is(err, ErrProtocol) {
				t.Fatalf("want ErrProtocol, got %v", err)
			}
		})
	}
	if _, err := Decode([]byte(`{"type":"nope","nope":{}}`)); !errors.Is(err, ErrUnknownType) {
		t.Fatalf("want ErrUnknownType, got %v", err)
	}
}

func TestEncodeRefusesMismatchedEnvelope(t *testing.T) {
	for _, m := range []Message{
		{Type: "nope"},
		{Type: TypeHello},
		{Type: TypeHello, Bye: &Bye{}},
		{Type: TypeBye, Bye: &Bye{}, Hello: &Hello{}},
	} {
		if _, err := Encode(m); !errors.Is(err, ErrProtocol) {
			t.Fatalf("%+v: want ErrProtocol, got %v", m, err)
		}
	}
}

func TestDecodeRejectsOversizedLine(t *testing.T) {
	big := make([]byte, MaxLine+1)
	if _, err := Decode(big); !errors.Is(err, ErrLineTooLarge) {
		t.Fatalf("want ErrLineTooLarge, got %v", err)
	}
}

// Over a connection the limit is enforced while reading, so an endless line
// is refused without being buffered whole.
func TestConnRejectsOversizedLine(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	go func() {
		defer func() { _ = b.Close() }()
		chunk := bytes.Repeat([]byte("A"), 1<<20)
		for i := 0; i < MaxLine/len(chunk)+2; i++ {
			if _, err := b.Write(chunk); err != nil {
				return
			}
		}
	}()
	_, err := NewConn(a).Read()
	if !errors.Is(err, ErrLineTooLarge) {
		t.Fatalf("want ErrLineTooLarge, got %v", err)
	}
}

func TestConnReadEOFAndTruncation(t *testing.T) {
	a, b := net.Pipe()
	go func() { _ = b.Close() }()
	if _, err := NewConn(a).Read(); err != io.EOF {
		t.Fatalf("clean close: want io.EOF, got %v", err)
	}

	a, b = net.Pipe()
	go func() {
		_, _ = b.Write([]byte(`{"type":"bye","bye":{"session_id":"x"}}`)) // no "\n"
		_ = b.Close()
	}()
	if _, err := NewConn(a).Read(); !errors.Is(err, ErrProtocol) {
		t.Fatalf("cut-off line: want ErrProtocol, got %v", err)
	}
}

func TestConnRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	ca, cb := NewConn(a), NewConn(b)
	defer func() { _ = ca.Close(); _ = cb.Close() }()
	msgs := sampleMessages()
	go func() {
		for _, m := range msgs {
			if err := ca.Write(m); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for _, want := range msgs {
		got, err := cb.Read()
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v want %+v", got, want)
		}
	}
}

// FuzzDecode feeds arbitrary lines to the decoder. It must never panic, and
// anything it accepts must survive a re-encode/decode with the same type.
func FuzzDecode(f *testing.F) {
	for _, m := range sampleMessages() {
		line, err := Encode(m)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(line)
	}
	f.Add([]byte(`{"type":"hello","hello":{"version":1,"x":[[[[[[[[[[]]]]]]]]]]}}`))
	f.Add([]byte(`{"type":"decide","decide":{"raw":"\ud800"}}`))
	f.Fuzz(func(t *testing.T, line []byte) {
		m, err := Decode(line)
		if err != nil {
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("decode error does not wrap ErrProtocol: %v", err)
			}
			return
		}
		out, err := Encode(m)
		if err != nil {
			return // e.g. a decide raw with a newline inside: refused on the way out
		}
		m2, err := Decode(out)
		if err != nil {
			t.Fatalf("re-decode of %q failed: %v", out, err)
		}
		if m2.Type != m.Type {
			t.Fatalf("type changed: %q -> %q", m.Type, m2.Type)
		}
	})
}
