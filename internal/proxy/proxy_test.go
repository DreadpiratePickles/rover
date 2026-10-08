package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"rover/internal/audit"
)

func entries(t *testing.T, buf *bytes.Buffer) []audit.Entry {
	t.Helper()
	var out []audit.Entry
	sc := bufio.NewScanner(buf)
	for sc.Scan() {
		var e audit.Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("bad log line %q: %v", sc.Text(), err)
		}
		out = append(out, e)
	}
	return out
}

// The gateway must forward exactly the bytes it received.
func TestPumpForwardsBytesExactly(t *testing.T) {
	// Odd-but-valid JSON: spacing, key order, unicode escape, big number.
	in := `{"id":1, "jsonrpc":"2.0","method":"tools/call","params":{"name":"echo","arguments":{"text":"café","n":12345678901234567890}}}` + "\n"
	var logBuf, out bytes.Buffer
	s := NewSession("t", audit.New(&logBuf))
	if err := s.Pump(strings.NewReader(in), &out, ClientToServer); err != nil {
		t.Fatal(err)
	}
	if out.String() != in {
		t.Fatalf("forwarded bytes changed:\n got %q\nwant %q", out.String(), in)
	}
}

func TestCorrelatesRequestAndResponse(t *testing.T) {
	var logBuf bytes.Buffer
	s := NewSession("t", audit.New(&logBuf))
	clock := time.Unix(0, 0)
	s.now = func() time.Time { return clock }

	req := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/hosts"}}}` + "\n"
	resp := `{"jsonrpc":"2.0","id":7,"result":{"content":[],"isError":true}}` + "\n"

	if err := s.Pump(strings.NewReader(req), io.Discard, ClientToServer); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(42 * time.Millisecond)
	if err := s.Pump(strings.NewReader(resp), io.Discard, ServerToClient); err != nil {
		t.Fatal(err)
	}

	es := entries(t, &logBuf)
	if len(es) != 2 {
		t.Fatalf("want 2 entries, got %d", len(es))
	}
	if es[0].Tool != "read_file" || es[0].Kind != "request" {
		t.Fatalf("request entry wrong: %+v", es[0])
	}
	r := es[1]
	if r.ReplyTo != "tools/call" || r.Tool != "read_file" || !r.ToolError {
		t.Fatalf("response not correlated: %+v", r)
	}
	if r.LatencyMS == nil || *r.LatencyMS != 42 {
		t.Fatalf("latency = %v, want 42", r.LatencyMS)
	}
}

// An id the SERVER used for its own request must not be matched with a
// client request that happens to share the same id.
func TestIDsAreScopedByDirection(t *testing.T) {
	var logBuf bytes.Buffer
	s := NewSession("t", audit.New(&logBuf))
	_ = s.Pump(strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}`+"\n"), io.Discard, ClientToServer)
	// Server answers with id 1 travelling c2s? That would be a client's reply to a server request - no such request exists.
	_ = s.Pump(strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":{}}`+"\n"), io.Discard, ClientToServer)
	es := entries(t, &logBuf)
	if es[1].ReplyTo != "" {
		t.Fatalf("wrongly correlated across directions: %+v", es[1])
	}
}

func TestRejectsOversizedMessage(t *testing.T) {
	var logBuf bytes.Buffer
	s := NewSession("t", audit.New(&logBuf))
	s.MaxMessage = 1024
	big := `{"jsonrpc":"2.0","id":1,"result":{"x":"` + strings.Repeat("A", 5000) + `"}}` + "\n"
	err := s.Pump(strings.NewReader(big), io.Discard, ServerToClient)
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("want ErrMessageTooLarge, got %v", err)
	}
}

// Messages bigger than bufio.Scanner's 64 KiB default must still pass.
func TestLargeMessageUnderLimitPasses(t *testing.T) {
	var logBuf, out bytes.Buffer
	s := NewSession("t", audit.New(&logBuf))
	big := `{"jsonrpc":"2.0","id":1,"result":{"x":"` + strings.Repeat("A", 200_000) + `"}}` + "\n"
	if err := s.Pump(strings.NewReader(big), &out, ServerToClient); err != nil {
		t.Fatal(err)
	}
	if out.Len() != len(big) {
		t.Fatalf("forwarded %d bytes, want %d", out.Len(), len(big))
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

// If the audit log can't be written, nothing is forwarded (fail closed).
func TestFailsClosedWhenAuditFails(t *testing.T) {
	var out bytes.Buffer
	s := NewSession("t", audit.New(failWriter{}))
	err := s.Pump(strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n"), &out, ClientToServer)
	if err == nil || out.Len() != 0 {
		t.Fatalf("expected failure and nothing forwarded; err=%v forwarded=%q", err, out.String())
	}
}
