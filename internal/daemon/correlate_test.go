package daemon

import (
	"bytes"
	"testing"
	"time"

	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/ipc"
)

// These are A1's proxy.observe tests, moved here with the logic. They call
// the decision path directly (no socket) so the clock is fully controlled.

func newConnState(d *Daemon) *connState {
	s := d.join(1000)
	return &connState{hello: ipc.Hello{ServerName: "fs"}, sess: s, pending: map[string]pending{}}
}

func decideRaw(t *testing.T, d *Daemon, cs *connState, dir, raw string) ipc.Verdict {
	t.Helper()
	v, keep, err := d.onDecide(cs, &ipc.Decide{SessionID: cs.sess.id, Seq: cs.lastSeq + 1, Dir: dir, Raw: []byte(raw)})
	if err != nil || !keep {
		t.Fatalf("decide: keep=%v err=%v", keep, err)
	}
	return v
}

func TestCorrelatesRequestAndResponse(t *testing.T) {
	var buf syncBuf
	clock := time.Unix(0, 0)
	d, err := New(Options{Audit: audit.New(&buf), Now: func() time.Time { return clock }, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	cs := newConnState(d)

	decideRaw(t, d, cs, "c2s", `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/hosts"}}}`)
	clock = clock.Add(42 * time.Millisecond)
	decideRaw(t, d, cs, "s2c", `{"jsonrpc":"2.0","id":7,"result":{"content":[],"isError":true}}`)

	es := buf.entries(t)
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
	if len(cs.pending) != 0 {
		t.Fatal("answered request still pending")
	}
}

// An error response is correlated too, and is not a tool error.
func TestCorrelatesErrorResponse(t *testing.T) {
	var buf syncBuf
	d, _ := New(Options{Audit: audit.New(&buf), Logf: func(string, ...any) {}})
	cs := newConnState(d)
	decideRaw(t, d, cs, "c2s", `{"jsonrpc":"2.0","id":"a","method":"tools/list"}`)
	decideRaw(t, d, cs, "s2c", `{"jsonrpc":"2.0","id":"a","error":{"code":-32601,"message":"nope"}}`)
	r := buf.entries(t)[1]
	if r.Kind != "error" || r.ReplyTo != "tools/list" || r.ToolError || r.LatencyMS == nil {
		t.Fatalf("%+v", r)
	}
}

// An id the SERVER used for its own request must not be matched with a
// client request that happens to share the same id.
func TestIDsAreScopedByDirection(t *testing.T) {
	var buf syncBuf
	d, _ := New(Options{Audit: audit.New(&buf), Logf: func(string, ...any) {}})
	cs := newConnState(d)
	decideRaw(t, d, cs, "c2s", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}`)
	// A c2s response with id 1 would be the client answering a SERVER request
	// with id 1; there is no such request.
	decideRaw(t, d, cs, "c2s", `{"jsonrpc":"2.0","id":1,"result":{}}`)
	es := buf.entries(t)
	if es[1].ReplyTo != "" {
		t.Fatalf("wrongly correlated across directions: %+v", es[1])
	}
	// The server's own request (s2c) is answered by the client (c2s).
	decideRaw(t, d, cs, "s2c", `{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage"}`)
	decideRaw(t, d, cs, "c2s", `{"jsonrpc":"2.0","id":1,"result":{}}`)
	if r := buf.entries(t)[3]; r.ReplyTo != "sampling/createMessage" {
		t.Fatalf("server request not correlated: %+v", r)
	}
}

// Requests that are never answered cannot grow the map without bound.
func TestPendingIsBounded(t *testing.T) {
	d, _ := New(Options{Audit: audit.New(&bytes.Buffer{}), Logf: func(string, ...any) {}})
	cs := newConnState(d)
	for i := 0; i < maxPending+100; i++ {
		raw := []byte(`{"jsonrpc":"2.0","id":` + itoa(i) + `,"method":"ping"}`)
		if _, _, err := d.onDecide(cs, &ipc.Decide{SessionID: cs.sess.id, Seq: cs.lastSeq + 1, Dir: "c2s", Raw: raw}); err != nil {
			t.Fatal(err)
		}
	}
	if len(cs.pending) != maxPending {
		t.Fatalf("pending = %d, want %d", len(cs.pending), maxPending)
	}
}

// Valid JSON that is not JSON-RPC 2.0 is logged as kind "invalid" (and,
// being valid JSON, keeps its body when bodies are on).
func TestNonJSONRPCMessageLogged(t *testing.T) {
	var buf syncBuf
	d, _ := New(Options{Audit: audit.New(&buf), LogBodies: true, Logf: func(string, ...any) {}})
	cs := newConnState(d)
	decideRaw(t, d, cs, "s2c", `{"jsonrpc":"1.0","id":1}`)
	if e := buf.entries(t)[0]; e.Kind != "invalid" || e.Body == nil {
		t.Fatalf("%+v", e)
	}
}
