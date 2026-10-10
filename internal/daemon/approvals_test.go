package daemon

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DreadpiratePickles/rover/internal/approve"
	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/ipc"
)

// testAuth is a fake OS dialog: it answers ok (changeable with set), or
// waits for a decision per reason when gated.
type testAuth struct {
	mu      sync.Mutex
	ok      bool
	gate    map[string]chan bool // reason substring -> answer
	reasons []string
}

func (a *testAuth) set(ok bool) {
	a.mu.Lock()
	a.ok = ok
	a.mu.Unlock()
}

func (a *testAuth) Authenticate(ctx context.Context, reason string) (bool, string, error) {
	a.mu.Lock()
	a.reasons = append(a.reasons, reason)
	var gate chan bool
	for k, ch := range a.gate {
		if strings.Contains(reason, k) {
			gate = ch
		}
	}
	ok := a.ok
	a.mu.Unlock()
	if gate != nil {
		select {
		case ok = <-gate:
		case <-ctx.Done():
			return false, "test", ctx.Err()
		}
	}
	return ok, "test", nil
}

const approvalPolicy = `
@id("echo-list") permit (principal, action == Action::"list_tools", resource == Server::"echo");
@id("ask-echo") @rover_require("approval")
permit (principal, action == Action::"call_tool", resource == Tool::"echo/echo");
@id("ask-reverse") @rover_require("approval")
permit (principal, action == Action::"call_tool", resource == Tool::"echo/reverse");
`

// approvalServer starts roverd with the approval policy and a Flow.
func approvalServer(t *testing.T, auth approve.Authenticator, clock approve.Clock) (*Server, *syncBuf) {
	t.Helper()
	log := &syncBuf{}
	flow := &approve.Flow{Store: approve.NewMemStore(), Auth: auth, Clock: clock, Timeout: time.Minute}
	s := start(t, Options{Audit: audit.New(log), Policy: engine(t, approvalPolicy), Config: enforce(), Prompter: flow})
	return s, log
}

func dialEcho(t *testing.T, s *Server, initialize string) *ipc.Client {
	t.Helper()
	c, err := ipc.Dial(s.Addr(), hello(1, "echo"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if initialize != "" {
		decide(t, c, "c2s", initialize)
	}
	listOnce(t, c, "100", pinEchoTool, pinReverseTool)
	return c
}

func waitRelease(t *testing.T, rel <-chan ipc.Frame) ipc.Frame {
	t.Helper()
	select {
	case f := <-rel:
		return f
	case <-time.After(10 * time.Second):
		t.Fatal("no release")
	}
	return ipc.Frame{}
}

func isErrorText(t *testing.T, f ipc.Frame) string {
	t.Helper()
	var r struct {
		Result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(f.ResponseRaw, &r); err != nil || !r.Result.IsError || len(r.Result.Content) != 1 {
		t.Fatalf("block body %s: %v", f.ResponseRaw, err)
	}
	return r.Result.Content[0].Text
}

// Acceptance (plan M9): concurrent calls flow while one is held. Two calls
// are held at once; pings and other traffic get verdicts meanwhile; then
// one is approved and the other denied.
func TestHeldCallsDoNotBlockThePipe(t *testing.T) {
	// Arrange
	auth := &testAuth{gate: map[string]chan bool{"echo.echo": make(chan bool), "echo.reverse": make(chan bool)}}
	s, log := approvalServer(t, auth, nil)
	c := dialEcho(t, s, "")

	// Act
	v1, rel1, err1 := c.Decide("c2s", []byte(call("1", "echo")))
	v2, rel2, err2 := c.Decide("c2s", []byte(call("2", "reverse")))
	pings := 0
	for i := 0; i < 20; i++ {
		if v := decide(t, c, "c2s", `{"jsonrpc":"2.0","id":"p`+string(rune('a'+i))+`","method":"ping"}`); v.Action == ipc.ActionForward {
			pings++
		}
	}
	auth.gate["echo.reverse"] <- false
	r2 := waitRelease(t, rel2)
	auth.gate["echo.echo"] <- true
	r1 := waitRelease(t, rel1)

	// Assert
	if err1 != nil || err2 != nil || v1.Action != ipc.ActionHold || v2.Action != ipc.ActionHold {
		t.Fatalf("verdicts %+v %+v (%v %v)", v1, v2, err1, err2)
	}
	if pings != 20 {
		t.Fatalf("only %d of 20 pings flowed while two calls were held", pings)
	}
	if r1.Action != ipc.ActionForward || r2.Action != ipc.ActionBlock {
		t.Fatalf("releases %+v %+v", r1, r2)
	}
	if text := isErrorText(t, r2); !strings.Contains(text, "approval denied") || !strings.Contains(text, "ask-reverse") {
		t.Fatalf("deny text %q", text)
	}
	auth.mu.Lock()
	reasons := strings.Join(auth.reasons, "\n")
	auth.mu.Unlock()
	if !strings.Contains(reasons, "Rover: allow an unknown client to run echo.echo?") {
		t.Fatalf("dialog texts %q", reasons)
	}
	var allowed, denied int
	for _, e := range log.entries(t) {
		if e.Kind == AuditKindApproval && e.Action == ipc.ActionForward {
			allowed++
		}
		if e.Kind == AuditKindApproval && e.Action == ipc.ActionBlock && strings.HasPrefix(e.Reason, "approval denied") {
			denied++
		}
	}
	if allowed != 1 || denied != 1 {
		t.Fatalf("audit allowed=%d denied=%d", allowed, denied)
	}
}

func TestApprovalTimesOutWithInjectedClock(t *testing.T) {
	// Arrange: the dialog never answers.
	clock := &fireClock{fire: make(chan time.Time)}
	auth := &testAuth{gate: map[string]chan bool{"echo.echo": make(chan bool)}}
	s, _ := approvalServer(t, auth, clock)
	c := dialEcho(t, s, "")

	// Act
	v, rel, err := c.Decide("c2s", []byte(call("1", "echo")))
	clock.fire <- time.Now()
	r := waitRelease(t, rel)

	// Assert
	if err != nil || v.Action != ipc.ActionHold || r.Action != ipc.ActionBlock {
		t.Fatalf("verdict %+v release %+v err %v", v, r, err)
	}
	if text := isErrorText(t, r); !strings.Contains(text, "approval timed out") {
		t.Fatalf("timeout text %q", text)
	}
}

type fireClock struct{ fire chan time.Time }

func (c *fireClock) Now() time.Time                       { return time.Now() }
func (c *fireClock) After(time.Duration) <-chan time.Time { return c.fire }

// The elicitation path: a client that advertised elicitation gets Rover's
// elicitation/create through the wrapper (an inject frame); its decline
// denies; its reply is never forwarded; a reply from another session does
// not count.
func TestElicitationDeclineDeniesAndReplyIsSwallowed(t *testing.T) {
	// Arrange
	auth := &testAuth{gate: map[string]chan bool{"echo.echo": make(chan bool)}}
	s, _ := approvalServer(t, auth, nil)
	initialize := `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{"elicitation":{}},"clientInfo":{"name":"claude-code","version":"2"}}}`
	c := dialEcho(t, s, initialize)
	injected := make(chan []byte, 1)
	c.SetInjectHandler(func(raw []byte) { injected <- raw })

	// Act
	v, rel, err := c.Decide("c2s", []byte(call("1", "echo")))
	var raw []byte
	select {
	case raw = <-injected:
	case <-time.After(10 * time.Second):
		t.Fatal("no elicitation was injected")
	}
	var req struct {
		ID     string `json:"id"`
		Method string `json:"method"`
	}
	_ = json.Unmarshal(raw, &req)
	forged := decide(t, c, "s2c", `{"jsonrpc":"2.0","id":"`+req.ID+`","method":"elicitation/create","params":{"message":"approve?"}}`)
	reply := decide(t, c, "c2s", `{"jsonrpc":"2.0","id":"`+req.ID+`","result":{"action":"decline"}}`)
	r := waitRelease(t, rel)

	// Assert
	if err != nil || v.Action != ipc.ActionHold || req.Method != "elicitation/create" || !strings.HasPrefix(req.ID, "rover-") {
		t.Fatalf("verdict %+v err %v injected %s", v, err, raw)
	}
	if reply.Action != ipc.ActionBlock || reply.Reason != ReasonRoverReply {
		t.Fatalf("the client's reply must never reach the server: %+v", reply)
	}
	if forged.Action != ipc.ActionBlock || forged.Reason != ReasonRoverIDTaken {
		t.Fatalf("a server request with a rover- id must be blocked: %+v", forged)
	}
	if r.Action != ipc.ActionBlock || !strings.Contains(isErrorText(t, r), "approval denied") {
		t.Fatalf("decline must deny: %+v", r)
	}
	if !strings.Contains(string(raw), "claude-code wants to run echo.echo") {
		t.Fatalf("elicitation text: %s", raw)
	}
}

func TestHoldWithoutPrompterBlocks(t *testing.T) {
	s := start(t, Options{Audit: audit.New(&syncBuf{}), Policy: engine(t, approvalPolicy), Config: enforce()})
	c := dialEcho(t, s, "")
	v := decide(t, c, "c2s", call("1", "echo"))
	if v.Action != ipc.ActionBlock || v.Reason != ReasonApprovalUnavailable {
		t.Fatalf("%+v", v)
	}
}

func TestElicitationCapabilityIsReadStrictly(t *testing.T) {
	for params, want := range map[string]bool{
		`{"capabilities":{"elicitation":{}}}`:                           true,
		`{"capabilities":{}}`:                                           false,
		`{"capabilities":{"elicitation":true}}`:                         false,
		`{"capabilities":{"elicitation":{},"elicitation":{}}}`:          false,
		`{"capabilities":{"Elicitation":{}}}`:                           false,
		`{"capabilities":{"elicitation":{}},"capabilities":{}}`:         false,
		`{"clientInfo":{"name":"x"},"capabilities":{"elicitation":{}}}`: true,
	} {
		if got := elicitationCapable([]byte(params)); got != want {
			t.Errorf("%s: %v", params, got)
		}
	}
}
