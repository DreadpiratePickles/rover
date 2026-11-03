package daemon

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/rover/internal/approve"
	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/ipc"
)

// Review M9 MEDIUM-2: at most MaxHoldsPerSession pending approvals per
// session; the next is denied at once.
func TestTooManyPendingApprovalsAreDenied(t *testing.T) {
	// Arrange
	auth := &testAuth{gate: map[string]chan bool{"echo.echo": make(chan bool)}}
	s, _ := approvalServer(t, auth, nil)
	c := dialEcho(t, s, "")
	var rels []<-chan ipc.Frame

	// Act
	for i := 1; i <= DefaultMaxHoldsPerSession+1; i++ {
		v, rel, err := c.Decide("c2s", []byte(call(itoa(i), "echo")))
		if err != nil || v.Action != ipc.ActionHold {
			t.Fatalf("call %d: %+v %v", i, v, err)
		}
		rels = append(rels, rel)
	}
	extra := waitRelease(t, rels[DefaultMaxHoldsPerSession])

	// Assert
	if extra.Action != ipc.ActionBlock || !strings.Contains(extra.Reason, ReasonTooManyApprovals) {
		t.Fatalf("hold %d: %+v", DefaultMaxHoldsPerSession+1, extra)
	}
	select {
	case r := <-rels[0]:
		t.Fatalf("the first holds must still be pending: %+v", r)
	default:
	}
}

func TestDaemonWideHoldCap(t *testing.T) {
	auth := &testAuth{gate: map[string]chan bool{"echo.echo": make(chan bool)}}
	flow := &approve.Flow{Store: approve.NewMemStore(), Auth: auth, Timeout: time.Minute}
	s := start(t, Options{Audit: audit.New(&syncBuf{}), Policy: engine(t, approvalPolicy), Config: enforce(), Prompter: flow, MaxHolds: 2})
	c := dialEcho(t, s, "")
	_, _, _ = c.Decide("c2s", []byte(call("1", "echo")))
	_, _, _ = c.Decide("c2s", []byte(call("2", "echo")))
	_, rel, _ := c.Decide("c2s", []byte(call("3", "echo")))
	if r := waitRelease(t, rel); r.Action != ipc.ActionBlock || r.Reason != ReasonTooManyApprovals {
		t.Fatalf("%+v", r)
	}
}

// Review M9 MEDIUM-3: the wrapper disconnects mid-hold: the approval is
// cancelled (the dialog closes), recorded wrapper_gone, audited block.
func TestWrapperGoneCancelsTheHold(t *testing.T) {
	// Arrange
	auth := &testAuth{gate: map[string]chan bool{"echo.echo": make(chan bool)}}
	log := &syncBuf{}
	store := approve.NewMemStore()
	flow := &approve.Flow{Store: store, Auth: auth, Timeout: time.Minute}
	s := start(t, Options{Audit: audit.New(log), Policy: engine(t, approvalPolicy), Config: enforce(), Prompter: flow})
	c := dialEcho(t, s, "")
	v, _, _ := c.Decide("c2s", []byte(call("1", "echo")))

	// Act
	_ = c.Close()

	// Assert
	var found audit.Entry
	for i := 0; i < 500 && found.Kind == ""; i++ {
		for _, e := range log.entries(t) {
			if e.Kind == AuditKindApproval {
				found = e
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if v.Action != ipc.ActionHold || found.Action != ipc.ActionBlock || !strings.Contains(found.Reason, approve.StateWrapperGone) {
		t.Fatalf("verdict %+v, audit %+v", v, found)
	}
	id := regexp.MustCompile(`approval ([0-9a-f-]{36}), wrapper_gone`).FindStringSubmatch(found.Reason)[1]
	if rec, ok, _ := store.Get(id); !ok || rec.State != approve.StateWrapperGone {
		t.Fatalf("record %q: %+v", id, rec)
	}
}

// Review M9 LOW: a cancelled hold is dropped with no reply to the client.
func TestCancelledHoldIsDroppedWithoutReply(t *testing.T) {
	auth := &testAuth{gate: map[string]chan bool{"echo.echo": make(chan bool)}}
	s, _ := approvalServer(t, auth, nil)
	c := dialEcho(t, s, "")
	_, rel, _ := c.Decide("c2s", []byte(call("7", "echo")))
	decide(t, c, "c2s", `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7}}`)
	r := waitRelease(t, rel)
	if r.Action != ipc.ActionBlock || !r.Drop || len(r.ResponseRaw) != 0 {
		t.Fatalf("%+v", r)
	}
}

// Review M9 LOW: once decided, Rover cancels its own elicitation.
func TestDecidedElicitationIsCancelledAtTheClient(t *testing.T) {
	auth := &testAuth{gate: map[string]chan bool{"echo.echo": make(chan bool)}}
	s, _ := approvalServer(t, auth, nil)
	c := dialEcho(t, s, `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"capabilities":{"elicitation":{}},"clientInfo":{"name":"x","version":"1"}}}`)
	injected := make(chan []byte, 4)
	c.SetInjectHandler(func(raw []byte) { injected <- raw })
	_, rel, _ := c.Decide("c2s", []byte(call("1", "echo")))
	first := <-injected
	auth.gate["echo.echo"] <- true
	waitRelease(t, rel)
	var second []byte
	select {
	case second = <-injected:
	case <-time.After(5 * time.Second):
		t.Fatal("no notifications/cancelled for Rover's elicitation")
	}
	var req, note struct {
		ID     string `json:"id"`
		Method string `json:"method"`
		Params struct {
			RequestID string `json:"requestId"`
		} `json:"params"`
	}
	_ = json.Unmarshal(first, &req)
	_ = json.Unmarshal(second, &note)
	if note.Method != "notifications/cancelled" || note.Params.RequestID != req.ID {
		t.Fatalf("first %s\nsecond %s", first, second)
	}
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

// Review M9 MEDIUM-5: pending approvals can be listed (same uid only, like
// every admin op), with the details page URL.
func TestApprovalsListShowsPendingHolds(t *testing.T) {
	auth := &testAuth{gate: map[string]chan bool{"echo.echo": make(chan bool)}}
	flow := &approve.Flow{Store: approve.NewMemStore(), Auth: auth, Timeout: time.Minute, Pages: fixedPages{}}
	s := start(t, Options{Audit: audit.New(&syncBuf{}), Policy: engine(t, approvalPolicy), Config: enforce(), Prompter: flow, PendingApprovals: flow.Pending})
	c := dialEcho(t, s, "")
	_, rel, _ := c.Decide("c2s", []byte(call("1", "echo")))
	var list []approve.PendingApproval
	for i := 0; i < 200 && len(list) == 0; i++ {
		res, err := ipc.Admin(s.Addr(), ipc.Frame{Op: ipc.OpApprovalsList})
		if err != nil {
			t.Fatal(err)
		}
		_ = json.Unmarshal(res.Result, &list)
		time.Sleep(10 * time.Millisecond)
	}
	if len(list) != 1 || list[0].Server != "echo" || list[0].Tool != "echo" || !strings.HasPrefix(list[0].URL, "http://127.0.0.1:1/approval/"+list[0].ID) {
		t.Fatalf("%+v", list)
	}
	auth.gate["echo.echo"] <- false
	waitRelease(t, rel)
	res, _ := ipc.Admin(s.Addr(), ipc.Frame{Op: ipc.OpApprovalsList})
	if string(res.Result) != "[]" {
		t.Fatalf("decided approvals must leave the list: %s", res.Result)
	}
}

type fixedPages struct{}

func (fixedPages) Register(r approve.Request) (string, error) {
	return "http://127.0.0.1:1/approval/" + r.ID + "?t=x", nil
}

// Review M9 MEDIUM-6: tamper_resolve and tamper_forget change what roverd
// watches, so roverd shows the dialog first; under deny nothing changes.
func TestTamperAdminNeedsTheDialog(t *testing.T) {
	r := newTamperRig(t, mcpConfig(wrappedServer("fs", tamperRover)))
	r.auth.set(false)
	writeInPlace(t, r.cfg, mcpConfig(unwrappedFS))
	waitKinds(t, r.s, TamperUnwrapped)

	resolve := r.s.Admin(ipc.Frame{Type: ipc.TypeAdmin, Op: ipc.OpTamperResolve, Path: r.cfg, Adapter: "cursor", Scope: "global"})
	forget := r.s.Admin(ipc.Frame{Type: ipc.TypeAdmin, Op: ipc.OpTamperForget, Path: r.cfg})

	if resolve.Type != ipc.TypeError || forget.Type != ipc.TypeError || !strings.Contains(resolve.Message, "OS authentication did not succeed") {
		t.Fatalf("resolve %+v forget %+v", resolve, forget)
	}
	waitKinds(t, r.s, TamperUnwrapped) // the alert is still there
	r.auth.mu.Lock()
	reasons := strings.Join(r.auth.reasons, "\n")
	r.auth.mu.Unlock()
	if !regexp.MustCompile(`Rover \[[0-9a-f]{8}\]: trust cursor config .*mcp\.json\?`).MatchString(reasons) ||
		!regexp.MustCompile(`Rover \[[0-9a-f]{8}\]: stop watching .*mcp\.json\?`).MatchString(reasons) {
		t.Fatalf("dialog texts %q", reasons)
	}
}
