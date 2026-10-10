package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"

	"github.com/DreadpiratePickles/rover/internal/approve"
	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
	"github.com/DreadpiratePickles/rover/internal/policy"
)

// LESSON (M9): a hold must not block the pipe. roverd answers "hold" at
// once, the wrapper parks the message and keeps pumping, and the approval
// runs here in its own goroutine. When the human answers (or the clock
// runs out) roverd pushes a release for that seq: forward, or block with
// the §5.1 isError body "approval denied" / "approval timed out". Other
// calls, pings and replies keep flowing the whole time; JSON-RPC lets
// requests complete out of order.

// AuditKindApproval marks the audit entry of an approval's outcome.
const AuditKindApproval = "approval"

// held is one message waiting for a human.
type held struct {
	sess   *Session
	server string
	dir    string
	seq    uint64
	m      jsonrpc.Message
	j      judgment
	cn     *conn
}

// startApproval runs the Prompter for h in the background and pushes the
// release when it is decided.
func (s *Server) startApproval(h held) {
	client, _ := h.sess.Client()
	r := approve.Request{
		ID: approve.NewID(), Session: h.sess.ID, Client: client, Server: h.server,
		Tool: h.m.ToolName(), Summary: summarize(h.m), Args: s.approvalArgs(h.m), RuleIDs: h.j.ruleIDs,
	}
	if r.Tool == "" {
		r.Tool = h.m.Method
	}
	if h.sess.Elicitation() {
		r.Elicitor = &elicitor{s: s, sess: h.sess, cn: h.cn}
	}
	ctx, cancel := context.WithCancelCause(s.ctx)
	key, entry := holdKey(h.sess, h.server, h.m.ID), &holdEntry{cancel: cancel, cn: h.cn, sess: h.sess.ID}
	if !s.holds.add(key, entry, s.capPerSession(), s.capTotal()) {
		cancel(nil)
		s.o.Logf("approval %s: denied: %s", r.ID, ReasonTooManyApprovals)
		s.releaseHeld(h, r, approve.Decision{Method: "limit", Reason: ReasonTooManyApprovals})
		return
	}
	s.approvWG.Add(1)
	go func() {
		defer s.approvWG.Done()
		defer cancel(nil)
		d, err := s.o.Prompter.Prompt(ctx, r)
		s.holds.mu.Lock()
		if s.holds.m[key] == entry {
			delete(s.holds.m, key)
		}
		s.holds.mu.Unlock()
		if err != nil {
			s.o.Logf("approval %s: %v", r.ID, err)
			d.Allow = false
		}
		if errors.Is(context.Cause(ctx), approve.ErrCancelledByClient) {
			d = approve.Decision{Method: approve.StateCancelled, Reason: ReasonCancelledByClient}
		}
		s.releaseHeld(h, r, d)
	}()
}

// releaseHeld audits the decision and sends the release frame. If the audit
// write fails, an approved call is blocked anyway (fail closed).
func (s *Server) releaseHeld(h held, r approve.Request, d approve.Decision) {
	action, reason := ipc.ActionForward, "approval "+r.ID+" allowed by "+d.Method
	if !d.Allow {
		action, reason = ipc.ActionBlock, orDefault(d.Reason, approve.ReasonDenied)
	}
	e := audit.Entry{Time: s.o.Now().UTC(), Session: h.sess.ID, Server: h.server, Dir: h.dir, Kind: AuditKindApproval,
		Method: h.m.Method, ID: h.m.ID, Tool: h.m.ToolName(), Action: action, RuleIDs: h.j.ruleIDs}
	e.Reason = reason
	if !d.Allow {
		e.Reason = reason + " (approval " + r.ID + ", " + d.Method + ")"
	}
	if err := s.writeAudit(e); err != nil && d.Allow {
		action, reason = ipc.ActionBlock, "audit log unavailable: "+err.Error()
	}
	f := ipc.Frame{Type: ipc.TypeRelease, Seq: h.seq, Action: action, Reason: reason, RuleIDs: h.j.ruleIDs}
	if action == ipc.ActionBlock {
		if d.Method == approve.StateCancelled {
			f.Drop = true // the client cancelled it: no reply (plan §4.3)
		} else {
			f.ResponseRaw = policy.BlockResponse(h.m, reason, h.j.ruleIDs)
		}
		if h.m.Kind == jsonrpc.KindRequest {
			h.sess.forget(h.server, h.dir, h.m.ID)
		}
	} else if h.dir == policy.DirC2S && h.m.Method == "tools/call" {
		h.sess.noteForwardedCall(h.server, h.dir, h.m.ID, h.j.callLabels)
	}
	if err := h.cn.send(f); err != nil {
		s.o.Logf("approval %s: the wrapper is gone (%v); nothing to release", r.ID, err)
	}
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// approvalArgs are the call's arguments with secrets redacted (M10): the
// record, and the details page when approvals.show_args is on, never see
// the original values.
func (s *Server) approvalArgs(m jsonrpc.Message) json.RawMessage {
	args := callArgs(m)
	if len(args) == 0 {
		return nil
	}
	return s.redactRaw(args)
}

// summarize is the "<short summary>" of the dialog: the argument NAMES
// only (values, even redacted, are long; names say what kind of call it is).
func summarize(m jsonrpc.Message) string {
	fields, err := jsonrpc.Object(callArgs(m))
	if err != nil || len(fields) == 0 {
		return ""
	}
	names := make([]string, 0, len(fields))
	for _, f := range fields {
		names = append(names, f.Key)
	}
	slices.Sort(names)
	return "args: " + strings.Join(names, ", ")
}

// callArgs is params.arguments of a tools/call, else params.
func callArgs(m jsonrpc.Message) json.RawMessage {
	fields, err := jsonrpc.Object(m.Params)
	if err != nil {
		return nil
	}
	if m.Method == "tools/call" {
		a, _ := fields.Get("arguments")
		return a
	}
	return m.Params
}

// elicitTable holds the elicitations roverd sent and is waiting on.
type elicitTable struct {
	mu sync.Mutex
	m  map[string]elicitWait // by the decoded id, "rover-<uuid>"
}

type elicitWait struct {
	sess *Session
	ch   chan jsonrpc.Message
}

// elicitor asks the agent app through the wrapper that carried the call.
type elicitor struct {
	s    *Server
	sess *Session
	cn   *conn
}

// Elicit implements approve.Elicitor.
func (e *elicitor) Elicit(ctx context.Context, r approve.Request) (bool, error) {
	id := approve.NewElicitID()
	raw, err := approve.BuildElicitation(id, r)
	if err != nil {
		return false, err
	}
	ch := make(chan jsonrpc.Message, 1)
	t := &e.s.elicits
	t.mu.Lock()
	t.m[id] = elicitWait{sess: e.sess, ch: ch}
	t.mu.Unlock()
	defer func() {
		t.mu.Lock()
		delete(t.m, id)
		t.mu.Unlock()
	}()
	if err := e.cn.send(ipc.Frame{Type: ipc.TypeInject, Raw: raw}); err != nil {
		return false, err
	}
	select {
	case m := <-ch:
		return approve.ParseElicitReply(m)
	case <-ctx.Done():
		// Decided elsewhere: withdraw the question in the agent app.
		if note, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled",
			"params": map[string]string{"requestId": id, "reason": "decided"}}); err == nil {
			_ = e.cn.send(ipc.Frame{Type: ipc.TypeInject, Raw: note})
		}
		return false, ctx.Err()
	}
}

// roverID handles a message that carries Rover's id prefix: a client
// reply goes to the elicitation waiting for it (only if it came from the
// same session) and is never forwarded; a server request borrowing the
// prefix is refused with -32001.
func (s *Server) roverID(sess *Session, dir string, m jsonrpc.Message) (judgment, bool) {
	if !ipc.IsInjectID(m.ID) {
		return judgment{}, false
	}
	if dir == policy.DirC2S && (m.Kind == jsonrpc.KindResult || m.Kind == jsonrpc.KindError) {
		var id string
		_ = json.Unmarshal(m.ID, &id) // IsInjectID decoded it already
		t := &s.elicits
		t.mu.Lock()
		w, ok := t.m[id]
		if ok && w.sess == sess {
			delete(t.m, id)
		}
		t.mu.Unlock()
		if ok && w.sess == sess {
			w.ch <- m
		}
		return judgment{action: ipc.ActionBlock, audit: ipc.ActionBlock, reason: ReasonRoverReply}, true
	}
	if dir == policy.DirS2C && m.Kind == jsonrpc.KindRequest {
		return blockJ(m, ReasonRoverIDTaken, nil, nil), true
	}
	return judgment{}, false
}

// ReasonCancelledByClient releases a held call whose request the client
// cancelled (notifications/cancelled, plan §4.3).
const ReasonCancelledByClient = "cancelled by client"

// holdTable holds the cancel function of every running approval, by
// session, server and request id.
type holdTable struct {
	mu sync.Mutex
	m  map[string]*holdEntry
}

type holdEntry struct {
	cancel context.CancelCauseFunc
	cn     *conn  // the wrapper that will receive the release
	sess   string // session id, for the per-session cap
}

// Pending-approval caps (review M9): a burst of held calls must not pile
// dialogs and notifications on the human until they click without reading.
const (
	DefaultMaxHoldsPerSession = 5
	DefaultMaxHolds           = 20
	// ReasonTooManyApprovals denies a hold beyond the caps at once.
	ReasonTooManyApprovals = "too many pending approvals"
)

func (s *Server) capPerSession() int {
	if s.o.MaxHoldsPerSession > 0 {
		return s.o.MaxHoldsPerSession
	}
	return DefaultMaxHoldsPerSession
}

func (s *Server) capTotal() int {
	if s.o.MaxHolds > 0 {
		return s.o.MaxHolds
	}
	return DefaultMaxHolds
}

// add registers e unless the caps are reached.
func (t *holdTable) add(key string, e *holdEntry, perSession, total int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.m) >= total {
		return false
	}
	n := 0
	for _, o := range t.m {
		if o.sess == e.sess {
			n++
		}
	}
	if n >= perSession {
		return false
	}
	t.m[key] = e
	return true
}

// dropHolds cancels every approval whose wrapper connection is gone: its
// call can never be released, and the dialog for it must close (review M9).
func (s *Server) dropHolds(cn *conn) {
	s.holds.mu.Lock()
	var gone []*holdEntry
	for _, e := range s.holds.m {
		if e.cn == cn {
			gone = append(gone, e)
		}
	}
	s.holds.mu.Unlock()
	for _, e := range gone {
		e.cancel(approve.ErrWrapperGone)
	}
}

// holdKey names a held request; the id is compacted so 7 and " 7" match.
func holdKey(sess *Session, server string, id json.RawMessage) string {
	var b bytes.Buffer
	if json.Compact(&b, id) != nil {
		b.Reset()
		b.Write(id)
	}
	return sess.ID + "\x00" + server + "\x00" + b.String()
}

// cancelHeld drops the hold a client->server notifications/cancelled
// names: its approval stops (the dialog closes) and the call is released
// as a block. The notification itself is judged and forwarded as usual.
func (s *Server) cancelHeld(sess *Session, server, dir string, m jsonrpc.Message) {
	if dir != policy.DirC2S || m.Kind != jsonrpc.KindNotification || m.Method != "notifications/cancelled" {
		return
	}
	fields, err := jsonrpc.Object(m.Params)
	if err != nil {
		return
	}
	id, ok := fields.Get("requestId")
	if !ok {
		return
	}
	s.holds.mu.Lock()
	e := s.holds.m[holdKey(sess, server, id)]
	s.holds.mu.Unlock()
	if e != nil {
		e.cancel(approve.ErrCancelledByClient)
	}
}
