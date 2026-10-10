package daemon

import (
	"context"
	"encoding/json"
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
		Tool: h.m.ToolName(), Summary: summarize(h.m), Args: callArgs(h.m), RuleIDs: h.j.ruleIDs,
	}
	if r.Tool == "" {
		r.Tool = h.m.Method
	}
	if h.sess.Elicitation() {
		r.Elicitor = &elicitor{s: s, sess: h.sess, cn: h.cn}
	}
	s.approvWG.Add(1)
	go func() {
		defer s.approvWG.Done()
		d, err := s.o.Prompter.Prompt(s.ctx, r)
		if err != nil {
			s.o.Logf("approval %s: %v", r.ID, err)
			d.Allow = false
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
		f.ResponseRaw = policy.BlockResponse(h.m, reason, h.j.ruleIDs)
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

// summarize is the "<short summary>" of the dialog: the argument NAMES
// only. Values may be secrets (M10 redacts them later); names say what
// kind of call it is.
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
