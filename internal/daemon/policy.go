package daemon

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/DreadpiratePickles/rover/internal/config"
	"github.com/DreadpiratePickles/rover/internal/detect"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
	"github.com/DreadpiratePickles/rover/internal/pin"
	"github.com/DreadpiratePickles/rover/internal/policy"
)

// Policy is the decision source roverd consults. *policy.Engine implements
// it; tests may use a fake.
type Policy interface {
	Decide(policy.Input) policy.Outcome
	FilterToolsList(server string, resultRaw []byte) (replacement []byte, hidden []string, changed bool, err error)
}

// Audit actions besides the ipc verdict actions.
const (
	// AuditWouldDeny records a message observe mode forwarded although the
	// policy denied it.
	AuditWouldDeny = "would_deny"
	// ReasonNoPolicy blocks every policed message while no policy is loaded.
	ReasonNoPolicy = "no_policy"
	// ReasonToolsListRejected replaces a tools/list result that could not be
	// filtered: forwarding it might show the agent a hidden tool.
	ReasonToolsListRejected = "tools_list_rejected"
	// ReasonInvalidJSONRPC blocks a line jsonrpc.Parse could not classify
	// unambiguously (followed by ": " and jsonrpc.Message.Invalid).
	ReasonInvalidJSONRPC = policy.ReasonInvalidJSONRPC
)

// noPolicyLogEvery rate-limits the "no policy" warning.
const noPolicyLogEvery = time.Minute

// loaded is one consistent (policy, config) pair. It is swapped as a whole
// so a decision never mixes an old policy with a new config.
type loaded struct {
	pol Policy // nil: no policy loaded
	cfg config.Config
}

// ErrModeDowngrade refuses a reload that would switch an enforcing daemon
// to observe mode.
var ErrModeDowngrade = errors.New("refused: switching enforce -> observe needs OS authentication (M9)")

// Reload atomically replaces the policy and config. Decisions already in
// flight finish with the previous pair. Pass a nil interface (not a typed nil
// pointer) for p to run with no policy, which blocks every policed message.
//
// A reload may not switch from enforce to observe: anything that can edit or
// delete config.yaml (an agent with file access, say) could otherwise turn
// enforcement off with one `rover policy apply` (review M2). That switch will
// need OS authentication (M9); until then it returns ErrModeDowngrade and
// the previous policy and mode stay in force. At startup a missing
// config.yaml still means observe (D6).
func (s *Server) Reload(p Policy, cfg config.Config) error {
	next := &loaded{pol: p, cfg: cfg}
	for {
		cur := s.pol.Load()
		if cur != nil && cur.cfg.Mode == policy.ModeEnforce && cfg.Mode != policy.ModeEnforce {
			return ErrModeDowngrade
		}
		if s.pol.CompareAndSwap(cur, next) {
			return nil
		}
	}
}

// InputFor builds the policy input for one message. `rover policy test`
// uses it too, so a replay sees exactly what roverd would have seen.
func InputFor(cfg config.Config, server, transport, dir string, m jsonrpc.Message, client, clientVer string, flags policy.SessionCtx, now time.Time) policy.Input {
	return policy.Input{
		Mode:          cfg.Mode,
		Client:        client,
		ClientVersion: clientVer,
		Server:        server,
		Transport:     transport,
		Dir:           dir,
		Msg:           m,
		Labels:        cfg.Labels[server],
		Session:       flags,
		Now:           now.Local(), // context.time is the user's wall clock
		Roots:         cfg.Roots,
		Normalizers:   cfg.ToolNormalizers(server, m.ToolName()),
	}
}

// judgment is what decide does with one message: the verdict for the
// wrapper and the fields for the audit entry.
type judgment struct {
	action      string // ipc verdict action
	audit       string // audit action (differs for would_deny and rejected lists)
	reason      string
	ruleIDs     []string
	findings    []string
	responseRaw []byte   // block: the reply to the requester
	replacement []byte   // replace: the line forwarded instead
	callLabels  []string // a forwarded tools/call: its labels, for the session flags
	call        bool
	pinEvents   []pin.Event   // audited before the message itself, mismatches notified
	poisoned    []poisonEvent // tools detection removed: audited and notified the same way
	untrusted   bool          // a result with a detection finding: the session saw untrusted data
	bodyOut     []byte        // the line as forwarded, for the audit body when it was rewritten
}

var forwardJ = judgment{action: ipc.ActionForward, audit: ipc.ActionForward}

// judge runs the policy on one message. It never fails open: every error
// path ends in block (or, for a server response, a replacement error).
// cursor is the params.cursor of the tools/list request a result answers.
func (s *Server) judge(sess *Session, server, transport, dir string, m jsonrpc.Message, replyTo, cursor string, now time.Time) judgment {
	st := s.pol.Load()
	// A line that is not unambiguous JSON-RPC is blocked in both directions,
	// in every mode and with or without a policy: whatever Rover would judge
	// it as, the receiver may read it as something else (review C1).
	if m.Kind == jsonrpc.KindInvalid {
		if dir == policy.DirS2C && m.Method == "" && m.ID != nil && sess.take(server, policy.DirC2S, m.ID) {
			return invalidReplyJ(m)
		}
		return invalidJ(m)
	}
	// A result answering tools/list, or answering nothing we know of (a
	// server could otherwise send a second, unfiltered reply), is filtered.
	if dir == policy.DirS2C && m.Kind == jsonrpc.KindResult && (replyTo == "tools/list" || replyTo == "") {
		return s.filterList(st, server, m, replyTo == "", cursor)
	}
	// Tool and resource results are scanned for injection (M5), in every mode.
	if dir == policy.DirS2C && m.Kind == jsonrpc.KindResult && (replyTo == "tools/call" || replyTo == "resources/read") {
		return s.detectResult(m, replyTo)
	}
	// Pins come before policy and apply in every mode (D6): a tool that
	// changed under the agent is refused even while learning. So is a tool
	// detection removed from the list.
	if dir == policy.DirC2S && m.Kind == jsonrpc.KindRequest && m.Method == "tools/call" {
		if j, refused := s.pinCall(server, m); refused {
			return j
		}
		if j, refused := s.poisonedCall(server, m); refused {
			return j
		}
	}
	var pinEvents []pin.Event
	if dir == policy.DirS2C && m.Kind == jsonrpc.KindNotification && m.Method == MethodToolsListChanged {
		pinEvents = s.pinRecheck(server)
	}
	var det detect.Summary
	if m.Kind == jsonrpc.KindRequest {
		var blocked *judgment
		if det, blocked = s.detectRequest(dir, m); blocked != nil {
			return *blocked // high: blocked in every mode (D6)
		}
	}
	j := s.judgePolicy(st, sess, server, transport, dir, m, now, det)
	j.pinEvents = pinEvents
	return j
}

// judgePolicy is the Cedar half of judge.
// det is the detection summary of the message (context.detection).
func (s *Server) judgePolicy(st *loaded, sess *Session, server, transport, dir string, m jsonrpc.Message, now time.Time, det detect.Summary) judgment {
	if st.pol == nil {
		if !policy.Policed(dir, m) {
			return forwardJ
		}
		s.warnNoPolicy(now)
		return blockJ(m, ReasonNoPolicy, nil, det.IDs)
	}
	name, ver := sess.Client()
	in := InputFor(st.cfg, server, transport, dir, m, name, ver, sess.Flags(), now)
	in.Detection = policy.DetectionCtx{MaxScore: det.MaxScore, Findings: det.IDs}
	o := st.pol.Decide(in)
	findings := sortedUnique(append(append([]string(nil), det.IDs...), o.Findings...))
	j := judgment{action: o.Action, audit: o.Action, reason: o.Reason, ruleIDs: o.RuleIDs, findings: findings}
	switch {
	case o.Action == ipc.ActionBlock:
		j.responseRaw = o.Response
	case o.Action != ipc.ActionForward:
		// TODO(M9): hold. Until approvals exist, anything else blocks.
		return blockJ(m, "unsupported decision "+o.Action, o.RuleIDs, findings)
	case o.WouldDeny:
		j.audit = AuditWouldDeny
	}
	if j.action == ipc.ActionForward && dir == policy.DirC2S && m.Kind == jsonrpc.KindRequest && m.Method == "tools/call" {
		j.call = true
		j.callLabels = st.cfg.ToolLabels(server, m.ToolName())
	}
	return j
}

// invalidJ blocks an invalid line (see policy.InvalidOutcome).
func invalidJ(m jsonrpc.Message) judgment {
	o := policy.InvalidOutcome(m)
	return judgment{action: o.Action, audit: o.Action, reason: o.Reason, responseRaw: o.Response}
}

// invalidReplyJ replaces an invalid server line that names a pending agent
// request with a -32001 error for that id, so the agent is not left waiting
// for a reply that will never come. The line itself is never forwarded.
func invalidReplyJ(m jsonrpc.Message) judgment {
	reason := ReasonInvalidJSONRPC + ": " + m.Invalid
	return judgment{
		action: ipc.ActionReplace, audit: ipc.ActionBlock, reason: reason,
		replacement: policy.ErrorResponse(m.ID, reason),
	}
}

func blockJ(m jsonrpc.Message, reason string, ids, findings []string) judgment {
	return judgment{
		action: ipc.ActionBlock, audit: ipc.ActionBlock, reason: reason, ruleIDs: ids, findings: findings,
		responseRaw: policy.BlockResponse(m, reason, ids),
	}
}

// filterList removes from a tools/list result first every tool whose pin
// does not match (pin.Checker.Check, in every mode), then every tool the
// policy hides. The rest of the line (id, jsonrpc, unknown members) stays
// byte-identical. uncorrelated is a result answering no request we know of:
// it is checked too if it carries tools (a server could otherwise send a
// second, unfiltered list).
func (s *Server) filterList(st *loaded, server string, m jsonrpc.Message, uncorrelated bool, cursor string) judgment {
	line, result := m.Raw, m.Result
	var reasons, found []string
	var removed []poisonEvent
	filtered, pinChanged, events, err := s.pins.CheckPage(server, m.Result, cursor)
	notList := errors.Is(err, pin.ErrNotToolsList) && uncorrelated
	switch {
	case notList:
		// not a tool list: nothing to pin; scanned as a result below
	case err != nil:
		return rejectList(m, err)
	case pinChanged:
		if line, err = spliceResult(line, filtered); err != nil {
			return rejectList(m, err)
		}
		result = filtered
		reasons = append(reasons, ReasonPinMismatch+": "+strings.Join(mismatched(events), ", "))
	}
	// Detection (M5): after pins, before the policy hides tools.
	if !notList {
		var rep []byte
		if rep, removed, found, err = s.detectList(server, result); err != nil {
			return rejectList(m, err)
		}
		if len(removed) > 0 {
			if line, err = spliceResult(line, rep); err != nil {
				return rejectList(m, err)
			}
			result = rep
			reasons = append(reasons, ReasonToolPoisoning+": "+strings.Join(poisonedNames(removed), ", "))
		}
	}
	if st.pol != nil { // without a policy nothing is hidden
		rep, hidden, changed, err := st.pol.FilterToolsList(server, result)
		if err == nil && changed {
			line, err = spliceResult(line, rep)
			reasons = append(reasons, "hidden: "+strings.Join(hidden, ", "))
		}
		if err != nil {
			return rejectList(m, err)
		}
	}
	if notList {
		return s.detectResult(m, "")
	}
	j := judgment{action: ipc.ActionForward, audit: ipc.ActionForward, pinEvents: events, poisoned: removed, findings: found}
	if len(reasons) > 0 {
		j.action, j.audit, j.reason, j.replacement = ipc.ActionReplace, ipc.ActionReplace, strings.Join(reasons, "; "), line
	}
	return j
}

// rejectList replaces a tools/list result that could not be checked or
// filtered with an error: forwarding it might show the agent a hidden or
// changed tool.
func rejectList(m jsonrpc.Message, err error) judgment {
	return judgment{
		action: ipc.ActionReplace, audit: ipc.ActionBlock,
		reason:      ReasonToolsListRejected + ": " + err.Error(),
		replacement: policy.ErrorResponse(m.ID, ReasonToolsListRejected),
	}
}

// spliceResult returns raw with the value of its top-level "result" member
// replaced by rep. The member is found with the strict reader, by its exact
// key and byte offsets, so a message with a duplicate or case-colliding key
// ("result" and "Result") is refused: the client might read the copy we did
// not filter.
func spliceResult(raw, rep []byte) ([]byte, error) {
	fields, err := jsonrpc.Object(raw)
	if err != nil {
		return nil, fmt.Errorf("response: %w", err)
	}
	for _, f := range fields {
		if f.Key != "result" {
			continue
		}
		out := make([]byte, 0, len(raw)-(f.End-f.Start)+len(rep))
		out = append(out, raw[:f.Start]...)
		out = append(out, rep...)
		return append(out, raw[f.End:]...), nil
	}
	return nil, errors.New("no result member")
}

// warnNoPolicy logs at most once per noPolicyLogEvery.
func (s *Server) warnNoPolicy(now time.Time) {
	last := s.noPolicyWarned.Load()
	if last != 0 && now.Sub(time.Unix(0, last)) < noPolicyLogEvery {
		return
	}
	if s.noPolicyWarned.CompareAndSwap(last, now.UnixNano()) {
		s.o.Logf("NO POLICY LOADED: blocking every tools/call, tools/list, resources/read, sampling and elicitation request. " +
			"Run `rover policy init`, edit policy.cedar, then `rover policy apply`.")
	}
}
