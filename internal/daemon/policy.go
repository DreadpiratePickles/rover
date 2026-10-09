package daemon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/DreadpiratePickles/rover/internal/config"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
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
)

// noPolicyLogEvery rate-limits the "no policy" warning.
const noPolicyLogEvery = time.Minute

// loaded is one consistent (policy, config) pair. It is swapped as a whole
// so a decision never mixes an old policy with a new config.
type loaded struct {
	pol Policy // nil: no policy loaded
	cfg config.Config
}

// Reload atomically replaces the policy and config. Decisions already in
// flight finish with the previous pair. Pass a nil interface (not a typed nil
// pointer) for p to run with no policy, which blocks every policed message.
func (s *Server) Reload(p Policy, cfg config.Config) {
	s.pol.Store(&loaded{pol: p, cfg: cfg})
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
}

var forwardJ = judgment{action: ipc.ActionForward, audit: ipc.ActionForward}

// judge runs the policy on one message. It never fails open: every error
// path ends in block (or, for a server response, a replacement error).
func (s *Server) judge(sess *Session, server, transport, dir string, m jsonrpc.Message, replyTo string, now time.Time) judgment {
	st := s.pol.Load()
	// A result answering tools/list, or answering nothing we know of (a
	// server could otherwise send a second, unfiltered reply), is filtered.
	if dir == policy.DirS2C && m.Kind == jsonrpc.KindResult && (replyTo == "tools/list" || replyTo == "") {
		return filterList(st, server, m)
	}
	if st.pol == nil {
		if !policy.Policed(dir, m) {
			return forwardJ
		}
		s.warnNoPolicy(now)
		return blockJ(m, ReasonNoPolicy, nil, nil)
	}
	name, ver := sess.Client()
	o := st.pol.Decide(InputFor(st.cfg, server, transport, dir, m, name, ver, sess.Flags(), now))
	j := judgment{action: o.Action, audit: o.Action, reason: o.Reason, ruleIDs: o.RuleIDs, findings: o.Findings}
	switch {
	case o.Action == ipc.ActionBlock:
		j.responseRaw = o.Response
	case o.Action != ipc.ActionForward:
		// TODO(M9): hold. Until approvals exist, anything else blocks.
		return blockJ(m, "unsupported decision "+o.Action, o.RuleIDs, o.Findings)
	case o.WouldDeny:
		j.audit = AuditWouldDeny
	}
	if j.action == ipc.ActionForward && dir == policy.DirC2S && m.Kind == jsonrpc.KindRequest && m.Method == "tools/call" {
		j.call = true
		j.callLabels = st.cfg.ToolLabels(server, m.ToolName())
	}
	return j
}

func blockJ(m jsonrpc.Message, reason string, ids, findings []string) judgment {
	return judgment{
		action: ipc.ActionBlock, audit: ipc.ActionBlock, reason: reason, ruleIDs: ids, findings: findings,
		responseRaw: policy.BlockResponse(m, reason, ids),
	}
}

// filterList removes hidden tools from a tools/list result. The rest of the
// line (id, jsonrpc, unknown members) stays byte-identical.
func filterList(st *loaded, server string, m jsonrpc.Message) judgment {
	if st.pol == nil {
		return forwardJ // nothing is hidden without a policy
	}
	rep, hidden, changed, err := st.pol.FilterToolsList(server, m.Result)
	if err == nil && !changed {
		return forwardJ
	}
	var line []byte
	if err == nil {
		line, err = spliceResult(m.Raw, rep)
	}
	if err != nil {
		return judgment{
			action: ipc.ActionReplace, audit: ipc.ActionBlock,
			reason:      ReasonToolsListRejected + ": " + err.Error(),
			replacement: policy.ErrorResponse(m.ID, ReasonToolsListRejected),
		}
	}
	return judgment{action: ipc.ActionReplace, audit: ipc.ActionReplace, reason: "hidden: " + strings.Join(hidden, ", "), replacement: line}
}

// spliceResult returns raw with the value of its top-level "result" member
// replaced by rep. A message with a duplicate top-level key is refused: the
// client might read the copy we did not filter.
func spliceResult(raw, rep []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, errors.New("response is not a JSON object")
	}
	seen := map[string]bool{}
	start, end := -1, -1
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := t.(string)
		if !ok {
			return nil, errors.New("object key is not a string")
		}
		if seen[key] {
			return nil, fmt.Errorf("duplicate member %q", key)
		}
		seen[key] = true
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		if key == "result" {
			end = int(dec.InputOffset())
			start = end - len(v)
		}
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return nil, errors.New("response object is not closed")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after the response")
	}
	if start < 0 {
		return nil, errors.New("no result member")
	}
	out := make([]byte, 0, len(raw)-(end-start)+len(rep))
	out = append(out, raw[:start]...)
	out = append(out, rep...)
	return append(out, raw[end:]...), nil
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
