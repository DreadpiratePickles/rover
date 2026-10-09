package policy

import (
	"errors"
	"strings"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"

	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
)

// Reasons Decide reports.
const (
	ReasonNoPermit  = "no permit matched"
	ReasonWouldDeny = "would_deny"
	// ReasonApprovalM2 blocks a permit that needs approval, because the
	// approval flow does not exist before M9 (fail closed).
	ReasonApprovalM2 = "approval_required_not_available_until_M9"
	// ReasonInvalidJSONRPC blocks a line jsonrpc.Parse could not classify
	// unambiguously; the full reason is "invalid_jsonrpc: <Message.Invalid>".
	ReasonInvalidJSONRPC = "invalid_jsonrpc"
)

// Outcome is what the enforcement point must do with one message.
type Outcome struct {
	Action   string   // ipc.ActionForward, ipc.ActionBlock (ActionHold from M9)
	Reason   string   // why; "" for an unpoliced message
	RuleIDs  []string // the deciding policy ids, sorted
	Findings []string // from argument conversion and normalisation
	// Response is the complete JSON-RPC message (no trailing newline) to
	// send back to the requester when Action is block (plan §5.1).
	Response []byte
	// WouldDeny is set in observe mode when the message was denied but is
	// forwarded anyway; the audit log records it as "would_deny".
	WouldDeny bool
}

// Decide judges one message. It never returns an error: every failure on
// the decision path becomes a block.
//
// Policed messages: client->server tools/call (call_tool), tools/list
// (list_tools), resources/read (read_resource) and server->client
// sampling/createMessage (server_sampling), elicitation/create
// (server_elicitation). Everything else is forwarded unjudged in M2, except
// an invalid (ambiguous) line, which is blocked in every mode.
func (e *Engine) Decide(in Input) Outcome {
	if in.Dir != DirC2S && in.Dir != DirS2C {
		return block(in, ReasonInvalidDirection, nil, nil)
	}
	if in.Msg.Kind == jsonrpc.KindInvalid {
		return InvalidOutcome(in.Msg)
	}
	action := policedAction(in.Dir, in.Msg)
	if action == "" {
		return Outcome{Action: ipc.ActionForward}
	}
	b, err := buildRequest(in, action)
	if err != nil {
		// Conversion and normalisation failures block even in observe
		// mode: the message is malformed or hostile, not merely unpermitted.
		var d denyError
		if !errors.As(err, &d) {
			d = denyError{reason: "internal_error"}
		}
		return block(in, d.reason, nil, nil)
	}
	decision, diag := cedar.Authorize(e.policies, b.entities, b.req)
	return e.outcome(in, decision, diag, b.findings)
}

// outcome turns Cedar's answer into an Outcome.
func (e *Engine) outcome(in Input, decision types.Decision, diag types.Diagnostic, findings []string) Outcome {
	fired := make([]types.PolicyID, 0, len(diag.Reasons))
	for _, r := range diag.Reasons {
		fired = append(fired, r.PolicyID)
	}
	// A forbid that failed to evaluate might have fired; treat it as fired.
	var erroredForbids []types.PolicyID
	for _, de := range diag.Errors {
		if e.forbids[de.PolicyID] {
			erroredForbids = append(erroredForbids, de.PolicyID)
		}
	}

	if decision == cedar.Allow && len(erroredForbids) == 0 {
		for _, id := range fired {
			if e.approval[id] {
				// TODO(M9): return ipc.ActionHold and start the OS approval
				// dialog. Until then a permit that needs approval blocks.
				return block(in, ReasonApprovalM2, sortedIDs(fired), findings)
			}
		}
		return Outcome{Action: ipc.ActionForward, RuleIDs: sortedIDs(fired), Findings: findings}
	}

	var ids []string
	reason := ReasonNoPermit
	if decision == cedar.Allow {
		// Allowed only because an erroring forbid did not count: deny.
		ids = sortedIDs(erroredForbids)
		reason = "forbid " + strings.Join(ids, ", ") + " (evaluation error)"
	} else if forbids := append(fired, erroredForbids...); len(forbids) > 0 {
		// On deny, Cedar's reasons are the forbids that fired.
		ids = sortedIDs(forbids)
		reason = "forbid " + strings.Join(ids, ", ")
	}
	if in.Mode == ModeObserve {
		return Outcome{Action: ipc.ActionForward, Reason: ReasonWouldDeny, RuleIDs: ids, Findings: findings, WouldDeny: true}
	}
	return block(in, reason, ids, findings)
}

// block builds a block outcome with the response body for the requester.
func block(in Input, reason string, ids, findings []string) Outcome {
	return Outcome{
		Action:   ipc.ActionBlock,
		Reason:   reason,
		RuleIDs:  ids,
		Findings: findings,
		Response: blockResponse(in.Msg, reason, ids),
	}
}

// Policed reports whether Decide judges this message with Cedar (the five
// policed methods). roverd uses it to block exactly these messages when no
// policy is loaded, and to forward everything else.
//
// An invalid line counts as policed: Decide always blocks it.
func Policed(dir string, m jsonrpc.Message) bool {
	return m.Kind == jsonrpc.KindInvalid || policedAction(dir, m) != ""
}

// InvalidOutcome blocks an invalid line, in every mode (review C1: Rover
// cannot know how the receiver will read an ambiguous line). If it still
// names an exact id and method, the requester gets -32600 Invalid Request
// rather than waiting forever; anything else is dropped.
func InvalidOutcome(m jsonrpc.Message) Outcome {
	o := Outcome{Action: ipc.ActionBlock, Reason: ReasonInvalidJSONRPC + ": " + m.Invalid}
	if m.InvalidRequest() {
		o.Response = InvalidRequestResponse(m.ID, o.Reason)
	}
	return o
}
