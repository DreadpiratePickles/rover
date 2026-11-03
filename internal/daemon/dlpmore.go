package daemon

import (
	"strings"

	"github.com/DreadpiratePickles/rover/internal/dlp"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
)

// serverRequests are the server -> client requests whose text reaches the
// agent app (and through sampling, the model).
var serverRequests = map[string]bool{"sampling/createMessage": true, "elicitation/create": true}

// redactServerRequest redacts the params of a forwarded sampling or
// elicitation request (messages, systemPrompt, message, schema text)
// before it goes to the client, splicing only the changed strings.
func (s *Server) redactServerRequest(m jsonrpc.Message, j judgment) judgment {
	fs, err := jsonrpc.Object(m.Raw)
	if err != nil {
		return blockJ(m, ReasonDLPFailed+": "+err.Error(), j.ruleIDs, j.findings)
	}
	f, ok := field(fs, "params")
	if !ok {
		return j
	}
	val, kinds, _, err := dlp.RedactJSON(s.dlp, f.Value)
	if err != nil {
		return blockJ(m, ReasonDLPFailed+": "+err.Error(), j.ruleIDs, j.findings)
	}
	if len(kinds) == 0 {
		return j
	}
	line, err := applyEdits(m.Raw, []edit{{start: f.Start, end: f.End, with: val}})
	if err != nil || len(line) > s.maxLine {
		return blockJ(m, ReasonTooManySecrets, j.ruleIDs, j.findings)
	}
	// Audited as replace, because it was rewritten; observe mode's
	// would_deny stays in the reason.
	prefix := j.reason
	if j.audit == AuditWouldDeny {
		prefix = strings.TrimSuffix(AuditWouldDeny+": "+j.reason, ": ")
	}
	j.action, j.audit, j.replacement = ipc.ActionReplace, ipc.ActionReplace, line
	j.reason = strings.TrimPrefix(prefix+"; "+redactedReason(kinds), "; ")
	j.findings = sortedUnique(append(append([]string(nil), j.findings...), dlpFindings(kinds)...))
	return j
}
