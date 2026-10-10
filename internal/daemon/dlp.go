package daemon

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/cedar-policy/cedar-go/types"

	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/config"
	"github.com/DreadpiratePickles/rover/internal/detect"
	"github.com/DreadpiratePickles/rover/internal/dlp"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
	"github.com/DreadpiratePickles/rover/internal/labels"
	"github.com/DreadpiratePickles/rover/internal/policy"
)

// Secrets and data-loss prevention (M10) in roverd. It runs in every mode,
// like pins and detection (D6): learning a policy is no reason to show the
// model a credential or let one leave.
//
//   - Server -> agent results and errors: every string of "result" (text
//     blocks, structuredContent, resource contents) or "error" (message,
//     data) is redacted, "[REDACTED:<kind>]", BEFORE detection scans it and
//     before the agent sees it. Adjacent text blocks are also scanned across
//     their joint, so a key split in two blocks is caught. The verdict is
//     replace with the spliced line; the audit entry gets "dlp:<kind>".
//   - Agent -> server tools/call to a tool labelled egress: a secret in the
//     arguments blocks the call (secret_in_egress_args:<kind>). A tool that
//     is not egress gets its arguments unchanged: the tool may need the
//     value (writing a config file, say), and redacting it would break the
//     call without protecting anything, since the value never reaches the
//     model through this direction. Its audit entry is still redacted.
//   - Everything roverd writes: the audit log (a Redactor on the logger, so
//     approvals, pins and tamper entries are covered too), its own log
//     lines, learn-mode shapes in state.db and approval records.
//
// tools/list results are not rewritten: pins hash them as sent (M4), and a
// description is not where a server hands over a credential.
const (
	// ReasonSecretInEgress blocks an egress call carrying a secret.
	ReasonSecretInEgress = "secret_in_egress_args"
	// ReasonTooManySecrets replaces a response that redaction would grow
	// past the message cap.
	ReasonTooManySecrets = "too_many_secrets"
	// ReasonDLPFailed blocks a call whose arguments could not be scanned.
	ReasonDLPFailed = "dlp_failed"
	// reasonRedacted is the audit reason part of a redacted response.
	reasonRedacted = "redacted"
	// findingPrefix marks DLP findings in the audit entry.
	findingPrefix = "dlp:"
	// joinWindow is how many bytes of each neighbour are joined to scan
	// the joint of two text blocks (a 4096-bit RSA key in PEM is ~3.2 KB).
	joinWindow = 4 << 10
	// unreadableBody replaces an audit body DLP could not read: never log
	// what could not be scanned.
	unreadableBody = `"[REDACTED:unreadable]"`
	// maxReplacement is the proxy's message cap (proxy.DefaultMaxMessage):
	// a rewritten line may not be larger than a line the wrapper accepts.
	maxReplacement = 16 << 20
)

func dlpFindings(kinds []string) []string {
	out := make([]string, len(kinds))
	for i, k := range kinds {
		out[i] = findingPrefix + k
	}
	return out
}

// textAt is one text value inside a buffer: its decoded text and the
// offsets of its JSON string.
type textAt struct {
	text       string
	start, end int
}

// redacted is what redactResponse did to a line.
type redacted struct {
	line  []byte
	kinds []string
	n     int  // matches redacted
	cut   bool // too large once redacted: the whole result was replaced
}

// reason is the audit reason of a redaction.
func (r redacted) reason() string {
	if r.cut {
		return fmt.Sprintf("%s; %s (%d matches)", redactedReason(r.kinds), ReasonTooManySecrets, r.n)
	}
	return redactedReason(r.kinds)
}

// redactResponse redacts raw's top-level member ("result" or "error"):
// first the joints between adjacent text blocks of its blocks member
// ("content", "contents"; "" for none), on the original text, then every
// string and member name. It returns raw itself when nothing changed. A
// redacted line larger than the message cap (each marker is longer than
// what it replaces: 7.8 MB of "pwd=a1234567 " becomes 20 MB) is replaced
// as a whole by tooManySecrets. An error means the line could not be read
// strictly.
func (s *Server) redactResponse(raw []byte, member, blocks string, kind detect.Kind) (redacted, error) {
	top, err := splitObject(raw, 0, len(raw))
	if err != nil {
		return redacted{}, err
	}
	f, ok := field(top, member)
	if !ok {
		return redacted{line: raw}, nil
	}
	val := f.Value
	var r redacted
	if blocks != "" && len(val) > 0 && val[0] == '{' {
		if val, r.kinds, r.n, err = s.redactJoints(val, blocks, kind); err != nil {
			return redacted{}, fmt.Errorf("%s: %w", member, err)
		}
	}
	val, more, n, err := dlp.RedactJSON(s.dlp, val)
	if err != nil {
		return redacted{}, fmt.Errorf("%s: %w", member, err)
	}
	r.n += n
	if r.kinds = sortedUnique(append(r.kinds, more...)); len(r.kinds) == 0 {
		return redacted{line: raw}, nil
	}
	if len(raw)-len(f.Value)+len(val) > s.maxLine {
		return tooManySecrets(raw, member, r), nil
	}
	r.line, err = applyEdits(raw, []edit{{start: f.Start, end: f.End, with: val}})
	return r, err
}

// blockTexts finds the text of every element of res's member array: a
// content block's text (blockTextField) or a resources/read entry's text.
// Offsets are absolute in res; an element without text is nil.
func blockTexts(res []byte, member string, kind detect.Kind) ([]*textAt, error) {
	fs, err := splitObject(res, 0, len(res))
	if err != nil {
		return nil, err
	}
	cf, ok := field(fs, member)
	if !ok || len(cf.Value) == 0 || cf.Value[0] != '[' {
		return nil, nil
	}
	els, err := splitArray(res, cf.Start, cf.End)
	if err != nil {
		return nil, err
	}
	texts := make([]*textAt, len(els))
	for i, el := range els {
		var tf jsonrpc.Field
		var found bool
		if kind == detect.KindResource {
			if ef, eerr := splitObject(res, el[0], el[1]); eerr == nil {
				tf, found = field(ef, "text")
			}
		} else if f, ok, berr := blockTextField(res, el); berr == nil {
			tf, found = f, ok
		}
		if t, isString := stringValue(tf.Value); found && isString {
			texts[i] = &textAt{text: t, start: tf.Start, end: tf.End}
		}
	}
	return texts, nil
}

// tooManySecrets replaces a whole response by a fixed notice (a result
// with one text block, or an error with that message). The request id is
// kept so the agent gets its answer.
func tooManySecrets(raw []byte, member string, r redacted) redacted {
	id := json.RawMessage("null")
	if fs, err := jsonrpc.Object(raw); err == nil {
		if v, ok := fs.Get("id"); ok {
			id = v
		}
	}
	text := fmt.Sprintf("[Rover removed content: too many secrets to redact (%d matches)]", r.n)
	var body any = map[string]any{"content": []any{map[string]string{"type": "text", "text": text}}, "isError": false}
	if member == "error" {
		body = map[string]any{"code": -32001, "message": text}
	}
	r.line = mustJSON(map[string]any{"jsonrpc": "2.0", "id": id, member: body})
	r.cut = true
	return r
}

// dlpResponse redacts a server response that detection does not scan (an
// error, or a result to anything but tools/call, resources/read and
// tools/list). changed is false when there was nothing to redact.
func (s *Server) dlpResponse(m jsonrpc.Message) (judgment, bool) {
	member := "result"
	if m.Kind == jsonrpc.KindError {
		member = "error"
	}
	r, err := s.redactResponse(m.Raw, member, "", detect.KindToolResult)
	if err != nil {
		return judgment{action: ipc.ActionReplace, audit: ipc.ActionBlock, reason: ReasonResultRejected + ": " + err.Error(),
			replacement: policy.ErrorResponse(m.ID, ReasonResultRejected)}, true
	}
	if len(r.kinds) == 0 {
		return judgment{}, false
	}
	return judgment{action: ipc.ActionReplace, audit: ipc.ActionReplace, reason: r.reason(),
		findings: dlpFindings(r.kinds), replacement: r.line}, true
}

func redactedReason(kinds []string) string { return reasonRedacted + ": " + strings.Join(kinds, ", ") }

// egressSecret checks a tools/call's arguments. A secret in the arguments
// of an egress tool blocks the call (blocked non-nil); otherwise kinds are
// the secrets found, for the audit findings.
func (s *Server) egressSecret(cfg config.Config, server string, m jsonrpc.Message) (kinds []string, blocked *judgment) {
	kinds, err := dlp.FindJSON(s.dlp, m.ToolArguments())
	if err != nil {
		j := blockJ(m, ReasonDLPFailed+": "+err.Error(), nil, nil)
		return nil, &j
	}
	if len(kinds) == 0 {
		return nil, nil
	}
	if ls, _ := cfg.EffectiveLabels(server, m.ToolName()); slices.Contains(ls, labels.Egress) {
		j := blockJ(m, ReasonSecretInEgress+":"+kinds[0], nil, dlpFindings(kinds))
		return kinds, &j
	}
	return kinds, nil
}

// withSecrets notes the secrets of a call that went on (not egress): the
// audit findings, and a learn-mode shape that must not keep them.
func (s *Server) withSecrets(j judgment, kinds []string) judgment {
	j.findings = sortedUnique(append(append([]string(nil), j.findings...), dlpFindings(kinds)...))
	if j.obs != nil {
		obs := *j.obs
		obs.Args, obs.Norm = s.redactRecord(obs.Args), s.redactRecord(obs.Norm)
		j.obs = &obs
	}
	return j
}

// redactRaw redacts one JSON value for the audit log or an approval record.
func (s *Server) redactRaw(raw json.RawMessage) json.RawMessage {
	out, _, _, err := dlp.RedactJSON(s.dlp, raw)
	if err != nil {
		return json.RawMessage(unreadableBody)
	}
	return out
}

func (s *Server) redactText(text string) string {
	out, _ := dlp.RedactString(s.dlp, text)
	return out
}

// redactEntry is the audit log's Redactor.
func (s *Server) redactEntry(e audit.Entry) audit.Entry {
	e.Server, e.Method, e.Tool, e.ReplyTo = s.redactText(e.Server), s.redactText(e.Method), s.redactText(e.Tool), s.redactText(e.ReplyTo)
	e.Reason = s.redactText(e.Reason)
	if len(e.ID) > 0 {
		e.ID = s.redactRaw(e.ID)
	}
	if len(e.Body) > 0 {
		e.Body = s.redactBody(e)
	}
	return e
}

// redactBody redacts an audit entry's body. The body of a server reply is
// the original line (M9: the log keeps what the server sent), so it gets
// what the forwarded line got, the joint scan across its text blocks
// included: a key split in two blocks must not be whole in the log.
func (s *Server) redactBody(e audit.Entry) json.RawMessage {
	member, blocks, kind := "", "", detect.KindToolResult
	switch e.Kind {
	case string(jsonrpc.KindResult):
		member, blocks = "result", "content"
		switch e.ReplyTo {
		case "resources/read":
			blocks, kind = "contents", detect.KindResource
		case "initialize", "prompts/get":
			blocks = ""
		}
	case string(jsonrpc.KindError):
		member = "error"
	}
	if member == "" {
		return s.redactRaw(e.Body)
	}
	r, err := s.redactResponse(e.Body, member, blocks, kind)
	if err != nil {
		return json.RawMessage(unreadableBody)
	}
	return r.line
}

// redactingLogf wraps logf so no log line carries a secret.
func redactingLogf(d dlp.Detector, logf func(string, ...any)) func(string, ...any) {
	return func(format string, a ...any) {
		out, ms := dlp.RedactString(d, fmt.Sprintf(format, a...))
		if len(ms) == 0 {
			logf(format, a...) // unchanged: the caller's format and arguments
			return
		}
		logf("%s", out)
	}
}

// RedactingLogf is redactingLogf with the built-in detector, for the
// daemon command's own log lines.
func RedactingLogf(logf func(string, ...any)) func(string, ...any) {
	return redactingLogf(dlp.New(), logf)
}

// redactRecord returns r with every string redacted (learn-mode shapes
// keep short literals, which is exactly the size of a key id).
// Argument names are redacted too, kept unique like RedactJSON's.
func (s *Server) redactRecord(r types.Record) types.Record {
	m := make(types.RecordMap, r.Len())
	used := map[string]bool{}
	var renamed []types.String
	for k := range r.All() {
		if len(s.dlp.Find([]byte(k))) > 0 {
			renamed = append(renamed, k)
		} else {
			used[strings.ToLower(string(k))] = true
		}
	}
	for k, v := range r.All() {
		m[k] = s.redactValue(string(k), v)
	}
	for _, k := range renamed {
		v := m[k]
		delete(m, k)
		name := dlp.UniqueName(s.redactText(string(k)), used)
		used[strings.ToLower(name)] = true
		m[types.String(name)] = v
	}
	return types.NewRecord(m)
}

func (s *Server) redactValue(key string, v types.Value) types.Value {
	switch x := v.(type) {
	case types.String:
		if ms := dlp.FindValue(s.dlp, key, string(x)); len(ms) > 0 {
			return types.String(dlp.Redact([]byte(x), ms))
		}
	case types.Record:
		return s.redactRecord(x)
	case types.Set:
		vs := make([]types.Value, 0, x.Len())
		for e := range x.All() {
			vs = append(vs, s.redactValue(key, e))
		}
		return types.NewSet(vs...)
	}
	return v
}
