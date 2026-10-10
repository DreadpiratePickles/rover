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

// redactResponse redacts raw's top-level member ("result" or "error"):
// every string, then the boundaries between adjacent text blocks of its
// blocks member ("content", "contents"; "" for none). It returns raw
// itself when nothing changed. An error means the line could not be read
// strictly.
func (s *Server) redactResponse(raw []byte, member, blocks string, kind detect.Kind) ([]byte, []string, error) {
	top, err := splitObject(raw, 0, len(raw))
	if err != nil {
		return nil, nil, err
	}
	f, ok := field(top, member)
	if !ok {
		return raw, nil, nil
	}
	val, kinds, err := dlp.RedactJSON(s.dlp, f.Value)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", member, err)
	}
	if blocks != "" && len(val) > 0 && val[0] == '{' {
		var more []string
		if val, more, err = s.redactBoundaries(val, blocks, kind); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", member, err)
		}
		kinds = sortedUnique(append(kinds, more...))
	}
	if len(kinds) == 0 {
		return raw, nil, nil
	}
	out, err := applyEdits(raw, []edit{{start: f.Start, end: f.End, with: val}})
	return out, kinds, err
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

// redactBoundaries scans the joint of each pair of adjacent text blocks
// (the last joinWindow bytes of one and the first of the next, joined) for
// a secret split across them, and redacts both halves.
func (s *Server) redactBoundaries(res []byte, member string, kind detect.Kind) ([]byte, []string, error) {
	texts, err := blockTexts(res, member, kind)
	if err != nil {
		return nil, nil, err
	}
	split := make([][]dlp.Match, len(texts))
	var kinds []string
	for i := 0; i+1 < len(texts); i++ {
		a, b := texts[i], texts[i+1]
		if a == nil || b == nil {
			continue
		}
		tail, head := a.text[max(0, len(a.text)-joinWindow):], b.text[:min(len(b.text), joinWindow)]
		for _, m := range s.dlp.Find([]byte(tail + head)) {
			if m.Start >= len(tail) || m.End <= len(tail) {
				continue // inside one block: already redacted there
			}
			split[i] = append(split[i], dlp.Match{Kind: m.Kind, Start: len(a.text) - len(tail) + m.Start, End: len(a.text)})
			split[i+1] = append(split[i+1], dlp.Match{Kind: m.Kind, Start: 0, End: m.End - len(tail)})
			kinds = append(kinds, m.Kind)
		}
	}
	var edits []edit
	for i, ms := range split {
		if len(ms) > 0 {
			red := dlp.Redact([]byte(texts[i].text), ms)
			edits = append(edits, edit{start: texts[i].start, end: texts[i].end, with: mustJSON(string(red))})
		}
	}
	if len(edits) == 0 {
		return res, nil, nil
	}
	out, err := applyEdits(res, edits)
	return out, kinds, err
}

// dlpResponse redacts a server response that detection does not scan (an
// error, or a result to anything but tools/call, resources/read and
// tools/list). changed is false when there was nothing to redact.
func (s *Server) dlpResponse(m jsonrpc.Message) (judgment, bool) {
	member := "result"
	if m.Kind == jsonrpc.KindError {
		member = "error"
	}
	line, kinds, err := s.redactResponse(m.Raw, member, "", detect.KindToolResult)
	if err != nil {
		return judgment{action: ipc.ActionReplace, audit: ipc.ActionBlock, reason: ReasonResultRejected + ": " + err.Error(),
			replacement: policy.ErrorResponse(m.ID, ReasonResultRejected)}, true
	}
	if len(kinds) == 0 {
		return judgment{}, false
	}
	return judgment{action: ipc.ActionReplace, audit: ipc.ActionReplace, reason: redactedReason(kinds),
		findings: dlpFindings(kinds), replacement: line}, true
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
	out, _, err := dlp.RedactJSON(s.dlp, raw)
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
		e.Body = s.redactRaw(e.Body)
	}
	return e
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
func (s *Server) redactRecord(r types.Record) types.Record {
	m := make(types.RecordMap, r.Len())
	for k, v := range r.All() {
		m[k] = s.redactValue(string(k), v)
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
