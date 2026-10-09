package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/DreadpiratePickles/rover/internal/detect"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
	"github.com/DreadpiratePickles/rover/internal/policy"
)

// resultPlan is what scanning one result decided: findings and the edits
// that turn the line into what the agent receives.
type resultPlan struct {
	findings []detect.Finding
	edits    []edit
	removed  []string // SHA-256 of each removed text
	warned   bool
}

func (p resultPlan) reason() string {
	var parts []string
	if len(p.removed) > 0 {
		parts = append(parts, "removed sha256:"+strings.Join(p.removed, ", sha256:"))
	}
	if p.warned {
		parts = append(parts, reasonWarned)
	}
	return strings.Join(parts, "; ")
}

// detectResult scans the text of a tools/call result (or a result answering
// nothing we know of) or a resources/read result. High: the block's text is
// replaced by removedText (only that JSON string changes; its SHA-256 goes
// in the audit reason so the removed text stays referenceable). Medium: a
// tool result gets UntrustedNotice as a first text block; a resource, whose
// contents must each carry a uri, gets the notice in front of its text. Low:
// findings only. Any finding marks the session saw_untrusted.
func (s *Server) detectResult(m jsonrpc.Message, replyTo string) judgment {
	kind, member := detect.KindToolResult, "content"
	if replyTo == "resources/read" {
		kind, member = detect.KindResource, "contents"
	}
	plan, err := scanResult(m.Raw, kind, member)
	if err != nil {
		return judgment{
			action: ipc.ActionReplace, audit: ipc.ActionBlock,
			reason:      ReasonResultRejected + ": " + err.Error(),
			replacement: policy.ErrorResponse(m.ID, ReasonResultRejected),
		}
	}
	if len(plan.findings) == 0 {
		return forwardJ
	}
	j := judgment{action: ipc.ActionForward, audit: ipc.ActionForward, findings: detect.Score(plan.findings).IDs, untrusted: true}
	if len(plan.edits) == 0 {
		return j
	}
	line, err := applyEdits(m.Raw, plan.edits)
	if err != nil {
		return judgment{action: ipc.ActionReplace, audit: ipc.ActionBlock, reason: ReasonResultRejected + ": " + err.Error(),
			replacement: policy.ErrorResponse(m.ID, ReasonResultRejected)}
	}
	j.action, j.audit, j.reason, j.replacement, j.bodyOut = ipc.ActionReplace, ipc.ActionReplace, plan.reason(), line, line
	return j
}

// textAt is one text value inside the line: its decoded text and offsets.
type textAt struct {
	text       string
	start, end int // of the JSON string in the line
}

// scanResult finds every text block of the result's member array (content
// or contents), scans it, and plans the edits.
func scanResult(line []byte, kind detect.Kind, member string) (resultPlan, error) {
	var plan resultPlan
	top, err := jsonrpc.Object(line)
	if err != nil {
		return plan, err
	}
	rf, ok := field(top, "result")
	if !ok {
		return plan, errors.New("no result member")
	}
	if len(rf.Value) == 0 || rf.Value[0] != '{' {
		return plan, nil // not an object: no text blocks to scan
	}
	res, err := jsonrpc.Object(rf.Value)
	if err != nil {
		return plan, fmt.Errorf("result: %w", err) // ambiguous: the client might read another copy
	}
	cf, ok := field(res, member)
	if !ok {
		return plan, nil
	}
	base := rf.Start + cf.Start
	els, err := arrayElems(cf.Value)
	if err != nil {
		return plan, fmt.Errorf("%s: %w", member, err)
	}
	rules := detect.NewRules()
	for i, el := range els {
		t, ok, err := blockText(el.raw, kind)
		if err != nil {
			return plan, fmt.Errorf("%s[%d]: %w", member, i, err)
		}
		if !ok {
			continue
		}
		t.start, t.end = t.start+base+el.start, t.end+base+el.start
		fs := rules.Scan(kind, []byte(t.text))
		plan.findings = append(plan.findings, fs...)
		switch detect.Max(fs) {
		case detect.High:
			plan.edits = append(plan.edits, edit{t.start, t.end, mustJSON(removedText(detect.Score(fs).IDs))})
			plan.removed = append(plan.removed, sha(t.text))
		case detect.Medium:
			if kind == detect.KindResource {
				plan.edits = append(plan.edits, edit{t.start, t.end, mustJSON(UntrustedNotice + "\n\n" + t.text)})
			}
			plan.warned = true
		}
	}
	if plan.warned && kind == detect.KindToolResult {
		at := base + els[0].start
		plan.edits = append(plan.edits, edit{at, at, append(append([]byte(nil), noticeBlock...), ',')})
	}
	return plan, nil
}

// blockText returns the text of one content block: {"type":"text","text":…}
// or {"type":"resource","resource":{"text":…}} in a tool result, or
// {"uri":…,"text":…} in resource contents. Offsets are within raw.
func blockText(raw json.RawMessage, kind detect.Kind) (textAt, bool, error) {
	fs, err := jsonrpc.Object(raw)
	if err != nil {
		return textAt{}, false, err
	}
	base := 0
	if kind == detect.KindToolResult {
		tf, _ := field(fs, "type")
		typ, _ := stringValue(tf.Value)
		switch typ {
		case "text":
		case "resource":
			rf, ok := field(fs, "resource")
			if !ok {
				return textAt{}, false, nil
			}
			if fs, err = jsonrpc.Object(rf.Value); err != nil {
				return textAt{}, false, fmt.Errorf("resource: %w", err)
			}
			base = rf.Start
		default:
			return textAt{}, false, nil // image, audio, resource_link: no text to scan
		}
	}
	f, ok := field(fs, "text")
	if !ok {
		return textAt{}, false, nil
	}
	text, isString := stringValue(f.Value)
	if !isString {
		return textAt{}, false, errors.New("text is not a string")
	}
	return textAt{text: text, start: base + f.Start, end: base + f.End}, true, nil
}
