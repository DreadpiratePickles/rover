package daemon

import (
	"errors"
	"fmt"
	"strings"

	"github.com/DreadpiratePickles/rover/internal/detect"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
	"github.com/DreadpiratePickles/rover/internal/policy"
)

// resultPlan is what scanning one server reply decided: findings and the
// edits (absolute in the line) that turn it into what the agent receives.
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

// detectResult scans what a server sends back: tools/call results (text
// blocks and structuredContent; also results answering nothing we know of),
// resources/read contents, prompts/get messages, initialize instructions,
// and the message of an error reply. High: the text is replaced by
// removedText (only that JSON string changes). Medium: a warning. Low:
// findings only. Any finding marks the session saw_untrusted.
//
// The audit entry keeps the original line as its body when bodies are
// logged (review M1: "keep the original in the audit log"); its reason
// holds the SHA-256 of each removed text and of the line as forwarded.
func (s *Server) detectResult(m jsonrpc.Message, replyTo string) judgment {
	var plan resultPlan
	var err error
	switch {
	case m.Kind == jsonrpc.KindError:
		plan, err = planError(m)
	case replyTo == "initialize":
		plan, err = planInstructions(m)
	case replyTo == "prompts/get":
		plan, err = planPrompt(m)
	case replyTo == "resources/read":
		plan, err = planContents(m)
	default:
		plan, err = planToolResult(m)
	}
	if err != nil {
		return rejectResult(m, err)
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
		return rejectResult(m, err)
	}
	j.action, j.audit, j.replacement = ipc.ActionReplace, ipc.ActionReplace, line
	j.reason = plan.reason() + "; forwarded sha256:" + sha(line)
	return j
}

func rejectResult(m jsonrpc.Message, err error) judgment {
	return judgment{
		action: ipc.ActionReplace, audit: ipc.ActionBlock,
		reason:      ReasonResultRejected + ": " + err.Error(),
		replacement: policy.ErrorResponse(m.ID, ReasonResultRejected),
	}
}

// resultObject returns the members of the result, or nil if it is not an
// object (then there is nothing to scan).
func resultObject(m jsonrpc.Message) (jsonrpc.Fields, error) {
	rs, re := m.ResultAt[0], m.ResultAt[1]
	if i := skipSpace(m.Raw, rs, re); i >= re || m.Raw[i] != '{' {
		return nil, nil
	}
	fs, err := splitObject(m.Raw, rs, re)
	if err != nil {
		return nil, fmt.Errorf("result: %w", err) // ambiguous: the client might read another copy
	}
	return fs, nil
}

// scanText scans one JSON string value at f and plans what a high finding
// (replace) or, with prefix, a medium finding (notice in front) does to it.
func (p *resultPlan) scanText(f jsonrpc.Field, kind detect.Kind, prefixOnMedium bool) error {
	text, ok := textValue(f.Value)
	if !ok {
		return errors.New(f.Key + " is not a string")
	}
	fs := detect.NewRules().Scan(kind, text)
	p.findings = append(p.findings, fs...)
	switch detect.Max(fs) {
	case detect.High:
		p.edits = append(p.edits, edit{f.Start, f.End, mustJSON(removedText(detect.Score(fs).IDs))})
		p.removed = append(p.removed, sha(text))
	case detect.Medium:
		if prefixOnMedium {
			p.edits = append(p.edits, edit{f.Start, f.End, mustJSON(UntrustedNotice + "\n\n" + string(text))})
		}
		p.warned = true
	}
	return nil
}

// blockTextField finds the text of one content block: {"type":"text",
// "text":…} or {"type":"resource","resource":{"text":…}}.
func blockTextField(b []byte, at [2]int) (jsonrpc.Field, bool, error) {
	fs, err := splitObject(b, at[0], at[1])
	if err != nil {
		return jsonrpc.Field{}, false, err
	}
	tf, _ := field(fs, "type")
	typ, _ := stringValue(tf.Value)
	switch typ {
	case "text":
	case "resource":
		rf, ok := field(fs, "resource")
		if !ok {
			return jsonrpc.Field{}, false, nil
		}
		if fs, err = splitObject(b, rf.Start, rf.End); err != nil {
			return jsonrpc.Field{}, false, fmt.Errorf("resource: %w", err)
		}
	default:
		return jsonrpc.Field{}, false, nil // image, audio, resource_link: no text
	}
	f, ok := field(fs, "text")
	return f, ok, nil
}

// planToolResult: content blocks, then structuredContent (review M3). A
// high finding in structuredContent replaces the whole result, because the
// client may show either; medium adds the warning block.
func planToolResult(m jsonrpc.Message) (resultPlan, error) {
	var plan resultPlan
	b := m.Raw
	fs, err := resultObject(m)
	if err != nil || fs == nil {
		return plan, err
	}
	cf, hasContent := field(fs, "content")
	var els [][2]int
	if hasContent {
		if els, err = splitArray(b, cf.Start, cf.End); err != nil {
			return plan, fmt.Errorf("content: %w", err)
		}
	}
	for i, el := range els {
		f, ok, err := blockTextField(b, el)
		if err != nil {
			return plan, fmt.Errorf("content[%d]: %w", i, err)
		}
		if ok {
			if err := plan.scanText(f, detect.KindToolResult, false); err != nil {
				return plan, fmt.Errorf("content[%d]: %w", i, err)
			}
		}
	}
	if sc, ok := field(fs, "structuredContent"); ok {
		text, err := decodedText(m.Raw, sc.Start, sc.End)
		if err != nil {
			return plan, fmt.Errorf("structuredContent: %w", err)
		}
		found := detect.NewRules().Scan(detect.KindToolResult, text)
		plan.findings = append(plan.findings, found...)
		switch detect.Max(found) {
		case detect.High:
			whole := `{"content":[{"type":"text","text":` + string(mustJSON(removedText(detect.Score(found).IDs))) + `}],"isError":false}`
			plan.edits, plan.warned = []edit{{m.ResultAt[0], m.ResultAt[1], []byte(whole)}}, false
			plan.removed = append(plan.removed, sha(sc.Value))
			return plan, nil
		case detect.Medium:
			plan.warned = true
		}
	}
	if plan.warned {
		switch {
		case len(els) > 0:
			plan.edits = append(plan.edits, edit{els[0][0], els[0][0], append(append([]byte(nil), noticeBlock...), ',')})
		case hasContent:
			at := skipSpace(b, cf.Start, cf.End) + 1 // just inside "["
			plan.edits = append(plan.edits, edit{at, at, noticeBlock})
		default:
			at := skipSpace(b, m.ResultAt[0], m.ResultAt[1]) + 1 // just inside "{"
			plan.edits = append(plan.edits, edit{at, at, []byte(`"content":[` + string(noticeBlock) + `],`)})
		}
	}
	return plan, nil
}

// planContents: resources/read contents, each {"uri":…,"text":…}. Every
// entry must carry a uri, so a warning goes in front of the text itself.
func planContents(m jsonrpc.Message) (resultPlan, error) {
	var plan resultPlan
	fs, err := resultObject(m)
	if err != nil || fs == nil {
		return plan, err
	}
	cf, ok := field(fs, "contents")
	if !ok {
		return plan, nil
	}
	els, err := splitArray(m.Raw, cf.Start, cf.End)
	if err != nil {
		return plan, fmt.Errorf("contents: %w", err)
	}
	for i, el := range els {
		ef, err := splitObject(m.Raw, el[0], el[1])
		if err != nil {
			return plan, fmt.Errorf("contents[%d]: %w", i, err)
		}
		if f, ok := field(ef, "text"); ok {
			if err := plan.scanText(f, detect.KindResource, true); err != nil {
				return plan, fmt.Errorf("contents[%d]: %w", i, err)
			}
		}
	}
	return plan, nil
}

// planPrompt: prompts/get messages, each {"role":…,"content":<block>}.
func planPrompt(m jsonrpc.Message) (resultPlan, error) {
	var plan resultPlan
	fs, err := resultObject(m)
	if err != nil || fs == nil {
		return plan, err
	}
	mf, ok := field(fs, "messages")
	if !ok {
		return plan, nil
	}
	els, err := splitArray(m.Raw, mf.Start, mf.End)
	if err != nil {
		return plan, fmt.Errorf("messages: %w", err)
	}
	for i, el := range els {
		ef, err := splitObject(m.Raw, el[0], el[1])
		if err != nil {
			return plan, fmt.Errorf("messages[%d]: %w", i, err)
		}
		cf, ok := field(ef, "content")
		if !ok {
			continue
		}
		f, ok, err := blockTextField(m.Raw, [2]int{cf.Start, cf.End})
		if err != nil {
			return plan, fmt.Errorf("messages[%d]: %w", i, err)
		}
		if ok {
			if err := plan.scanText(f, detect.KindToolResult, true); err != nil {
				return plan, fmt.Errorf("messages[%d]: %w", i, err)
			}
		}
	}
	return plan, nil
}

// planInstructions: the initialize result's "instructions", which the
// client may put in the model's system prompt; scanned like a description.
func planInstructions(m jsonrpc.Message) (resultPlan, error) {
	var plan resultPlan
	fs, err := resultObject(m)
	if err != nil || fs == nil {
		return plan, err
	}
	if f, ok := field(fs, "instructions"); ok {
		err = plan.scanText(f, detect.KindToolDescription, false)
	}
	plan.warned = false // a warning has nowhere to go: findings only below high
	return plan, err
}

// planError: the "message" of a server's error reply.
func planError(m jsonrpc.Message) (resultPlan, error) {
	var plan resultPlan
	fs, err := splitObject(m.Raw, m.ErrorAt[0], m.ErrorAt[1])
	if err != nil {
		return plan, fmt.Errorf("error: %w", err)
	}
	if f, ok := field(fs, "message"); ok {
		err = plan.scanText(f, detect.KindToolResult, false)
	}
	plan.warned = false
	return plan, err
}
