// Package detect is Rover's detection tier 1 (plan §6 M5, D7): fast local
// rules that look for prompt injection, tool poisoning and data exfiltration
// in text an MCP server hands to the agent. No data leaves the machine and
// there is no model: every rule is a character class, a word lookup or a
// short regular expression.
//
// LESSON (M5): rules are cheap, explainable and always on, but they only
// catch what someone thought of. A paraphrase ("pay no attention to what you
// were told earlier") walks straight past the phrase list. Tiers 2 (a local
// classifier) and 3 (an LLM judge) arrive in M12; until then tier 1 is a
// tripwire, not a wall, and the policy (M2) and pins (M4) still apply.
package detect

import (
	"sort"
)

// Kind says where a text came from; the same rule can be more or less
// suspicious depending on it.
type Kind string

// The kinds of text Rover scans.
const (
	KindToolDescription Kind = "tool_description" // a tool's name, description, schema descriptions
	KindToolArgs        Kind = "tool_args"        // string arguments of a tools/call
	KindToolResult      Kind = "tool_result"      // a text block of a tools/call result
	KindResource        Kind = "resource"         // text of a resources/read result
	KindElicitationText Kind = "elicitation_text" // server-initiated elicitation or sampling text
)

// Kinds lists every kind, in a stable order.
var Kinds = []Kind{KindToolDescription, KindToolArgs, KindToolResult, KindResource, KindElicitationText}

// Valid reports whether k is one of Kinds.
func (k Kind) Valid() bool {
	for _, v := range Kinds {
		if k == v {
			return true
		}
	}
	return false
}

// Severity is how sure a finding is, and so what Rover does about it.
type Severity string

// Severities, weakest first.
const (
	Low    Severity = "low"
	Medium Severity = "medium"
	High   Severity = "high"
)

// Score values of each severity (context.detection.max_score).
const (
	ScoreHigh   int64 = 90
	ScoreMedium int64 = 50
	ScoreLow    int64 = 10
)

// Score is the numeric value of a severity.
func (s Severity) Score() int64 {
	switch s {
	case High:
		return ScoreHigh
	case Medium:
		return ScoreMedium
	case Low:
		return ScoreLow
	}
	return 0
}

// Rule ids. They are stable strings: audit entries and policies
// (context.detection.findings) refer to them.
const (
	RuleUnicodeTags     = "unicode_tags"
	RuleZeroWidth       = "zero_width"
	RuleBidiOverride    = "bidi_override"
	RuleANSIEscape      = "ansi_escape"
	RuleHTMLComment     = "html_comment"
	RuleHiddenMarkup    = "hidden_markup"
	RuleInstruction     = "instruction_phrase"
	RuleSensitivePath   = "sensitive_path"
	RuleCrossTool       = "cross_tool_reference"
	RuleMarkdownExfil   = "markdown_exfil_url"
	RuleBase64Blob      = "base64_blob"
	RuleOversized       = "oversized"
	RuleOversizedResult = "oversized_result"
)

// RuleIDs lists every rule id.
var RuleIDs = []string{
	RuleUnicodeTags, RuleZeroWidth, RuleBidiOverride, RuleANSIEscape, RuleHTMLComment,
	RuleHiddenMarkup, RuleInstruction, RuleSensitivePath, RuleCrossTool, RuleMarkdownExfil,
	RuleBase64Blob, RuleOversized, RuleOversizedResult,
}

// Finding is one rule firing on one place in a text.
type Finding struct {
	ID       string
	Severity Severity
	Span     [2]int // byte offsets [start, end) into the scanned text
	Note     string // a short human explanation; may quote (sanitised) text
}

// Scanner scans one text of one kind.
type Scanner interface {
	Scan(kind Kind, text []byte) []Finding
}

// Summary is the policy's view of a set of findings: context.detection.
type Summary struct {
	MaxScore int64
	IDs      []string // sorted, unique
}

// Score summarises findings: the highest severity's score and the ids.
func Score(fs []Finding) Summary {
	var s Summary
	seen := map[string]bool{}
	for _, f := range fs {
		if v := f.Severity.Score(); v > s.MaxScore {
			s.MaxScore = v
		}
		if !seen[f.ID] {
			seen[f.ID] = true
			s.IDs = append(s.IDs, f.ID)
		}
	}
	sort.Strings(s.IDs)
	return s
}

// Max returns the highest severity among fs, or "" for none.
func Max(fs []Finding) Severity {
	var best Severity
	for _, f := range fs {
		if f.Severity.Score() > best.Score() {
			best = f.Severity
		}
	}
	return best
}
