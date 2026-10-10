package detect

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits of the rules.
const (
	// MaxDescriptionBytes: a longer tool description is "oversized" (low):
	// long descriptions are where poisoning hides, but some real tools are
	// verbose, so it only annotates.
	MaxDescriptionBytes = 4 << 10
	// MaxResultBytes: a longer tool result or resource is "oversized_result".
	MaxResultBytes = 1 << 20
	// base64MinRun is the shortest run of base64 alphabet that is a blob.
	base64MinRun = 200
	// urlQueryMax: a bare URL whose query is longer than this may carry data.
	urlQueryMax = 64
	// maxPerRule caps the findings one rule reports for one text, so a 64 KB
	// wall of "ignore previous instructions" yields 8 findings, not 9000.
	maxPerRule = 8
	// noteMax caps the quoted text in a Finding's Note.
	noteMax = 60
	// minToolName: shorter tool names are never looked for in other texts.
	minToolName = 6
)

// Option configures NewRules.
type Option func(*Rules)

// WithKnownTools tells the scanner which tools each server offers (server
// name -> tool names). A tool description on one server that names a tool
// of ANOTHER server is a cross_tool_reference (shadowing): medium on its own,
// high when the mention sits in an instruction ("when ... send_email",
// "call send_email", or an instruction phrase in the same text). Only
// distinctive names count (see identLike).
func WithKnownTools(tools map[string][]string) Option {
	return func(r *Rules) {
		for server, names := range tools {
			for _, n := range names {
				if identLike(n) {
					r.tools[strings.ToLower(n)] = append(r.tools[strings.ToLower(n)], server)
				}
			}
		}
	}
}

// WithProvisionalNames caps a bare mention of another server's tool at
// medium, even inside an instruction: the scanned server's own list is not
// complete yet (a paged tools/list), so the name may still turn out to be
// its own. Phrases and the shadowing patterns are unaffected.
func WithProvisionalNames() Option {
	return func(r *Rules) { r.provisional = true }
}

// WithServer names the server whose texts are scanned; its own tools are
// not "another server's tool".
func WithServer(name string) Option {
	return func(r *Rules) { r.server = name }
}

// Rules is detection tier 1. It is immutable after NewRules and safe for
// concurrent use; the compiled expressions are shared by every Rules.
type Rules struct {
	server      string
	tools       map[string][]string // lower-case tool name -> servers offering it
	provisional bool                // WithProvisionalNames
}

// NewRules returns the tier-1 scanner. It is cheap: the expressions are
// compiled once per process. It panics if the embedded rule files do not
// compile, which TestRuleFilesCompile catches before any release.
func NewRules(opts ...Option) Scanner {
	if rulesErr != nil {
		panic("detect: embedded rules: " + rulesErr.Error())
	}
	r := &Rules{tools: map[string][]string{}}
	for _, o := range opts {
		o(r)
	}
	return r
}

// identLike reports whether a tool name is distinctive enough to look for:
// at least 6 characters with an underscore, hyphen or dot (send_email,
// list-files, files.read). "search" or "notes" would match ordinary prose.
func identLike(n string) bool {
	return len(n) >= minToolName && strings.ContainsAny(n, "_-.")
}

// Scan runs every rule that applies to kind over text, in one linear pass
// (pass.go) plus a few bytes.Index loops for markup. Findings come out
// in rule order, at most maxPerRule per rule.
func (r *Rules) Scan(kind Kind, text []byte) []Finding {
	s := &scan{kind: kind, text: text, rules: r, count: map[string]int{}}
	s.oversized()
	s.pass()
	if kind != KindToolArgs {
		s.normalised()
	}
	if kind != KindToolArgs {
		s.htmlComments()
		if kind == KindToolDescription && len(r.tools) > 0 {
			s.knownTools()
		}
	}
	return s.out
}

// scan is the state of one Scan call.
type scan struct {
	kind     Kind
	text     []byte
	rules    *Rules
	out      []Finding
	count    map[string]int // findings per rule (maxPerRule)
	oscClear int            // OSC terminator search: none before this offset
}

// add records a finding unless the rule is at its cap or overlaps itself.
func (s *scan) add(id string, sev Severity, start, end int, note string) {
	if s.count[id] >= maxPerRule || s.overlaps(id, start, end) {
		return
	}
	s.count[id]++
	s.out = append(s.out, Finding{ID: id, Severity: sev, Span: [2]int{start, end}, Note: note})
}

// overlaps reports an earlier finding of rule id that overlaps [start, end)
// (at most maxPerRule to look at).
func (s *scan) overlaps(id string, start, end int) bool {
	if s.count[id] == 0 {
		return false
	}
	for _, f := range s.out {
		if f.ID == id && start < f.Span[1] && f.Span[0] < max(end, start+1) {
			return true
		}
	}
	return false
}

// pick chooses a severity by kind: tool description, tool arguments, tool
// result or resource, elicitation text. "" means the rule does not apply.
func (s *scan) pick(desc, args, result, elicit Severity) Severity {
	switch s.kind {
	case KindToolDescription:
		return desc
	case KindToolArgs:
		return args
	case KindToolResult, KindResource:
		return result
	case KindElicitationText:
		return elicit
	}
	return ""
}

// emit is add with a severity from pick; a rule that does not apply to the
// kind ("" severity) is dropped.
func (s *scan) emit(id string, sev Severity, start, end int, note string) {
	if sev != "" {
		s.add(id, sev, start, end, note)
	}
}

func (s *scan) oversized() {
	switch {
	case s.kind == KindToolDescription && len(s.text) > MaxDescriptionBytes:
		s.add(RuleOversized, Medium, 0, len(s.text), "description longer than 4 KiB")
	case (s.kind == KindToolResult || s.kind == KindResource) && len(s.text) > MaxResultBytes:
		s.add(RuleOversizedResult, Low, 0, len(s.text), "result longer than 1 MiB")
	}
}

// quote returns a short printable excerpt of text[start:end] for a Note.
func quote(text []byte, start, end int) string {
	if end-start > noteMax {
		end = start + noteMax
	}
	q := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || !unicode.IsPrint(r) {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(string(text[start:end]), ""))
	if !utf8.ValidString(q) {
		return ""
	}
	return `"` + strings.Join(strings.Fields(q), " ") + `"`
}
