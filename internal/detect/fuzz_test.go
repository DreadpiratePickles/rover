package detect

import (
	"testing"
	"unicode/utf8"
)

// FuzzScan checks that no input makes Scan panic, report a span outside
// the text, an unknown rule or severity, or more findings than the caps
// allow. (Time is bounded by construction, see TestWorstCaseInputsStayLinear.)
func FuzzScan(f *testing.F) {
	seeds := []string{
		"", "plain", "<IMPORTANT>do it</IMPORTANT>", "ignore previous instructions",
		"\x1b[8mx\x1b]0;t\x07", "![a](https://e.x/?d=1)", "[a](http://e?x=1", "<!--", "~/.ssh/id_rsa .env",
		"a\u200bb\u202ec\U000E0041", "\U0001F3F4\U000E0067\U000E007F", "<p hidden>x", "display:none", "\xff\xfe\xc2\x9b",
	}
	var kind byte // cycles through the kinds
	for _, s := range seeds {
		f.Add(kind, []byte(s))
		if kind++; int(kind) == len(Kinds) {
			kind = 0
		}
	}
	known := map[string]bool{}
	for _, id := range RuleIDs {
		known[id] = true
	}
	sc := NewRules(WithKnownTools(map[string][]string{"other": {"send_email", "getWeather"}}), WithServer("me"))
	f.Fuzz(func(t *testing.T, k uint8, text []byte) {
		kind := Kinds[int(k)%len(Kinds)]
		fs := sc.Scan(kind, text)
		if len(fs) > len(RuleIDs)*maxPerRule {
			t.Fatalf("%d findings", len(fs))
		}
		for _, f := range fs {
			if !known[f.ID] || f.Severity.Score() == 0 {
				t.Fatalf("bad finding %+v", f)
			}
			if f.Span[0] < 0 || f.Span[0] > f.Span[1] || f.Span[1] > len(text) {
				t.Fatalf("span %v outside %d bytes", f.Span, len(text))
			}
			if !utf8.ValidString(f.Note) {
				t.Fatalf("note is not UTF-8: %q", f.Note)
			}
		}
	})
}
