package detect

import (
	"fmt"
	"unicode/utf8"
)

// Characters a human does not see but a model reads.
//
//   - Unicode tag characters (U+E0000-E007F) mirror ASCII invisibly: a whole
//     sentence can ride along after a visible word ("ASCII smuggling").
//   - Zero-width characters (U+200B-200F, U+2060, U+FEFF) can split a
//     phrase so a filter misses it, or encode bits.
//   - Bidi overrides (U+202A-202E, U+2066-2069) make text display in a
//     different order than it is read ("Trojan Source").
//   - ANSI escapes can hide text in a terminal (conceal, cursor moves,
//     window-title sequences).
const (
	zwStrongCount = 3 // zero-width characters in a result before it is high
	runGap        = 8 // bytes between hits that still count as one run
	flagTagMax    = 8 // tag characters in an emoji subdivision flag
	blackFlag     = 0x1F3F4
	tagCancel     = 0xE007F
	csiC1         = 0x9B
	maxOSCBytes   = 4096 // how far to look for the end of an OSC sequence
)

// run collects nearby hits of one character class into one finding.
type run struct {
	start, end, n int
}

type runs struct {
	list  []run
	total int
}

func (r *runs) hit(start, end int) {
	r.total++
	if k := len(r.list) - 1; k >= 0 && start-r.list[k].end <= runGap {
		r.list[k].end, r.list[k].n = end, r.list[k].n+1
		return
	}
	if len(r.list) < maxPerRule {
		r.list = append(r.list, run{start, end, 1})
	}
}

func isZeroWidth(r rune) bool {
	return r >= 0x200B && r <= 0x200F || r == 0x2060 || r == 0xFEFF
}

func isBidi(r rune) bool {
	return r >= 0x202A && r <= 0x202E || r >= 0x2066 && r <= 0x2069 || r == 0x061C
}

// isC1 reports a C1 control character (U+0080-U+009F): terminals act on
// some of them (U+009B starts a control sequence), none belongs in text.
func isC1(r rune) bool { return r >= 0x80 && r <= 0x9F }

// softHyphen is invisible unless a line breaks at it.
const softHyphen = 0x00AD

func isTag(r rune) bool { return r >= 0xE0000 && r <= 0xE007F }

func isB64(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/'
}

// tagState collects tag characters. Emoji subdivision flags (England,
// Scotland, Wales) are U+1F3F4, a few tags, then U+E007F: legitimate. Tags
// right after U+1F3F4 are held until the run shows whether it is such a
// flag; anything else is committed.
type tagState struct {
	runs   runs
	held   [][2]int
	inFlag bool
}

func (ts *tagState) hit(r, prev rune, start, end int) {
	if !isTag(prev) {
		ts.end()
		ts.inFlag = prev == blackFlag
	}
	if !ts.inFlag {
		ts.runs.hit(start, end)
		return
	}
	ts.held = append(ts.held, [2]int{start, end})
	switch {
	case r == tagCancel && len(ts.held) <= flagTagMax:
		ts.held, ts.inFlag = ts.held[:0], false // a flag: forget it
	case r == tagCancel || len(ts.held) > flagTagMax:
		ts.end()
	}
}

// end commits held tags (the run was not a flag after all).
func (ts *tagState) end() {
	for _, h := range ts.held {
		ts.runs.hit(h[0], h[1])
	}
	ts.held, ts.inFlag = ts.held[:0], false
}

// countZeroWidth decides whether one zero-width character counts. U+200C-200F
// (joiners and direction marks) are legitimate between two visible non-ASCII
// characters: emoji ZWJ sequences, Persian and Indic scripts, Arabic and
// Hebrew text. Anywhere else, and U+200B, U+2060, U+FEFF (except a leading
// byte-order mark) always, they count.
func (s *scan) countZeroWidth(r, prev rune, i, size int) bool {
	if r == 0xFEFF && i == 0 {
		return false
	}
	if r < 0x200C || r > 0x200F {
		return true
	}
	next, _ := utf8.DecodeRune(s.text[i+size:])
	visible := func(x rune) bool {
		return x >= utf8.RuneSelf && x != utf8.RuneError && !isZeroWidth(x) && !isBidi(x) && !isTag(x)
	}
	return !visible(prev) || !visible(next)
}

func (s *scan) flushRuns(id string, r runs, sev Severity, what string) {
	for _, x := range r.list {
		s.emit(id, sev, x.start, x.end, fmt.Sprintf("%d %s (%d in the text)", x.n, what, r.total))
	}
}

// Base64 character classes; a blob must mix all three, so long hex
// digests, words and paths do not count.
const (
	b64Upper = 1 << iota
	b64Lower
	b64Digit
	b64All = b64Upper | b64Lower | b64Digit
)

func b64Class(c byte) int {
	switch {
	case c >= 'A' && c <= 'Z':
		return b64Upper
	case c >= 'a' && c <= 'z':
		return b64Lower
	case c >= '0' && c <= '9':
		return b64Digit
	}
	return 0
}

// blob reports a run of at least base64MinRun base64 characters.
func (s *scan) blob(start, end int) {
	s.emit(RuleBase64Blob, s.pick(Medium, "", Medium, Medium), start, end, fmt.Sprintf("%d characters of base64", end-start))
}

// ansi handles the escape sequence at i and returns the index after it.
// Plain colours (SGR without "conceal") are the weak variant: build logs are
// full of them. Cursor moves, erases, conceal and OSC (window title,
// hyperlinks) can hide or rewrite what a human sees: the strong variant.
func (s *scan) ansi(i int) int {
	t := s.text
	j := i + 1
	strong, what := true, "escape sequence"
	switch {
	case j < len(t) && t[j] == '[':
		j++
		p := j
		for j < len(t) && t[j] >= 0x30 && t[j] <= 0x3F {
			j++
		}
		params := t[p:j]
		for j < len(t) && t[j] >= 0x20 && t[j] <= 0x2F {
			j++
		}
		if j < len(t) && t[j] >= 0x40 && t[j] <= 0x7E {
			if t[j] == 'm' && !hasParam(params, "8") {
				strong, what = false, "colour sequence"
			} else {
				what = "CSI " + string(t[j]) + " sequence"
			}
			j++
		}
	case j < len(t) && t[j] == ']':
		// The payload (a window title, a link) is text: report the whole
		// sequence, but let the pass read the payload's words.
		// s.oscClear: no terminator before it, from an earlier search, so
		// a wall of "ESC ]" is searched once, not once per sequence.
		end, limit := max(j, s.oscClear), min(len(t), j+maxOSCBytes)
		for end < limit && t[end] != 0x07 && !oscST(t, end) {
			end++
		}
		s.oscClear = max(s.oscClear, end)
		s.emit(RuleANSIEscape, s.pick(High, Medium, High, High), i, min(end+1, len(t)), "OSC sequence")
		return j + 1
	case j < len(t):
		j++
	default:
		strong, what = false, "lone ESC"
	}
	sev := s.pick(High, Medium, Low, High)
	if strong {
		sev = s.pick(High, Medium, High, High)
	}
	s.emit(RuleANSIEscape, sev, i, j, what)
	return j
}

// csiEnd returns the index after the parameters, intermediates and final
// byte of a control sequence whose body starts at j.
func csiEnd(t []byte, j int) int {
	for j < len(t) && t[j] >= 0x20 && t[j] <= 0x3F {
		j++
	}
	if j < len(t) && t[j] >= 0x40 && t[j] <= 0x7E {
		j++
	}
	return j
}

// oscST reports the string terminator ESC \ at i.
func oscST(t []byte, i int) bool {
	return t[i] == 0x1b && i+1 < len(t) && t[i+1] == '\\'
}

// hasParam reports whether the ;-separated SGR parameters include p.
func hasParam(params []byte, p string) bool {
	start := 0
	for k := 0; k <= len(params); k++ {
		if k == len(params) || params[k] == ';' {
			if string(params[start:k]) == p {
				return true
			}
			start = k + 1
		}
	}
	return false
}
