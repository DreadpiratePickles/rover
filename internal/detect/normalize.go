package detect

import (
	"bytes"
	"html"
	"sort"
	"unicode/utf8"
)

// Cheap disguises for a phrase: "ig\u200bnore", "ig\u00adnore",
// "**ignore** *pre*vious", "&lt;IMPORTANT&gt;", "ignore previous". The
// pass reads the text as it is; normalised() reads it once more with these
// undone and maps what it finds back to the original offsets.
const maxEntity = 10 // longest HTML entity looked at, "&#x1F600;" fits

// disguises are the invisible and space-like characters normalise removes
// or turns into a space; a text with none of them, no entity and no
// emphasis character needs no second look.
var disguises = [][]byte{
	[]byte("\u200b"), []byte("\u200c"), []byte("\u200d"), []byte("\u2060"), []byte("\ufeff"),
	[]byte("\u00ad"), []byte("\u00a0"), []byte("\u2007"), []byte("\u202f"),
}

func needsNormalising(t []byte) bool {
	for _, d := range disguises {
		if bytes.Contains(t, d) {
			return true
		}
	}
	return insideWord(t, '*') || insideWord(t, '_') || insideWord(t, '`') || hasEntity(t)
}

// insideWord reports c between two letters or digits somewhere in t
// ("ig*no*re"). Emphasis around a word ("`make test`") does not split it.
func insideWord(t []byte, c byte) bool {
	alnum := func(b byte) bool { return isWordByte(b|0x20) && b != '_' }
	for off := 0; ; {
		i := bytes.IndexByte(t[off:], c)
		if i < 0 {
			return false
		}
		i += off
		if i > 0 && i+1 < len(t) && alnum(t[i-1]) && alnum(t[i+1]) {
			return true
		}
		off = i + 1
	}
}

// hasEntity reports something like an HTML entity: "&", letters, digits or
// "#", then ";" ("&lt;", "&#32;"; not the "&page=2" of a URL).
func hasEntity(t []byte) bool {
	for off := 0; ; {
		i := bytes.IndexByte(t[off:], '&')
		if i < 0 {
			return false
		}
		i += off
		j := i + 1
		for j < len(t) && j-i < maxEntity && (t[j] == '#' || isWordByte(t[j]|0x20)) {
			j++
		}
		if j > i+1 && j < len(t) && t[j] == ';' {
			return true
		}
		off = i + 1
	}
}

// special marks the bytes where normalise may change something.
var special = func() (t [256]bool) {
	for _, c := range []byte{'*', '_', '`', '&', 0xC2, 0xE2, 0xEF} {
		t[c] = true
	}
	return t
}()

// normalise returns t without zero-width characters, soft hyphens and
// markdown emphasis characters (* _ `), with HTML entities decoded and
// NBSP, U+2007 and U+202F turned into spaces. at maps it back: the byte
// norm[k] came from t[k+delta], where delta is that of the last breakpoint
// at or before k (see origin).
func normalise(t []byte) (norm []byte, at []breakpoint) {
	norm = make([]byte, 0, len(t))
	at = []breakpoint{{0, 0}}
	mark := func(orig int) { at = append(at, breakpoint{len(norm), orig - len(norm)}) }
	for i := 0; i < len(t); {
		j := i
		for j < len(t) && !special[t[j]] {
			j++
		}
		norm = append(norm, t[i:j]...)
		if i = j; i >= len(t) {
			break
		}
		c := t[i]
		switch {
		case c == '*' || c == '_' || c == '`':
			i++
			mark(i)
			continue
		case c == '&':
			if k := bytes.IndexByte(t[i:min(len(t), i+maxEntity)], ';'); k > 1 {
				ent := string(t[i : i+k+1])
				if dec := html.UnescapeString(ent); dec != ent {
					if r, _ := utf8.DecodeRuneInString(dec); isSpaceRune(r) {
						dec = " "
					}
					for _, b := range []byte(dec) {
						mark(i)
						norm = append(norm, b)
					}
					i += k + 1
					mark(i)
					continue
				}
			}
		case c >= utf8.RuneSelf:
			r, size := utf8.DecodeRune(t[i:])
			switch {
			case r >= 0x200B && r <= 0x200D || r == 0x2060 || r == 0xFEFF || r == softHyphen:
				i += size
				mark(i)
				continue
			case isSpaceRune(r):
				mark(i)
				norm = append(norm, ' ')
				i += size
				mark(i)
				continue
			}
			norm = append(norm, t[i:i+size]...)
			i += size
			continue
		}
		norm = append(norm, c)
		i++
	}
	return norm, at
}

// breakpoint: from norm offset n on, the original offset is n+delta.
type breakpoint struct{ n, delta int }

// origin maps a normalised offset back to the original text.
func origin(at []breakpoint, n int) int {
	k := sort.Search(len(at), func(i int) bool { return at[i].n > n }) - 1
	return n + at[k].delta
}

// isSpaceRune: the no-break spaces that should separate words like a space.
func isSpaceRune(r rune) bool { return r == 0xA0 || r == 0x2007 || r == 0x202F }

// fromNormalised are the rules worth running on the normalised text.
var fromNormalised = map[string]bool{RuleInstruction: true, RuleCrossTool: true, RuleHiddenMarkup: true, RuleSensitivePath: true}

// normalised reads the text once more with the disguises undone, if there
// were any, and keeps the word rules' findings at their original offsets.
// A finding the first pass already made is not repeated.
func (s *scan) normalised() {
	if !needsNormalising(s.text) {
		return
	}
	norm, at := normalise(s.text)
	if bytes.Equal(norm, s.text) {
		return
	}
	sub := &scan{kind: s.kind, text: norm, rules: s.rules, count: map[string]int{}}
	sub.words()
	for _, f := range sub.out {
		if !fromNormalised[f.ID] {
			continue
		}
		start := origin(at, f.Span[0])
		end := start
		if f.Span[1] > f.Span[0] {
			end = origin(at, f.Span[1]-1) + 1 // just after the last byte
		}
		s.add(f.ID, f.Severity, start, end, f.Note)
	}
}

// words is the word part of pass alone: tokens through the filter to token.
func (s *scan) words() {
	t := s.text
	filter, ends := textFilter, textEnds
	ws, key, last := -1, 0, 0
	for i := 0; i <= len(t); i++ {
		lc := byte(' ')
		if i < len(t) {
			lc = t[i]
			if 'A' <= lc && lc <= 'Z' {
				lc += 'a' - 'A'
			}
		}
		if isWordByte(lc) {
			last = wordCode(lc)
			switch {
			case ws < 0:
				ws, key = i, wordCode(lc)*wordAlphabet
			case i == ws+1:
				key += wordCode(lc)
			}
			continue
		}
		if ws < 0 {
			continue
		}
		if n := i - ws; n >= 2 && n < maxTokenLen &&
			filter[(key*maxTokenLen+n)/64]&(1<<((key*maxTokenLen+n)%64)) != 0 &&
			ends[(last*maxTokenLen+n)/64]&(1<<((last*maxTokenLen+n)%64)) != 0 {
			s.token(ws, i)
		}
		ws = -1
	}
}
