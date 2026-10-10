package detect

import (
	"unicode/utf8"
)

// pass is the single linear pass over the text. Every byte is loaded once:
// tokens (words), invisible characters, ANSI escapes and base64 runs are
// tracked in registers, and only rare events (a non-ASCII rune, an ESC, a
// word that may start a rule) touch memory again. That matters under the
// race detector, which makes every memory access about ten times slower.
func (s *scan) pass() {
	t := s.text
	filter, ends := textFilter, textEnds // local copies: stack reads are not instrumented
	if s.kind == KindToolArgs {
		filter, ends = argsFilter, argsEnds
	}
	var zw, bidi runs
	tags := tagState{}
	var prev rune = -1
	ws, key, last := -1, 0, 0 // current word: start, key of its first two letters, last letter
	b64Start, b64Mix, b64Len := -1, 0, 0
	w, wi := uint64(0), -8 // w holds t[wi:wi+8], read in one access
	inURL, url := false, urlState{}
	urlsOn := s.kind != KindToolArgs
	for i := 0; i < len(t); {
		var c byte
		switch {
		case i-wi < 8:
			c = byte(w >> (8 * (i - wi)) & 0xff)
		case i+8 <= len(t):
			w, wi = load8(t, i), i
			c = byte(w & 0xff)
		default:
			c = t[i]
		}
		lc := c
		if 'A' <= c && c <= 'Z' {
			lc += 'a' - 'A'
		}
		// URLs: track the query of the URL we are in (urls.go).
		if inURL {
			switch {
			case isURLEnd(c) || i-url.start >= maxURLBytes:
				s.endURL(url, i)
				inURL = false
			case c == '?' && url.query < 0:
				url.query = i
			case c == '#' && url.hash < 0:
				url.hash = i
			}
		}
		// "](//host/...": a protocol-relative markdown target.
		if c == '(' && prev == ']' && !inURL && urlsOn && s.at(i+1, "//") {
			url, inURL = urlState{start: i + 1, query: -1, hash: -1, markdown: true}, true
			prev = rune(c)
			i++
			continue
		}
		// Words: start, extend, or end (and maybe look closer).
		if isWordByte(lc) {
			last = wordCode(lc)
			switch {
			case ws < 0:
				ws, key = i, wordCode(lc)*wordAlphabet
			case i == ws+1:
				key += wordCode(lc)
			}
		} else if ws >= 0 {
			if n := i - ws; n >= 2 && n < maxTokenLen &&
				filter[(key*maxTokenLen+n)/64]&(1<<((key*maxTokenLen+n)%64)) != 0 &&
				ends[(last*maxTokenLen+n)/64]&(1<<((last*maxTokenLen+n)%64)) != 0 {
				s.token(ws, i)
			}
			if c == ':' && urlsOn && !inURL && key == wordCode('h')*wordAlphabet+wordCode('t') {
				url, inURL = s.startURL(ws, i)
			}
			ws = -1
		}
		// Base64 runs: alphabet only, mixing upper, lower and digits.
		switch {
		case isB64(c):
			if b64Start < 0 {
				b64Start, b64Mix, b64Len = i, 0, 0
			}
			b64Mix |= b64Class(c)
			b64Len++
		case c == '\r' || c == '\n':
			// a blob may be wrapped over lines (MIME style)
		case b64Start >= 0:
			if b64Len >= base64MinRun && b64Mix == b64All {
				s.blob(b64Start, i)
			}
			b64Start = -1
		}
		if c >= utf8.RuneSelf {
			r, size := utf8.DecodeRune(t[i:])
			s.rune(r, prev, i, size, &tags, &zw, &bidi)
			prev = r
			i += size
			if r == csiC1 {
				i = csiEnd(t, i) // its parameters are not words: "\u009b2Kignore"
			}
			continue
		}
		if len(tags.held) > 0 {
			tags.end()
		}
		prev = rune(c)
		if c == 0x1b {
			i = s.ansi(i)
			continue
		}
		i++
	}
	if inURL {
		s.endURL(url, len(t))
	}
	if ws >= 0 && len(t)-ws >= 2 && len(t)-ws < maxTokenLen {
		s.token(ws, len(t))
	}
	if b64Start >= 0 && b64Len >= base64MinRun && b64Mix == b64All {
		s.blob(b64Start, len(t))
	}
	tags.end()
	s.flushRuns(RuleUnicodeTags, tags.runs, s.pick(High, High, High, High), "Unicode tag characters (invisible ASCII)")
	zwSev := s.pick(High, Low, Low, Low)
	if zw.total >= zwStrongCount {
		zwSev = s.pick(High, Low, High, High)
	}
	s.flushRuns(RuleZeroWidth, zw, zwSev, "zero-width characters")
	s.flushRuns(RuleBidiOverride, bidi, s.pick(High, Medium, High, High), "bidirectional override characters")
}

// rune classifies one non-ASCII rune.
func (s *scan) rune(r, prev rune, i, size int, tags *tagState, zw, bidi *runs) {
	if !isTag(r) {
		tags.end()
	}
	switch {
	case isTag(r):
		tags.hit(r, prev, i, i+size)
	case isZeroWidth(r):
		if s.countZeroWidth(r, prev, i, size) {
			zw.hit(i, i+size)
		}
	case isBidi(r):
		bidi.hit(i, i+size)
	case isC1(r):
		s.emit(RuleANSIEscape, s.pick(High, Medium, High, High), i, i+size, "C1 control character")
	}
	if (r >= 0x200B && r <= 0x200D || r == 0x2060 || r == 0xFEFF || r == softHyphen) && s.insideWord(prev, i+size) {
		s.emit(RuleHiddenText, s.pick(High, "", Medium, Medium), i, i+size, "invisible character inside a word")
	}
}

// insideWord reports an invisible character between two ASCII letters or
// digits ("norm\u200bal"): it splits a word so a filter misses it.
func (s *scan) insideWord(prev rune, next int) bool {
	alnum := func(c rune) bool { return c < 0x80 && isWordByte(byte((c | 0x20) & 0xff)) && c != '_' }
	return alnum(prev) && next < len(s.text) && alnum(rune(s.text[next]))
}
