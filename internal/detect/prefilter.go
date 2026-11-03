package detect

import (
	"regexp/syntax"
	"unicode/utf8"
)

// nextBytes works out which bytes can follow the first n runes (the
// literal prefix up to the end of the anchor word) of the expression line,
// optionally after white space. It returns nil when it cannot tell, and the
// rule then always runs its regexp: the prefilter may only skip work, never
// change a result.
func nextBytes(line string, n int) (*[256]bool, bool) {
	re, err := syntax.Parse(line, syntax.Perl)
	if err != nil {
		return nil, false
	}
	re = re.Simplify()
	subs := []*syntax.Regexp{re}
	if re.Op == syntax.OpConcat {
		subs = re.Sub
	}
	i := 0
	for ; i < len(subs) && n > 0; i++ {
		if subs[i].Op != syntax.OpLiteral || subs[i].Flags&syntax.FoldCase != 0 {
			return nil, false
		}
		if lit := subs[i].Rune; len(lit) > n {
			var set [256]bool
			addRune(&set, lit[n])
			return &set, false
		}
		n -= len(subs[i].Rune)
	}
	if n > 0 {
		return nil, false
	}
	rest := subs[i:]
	skipWS := len(rest) > 0 && isSpaceRepeat(rest[0])
	if skipWS {
		rest = rest[1:]
	}
	set, nullable := firstOfConcat(rest)
	if nullable {
		return nil, false
	}
	return set, skipWS
}

// isSpaceRepeat reports \s+ or \s*.
func isSpaceRepeat(re *syntax.Regexp) bool {
	if (re.Op != syntax.OpPlus && re.Op != syntax.OpStar) || re.Sub[0].Op != syntax.OpCharClass {
		return false
	}
	for _, r := range re.Sub[0].Rune {
		if r < 0 || r > ' ' || !isSpace(byte(r)) {
			return false
		}
	}
	return true
}

func addRune(set *[256]bool, r rune) {
	var b [utf8.UTFMax]byte
	utf8.EncodeRune(b[:], r)
	set[b[0]] = true
}

// addRange adds the first bytes of every rune in [lo, hi].
func addRange(set *[256]bool, lo, hi rune) {
	for r := lo; r <= hi && r < utf8.RuneSelf; r++ {
		set[r] = true
	}
	if hi >= utf8.RuneSelf {
		for b := 0xC0; b < 0x100; b++ {
			set[b] = true
		}
	}
}

func firstOfConcat(subs []*syntax.Regexp) (*[256]bool, bool) {
	var set [256]bool
	for _, sub := range subs {
		f, nullable := first(sub)
		for b, ok := range f {
			set[b] = set[b] || ok
		}
		if !nullable {
			return &set, false
		}
	}
	return &set, true
}

// first returns the bytes a match of re can start with, and whether re can
// match the empty string.
func first(re *syntax.Regexp) ([256]bool, bool) {
	var set [256]bool
	switch re.Op {
	case syntax.OpLiteral:
		if len(re.Rune) == 0 || re.Flags&syntax.FoldCase != 0 {
			return all(), true
		}
		addRune(&set, re.Rune[0])
		return set, false
	case syntax.OpCharClass:
		for k := 0; k+1 < len(re.Rune); k += 2 {
			addRange(&set, re.Rune[k], re.Rune[k+1])
		}
		return set, false
	case syntax.OpCapture:
		return first(re.Sub[0])
	case syntax.OpConcat:
		p, nullable := firstOfConcat(re.Sub)
		return *p, nullable
	case syntax.OpAlternate:
		nullable := false
		for _, sub := range re.Sub {
			f, n := first(sub)
			for b, ok := range f {
				set[b] = set[b] || ok
			}
			nullable = nullable || n
		}
		return set, nullable
	case syntax.OpStar, syntax.OpQuest:
		f, _ := first(re.Sub[0])
		return f, true
	case syntax.OpPlus:
		return first(re.Sub[0])
	case syntax.OpRepeat:
		f, n := first(re.Sub[0])
		return f, n || re.Min == 0
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText,
		syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return set, true
	}
	return all(), true // anything else: assume it can start with anything
}

func all() [256]bool {
	var set [256]bool
	for i := range set {
		set[i] = true
	}
	return set
}
