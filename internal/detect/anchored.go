package detect

import (
	"bufio"
	_ "embed" // the rule lists are data files Bobby can read and extend
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// The phrase lists. See the comments at the top of each file for the format.
var (
	//go:embed rules/phrases.txt
	phrasesTxt string
	//go:embed rules/shadowing.txt
	shadowingTxt string
)

// hiddenMarkupRules are CSS that hides text from a human reader while a
// model still reads it. Same format as phrases.txt; built in because they are
// not a matter of taste.
const hiddenMarkupRules = `
display\s*:\s*none
visibility\s*:\s*hidden
font-size\s*:\s*0(?:\.0+)?(?:px|pt|em|rem|%)?\s*(?:[;"'}!]|$)
opacity\s*:\s*0(?:\.0+)?\s*(?:[;"'}!]|$)
`

// phraseWindow bounds a match: it must end within this many bytes of its
// first character. It also bounds the work per candidate.
const phraseWindow = 256

// anchored is one regular expression found through its first literal word.
type anchored struct {
	id     string
	src    string
	re     *regexp.Regexp // (?i)\A(?:src): matches only at the candidate
	prefix string         // literal text before the anchor word ("<" in "<important>")
	word   string         // the anchor word, lower case
	// next is the set of bytes that can follow the anchor word (after
	// white space when skipWS); nil when it could not be worked out. It
	// keeps "before you submit" from running the "before using this tool"
	// regexp at all.
	next   *[256]bool
	skipWS bool
}

// anchorIndex finds the rules whose anchor word starts like a token: a
// table keyed by the first two bytes of the word (a-z, 0-9, _), so a lookup
// is two array indexes, no hashing and no allocation.
type anchorIndex [][]*anchored

// wordAlphabet is the size of the word alphabet: a-z, 0-9, _.
const wordAlphabet = 37

func wordCode(c byte) int {
	switch {
	case c >= 'a' && c <= 'z':
		return int(c - 'a')
	case c >= '0' && c <= '9':
		return 26 + int(c-'0')
	}
	return 36 // '_'
}

func indexKey(w []byte) int { return wordCode(w[0])*wordAlphabet + wordCode(w[1]) }

// isWordByte is the tokenizer's word alphabet (on lowercased text).
func isWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_'
}

// compileList parses one rules file: one expression per line, # comments.
func compileList(id, src string) ([]*anchored, error) {
	var out []*anchored
	sc := bufio.NewScanner(strings.NewReader(src))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		a, err := compileLine(id, line)
		if err != nil {
			return nil, fmt.Errorf("%s line %d %q: %w", id, n, line, err)
		}
		out = append(out, a)
	}
	return out, sc.Err()
}

func compileLine(id, line string) (*anchored, error) {
	free, err := regexp.Compile(line)
	if err != nil {
		return nil, err
	}
	lit, _ := free.LiteralPrefix()
	if lit != strings.ToLower(lit) {
		return nil, fmt.Errorf("write the expression in lower case")
	}
	start := -1
	for i := 0; i < len(lit); i++ { // bytes >= 0x80 belong to multi-byte runes, never word bytes
		if lit[i] < 0x80 && isWordByte(lit[i]) {
			start = i
			break
		}
	}
	if start < 0 {
		return nil, fmt.Errorf("must start with a literal word (optionally after punctuation such as <)")
	}
	end := start
	for end < len(lit) && isWordByte(lit[end]) {
		end++
	}
	if end-start < 2 {
		return nil, fmt.Errorf("the first word must be at least 2 letters")
	}
	if !wordEndsThere(line, lit[start:end]) {
		return nil, fmt.Errorf("the first word must end where the expression says (followed by \\s, \\b, punctuation or the end; write \"when\" and \"whenever\" as two lines)")
	}
	// Case-insensitive, on the original text: no lowered copy to make.
	re, err := regexp.Compile(`(?i)\A(?:` + line + `)`)
	if err != nil {
		return nil, err
	}
	a := &anchored{id: id, src: line, re: re, prefix: lit[:start], word: lit[start:end]}
	a.next, a.skipWS = nextBytes(line, len([]rune(lit[:end])))
	return a, nil
}

// wordEndsThere reports whether, in the expression line, the anchor word
// is always followed by a non-word character (or nothing). The scanner then
// needs the whole token to equal the word, which is what makes a lookup
// cheap: "release" does not wake the rule anchored on "re-enter".
func wordEndsThere(line, word string) bool {
	i := strings.Index(line, word)
	if i < 0 {
		return false
	}
	rest := line[i+len(word):]
	for _, p := range []string{`\s`, `\b`, `\.`, `(?:'`, `(?:’`} {
		if strings.HasPrefix(rest, p) {
			return true
		}
	}
	if rest == "" {
		return true
	}
	r, size := utf8.DecodeRuneInString(rest)
	if !strings.ContainsRune(" ->:'’,;", r) {
		return false
	}
	return len(rest) == size || !strings.ContainsAny(rest[size:size+1], "?*{")
}

func newIndex(lists ...[]*anchored) anchorIndex {
	idx := make(anchorIndex, wordAlphabet*wordAlphabet)
	for _, l := range lists {
		for _, a := range l {
			k := indexKey([]byte(a.word))
			idx[k] = append(idx[k], a)
		}
	}
	return idx
}

// match tries every rule anchored on the token text[ws:we] and calls emit
// for each that matches there. The caller has lowered the token into tok.
func (idx anchorIndex) match(s *scan, tok []byte, ws, we int, emit func(a *anchored, start, end int)) {
	for _, a := range idx[indexKey(tok)] {
		start := ws - len(a.prefix)
		if string(tok) != a.word || start < 0 || s.count[a.id] >= maxPerRule || !s.at(start, a.prefix) || !a.follows(s, we) {
			continue
		}
		window := s.text[start:min(start+phraseWindow, len(s.text))]
		if !a.re.Match(window) { // no captures: no allocation
			continue
		}
		if loc := a.re.FindIndex(window); loc != nil {
			emit(a, start, start+loc[1])
		}
	}
}

// follows applies the next-byte prefilter at the end of the anchor word.
func (a *anchored) follows(s *scan, we int) bool {
	if a.next == nil {
		return true
	}
	i := we
	if a.skipWS {
		for i < len(s.text) && i-we < phraseWindow && isSpace(s.text[i]) {
			i++
		}
	}
	return i < len(s.text) && a.next[s.byteAt(i)]
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}

// maxTokenLen bounds the words the filter knows; longer tokens are no anchor.
const maxTokenLen = 16

// tokenFilter is a bitmap over (first two letters, length) of every word
// some rule starts with, so the pass can skip all other words with one
// lookup in a local array.
type tokenFilter [(wordAlphabet*wordAlphabet*maxTokenLen + 63) / 64]uint64

// endFilter is the same over (last letter, length): "release" has the
// first letters and length of "reenter" but not its last letter.
type endFilter [(wordAlphabet*maxTokenLen + 63) / 64]uint64

func (f *tokenFilter) set(word string, ends *endFilter) {
	n := min(len(word), maxTokenLen-1)
	bit := indexKey([]byte(word))*maxTokenLen + n
	f[bit/64] |= 1 << (bit % 64)
	bit = wordCode(word[len(word)-1])*maxTokenLen + n
	ends[bit/64] |= 1 << (bit % 64)
}

// The compiled rule sets, built once. The lists are embedded, so a bad line
// is a build defect that every test run catches (TestRuleFilesCompile).
var (
	phraseRules, shadowRules, hiddenRules []*anchored
	textIndex                             anchorIndex // phrases + shadowing + hidden markup
	argsIndex                             anchorIndex // hidden markup only (tool_args)
	textFilter, argsFilter                tokenFilter // words worth a closer look
	textEnds, argsEnds                    endFilter
	rulesErr                              error
)

func init() {
	var errs []error
	load := func(id, src string) []*anchored {
		l, err := compileList(id, src)
		if err != nil {
			errs = append(errs, err)
		}
		return l
	}
	phraseRules = load(RuleInstruction, phrasesTxt)
	shadowRules = load(RuleCrossTool, shadowingTxt)
	hiddenRules = load(RuleHiddenMarkup, hiddenMarkupRules)
	textIndex = newIndex(phraseRules, shadowRules, hiddenRules)
	argsIndex = newIndex(hiddenRules)
	for _, l := range [][]*anchored{phraseRules, shadowRules, hiddenRules} {
		for _, a := range l {
			textFilter.set(a.word, &textEnds)
		}
	}
	for _, a := range hiddenRules {
		argsFilter.set(a.word, &argsEnds)
	}
	for w := range sensitiveWords {
		textFilter.set(w, &textEnds)
		argsFilter.set(w, &argsEnds)
	}
	textFilter.set("hidden", &textEnds)
	argsFilter.set("hidden", &argsEnds)
	if len(errs) > 0 {
		rulesErr = errs[0]
	}
}
