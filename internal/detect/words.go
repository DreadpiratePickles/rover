package detect

import (
	"strings"
)

// token looks closer at a word the pass's filter let through: rules
// anchored on it, a sensitive path it is part of, a "hidden" attribute.
func (s *scan) token(ws, we int) {
	var buf [maxTokenLen]byte
	tok := buf[:we-ws]
	for k := range tok {
		tok[k] = s.byteAt(ws + k)
	}
	idx := textIndex
	if s.kind == KindToolArgs {
		idx = argsIndex // arguments: hidden markup only (plus paths, below)
	}
	idx.match(s, tok, ws, we, func(a *anchored, start, end int) {
		s.emit(a.id, s.ruleSeverity(a.id), start, end, quote(s.text, start, end))
	})
	if p := s.sensitivePath(tok, ws, we); p != "" {
		s.emit(RuleSensitivePath, s.pick(Medium, Low, Low, Medium), ws, we, "mentions "+p)
	}
	if string(tok) == "important" {
		s.importantTag(ws, we)
	}
	if string(tok) == "hidden" && s.inTagAttr(ws, we) {
		s.emit(RuleHiddenMarkup, s.ruleSeverity(RuleHiddenMarkup), ws, we, "hidden attribute")
	}
}

// importantTag reports "<IMPORTANT>" written with spaces or attributes
// ("< important >", "<Important level=1>"): "<" and white space before the
// word. (The plain form is in phrases.txt.)
func (s *scan) importantTag(ws, we int) {
	i := ws - 1
	for i >= 0 && ws-i <= 8 && isSpace(s.text[i]) {
		i--
	}
	if i >= 0 && s.text[i] == '<' {
		s.emit(RuleInstruction, s.ruleSeverity(RuleInstruction), i, we, "<IMPORTANT> tag")
	}
}

// ruleSeverity is the severity of the anchored rules by kind.
func (s *scan) ruleSeverity(id string) Severity {
	switch id {
	case RuleInstruction:
		return s.pick(High, "", Medium, Medium)
	case RuleCrossTool:
		return s.pick(High, "", Low, Low)
	case RuleHiddenMarkup:
		return s.pick(High, Low, Medium, Medium)
	}
	return ""
}

// at reports whether the text, ASCII-lowercased, has lit (lower case) at i.
func (s *scan) at(i int, lit string) bool {
	if i < 0 || i+len(lit) > len(s.text) {
		return false
	}
	for k := 0; k < len(lit); k++ {
		if s.byteAt(i+k) != lit[k] {
			return false
		}
	}
	return true
}

// byteAt returns the byte at i, ASCII-lowercased, or 0 outside the text.
func (s *scan) byteAt(i int) byte {
	if i < 0 || i >= len(s.text) {
		return 0
	}
	c := s.text[i]
	if 'A' <= c && c <= 'Z' {
		c += 'a' - 'A'
	}
	return c
}

// dotted reports whether the token at ws is a dot-file name: ".x" at the
// start of a path component (not "process.env").
func (s *scan) dotted(ws int) bool {
	return s.byteAt(ws-1) == '.' && !isWordByte(s.byteAt(ws-2)) && s.byteAt(ws-2) != '.'
}

// sensitivePath returns the path a token is part of, or "". It looks for
// the places credentials live, not the words: ".env" counts, "env" does not;
// "~/.ssh/id_rsa" counts, "~/.ssh/config" and "id_ed25519.pub" do not.
func (s *scan) sensitivePath(word []byte, ws, we int) string {
	tok, ok := sensitiveWords[string(word)] // no allocation
	if !ok {
		return ""
	}
	switch tok {
	case "ssh":
		if s.dotted(ws) && !s.at(we, "/config") && !s.at(we, "\\config") && !s.pubKeyAfter(we) {
			return "~/.ssh"
		}
	case "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa":
		if !s.at(we, ".pub") {
			return tok
		}
	case "env":
		if s.dotted(ws) && !isWordByte(s.byteAt(we)) && !s.at(we, ".example") && !s.at(we, ".sample") && !s.at(we, ".template") {
			return ".env"
		}
	case "credentials":
		if s.byteAt(ws-1) == '/' || s.byteAt(ws-1) == '\\' || s.at(ws-4, "git-") || s.at(we, ".json") || s.at(we, ".yml") || s.at(we, ".yaml") || s.at(we, ".toml") || s.at(we, ".ini") || s.at(we, ".db") {
			return "credentials file"
		}
	case "aws", "kube", "docker", "cursor":
		if s.dotted(ws) && (s.byteAt(we) == '/' || s.byteAt(we) == '\\') {
			return "~/." + tok
		}
	case "gnupg", "npmrc", "netrc", "pgpass", "pypirc", "bash_history", "zsh_history":
		if s.dotted(ws) {
			return "~/." + tok
		}
	case "keychain", "keychains":
		if s.byteAt(ws-1) == '.' || s.byteAt(we) == '/' || s.at(we, "-db") {
			return "keychain"
		}
	case "shadow":
		if s.at(ws-5, "/etc/") {
			return "/etc/shadow"
		}
	case "claude":
		if s.dotted(ws) && s.at(we, ".json") {
			return "~/.claude.json"
		}
	}
	return ""
}

// sensitiveWords are the tokens sensitivePath looks at.
var sensitiveWords = func() map[string]string {
	m := map[string]string{}
	for _, w := range []string{"ssh", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "env", "credentials",
		"aws", "kube", "docker", "cursor", "gnupg", "npmrc", "netrc", "pgpass", "pypirc", "bash_history",
		"zsh_history", "keychain", "keychains", "shadow", "claude"} {
		m[w] = w
	}
	return m
}()

// pubKeyAfter reports whether ".ssh/" is followed by a public key file.
func (s *scan) pubKeyAfter(we int) bool {
	if s.byteAt(we) != '/' && s.byteAt(we) != '\\' {
		return false
	}
	i := we + 1
	for i < len(s.text) && (isWordByte(s.byteAt(i)) || s.text[i] == '.' || s.text[i] == '-') {
		i++
	}
	return s.at(i-4, ".pub")
}

// inTagAttr reports whether the token at [ws, we) is an attribute inside an
// HTML tag: "<div hidden>", "<span class=x hidden=true>".
func (s *scan) inTagAttr(ws, we int) bool {
	b := s.byteAt(ws - 1)
	if b != ' ' && b != '\t' && b != '\n' {
		return false
	}
	switch s.byteAt(we) {
	case '>', ' ', '=', '/', '\t', '\n':
	default:
		return false
	}
	for i := ws - 1; i >= 0 && ws-i <= phraseWindow; i-- {
		switch s.text[i] {
		case '<':
			return isWordByte(s.byteAt(i + 1))
		case '>':
			return false
		}
	}
	return false
}

// knownTools finds names of other servers' tools in a description: medium
// alone, high when the mention is part of an instruction.
func (s *scan) knownTools() {
	l := s.text
	isName := func(c byte) bool { return isWordByte(c) || c == '-' || c == '.' }
	phrase := s.count[RuleInstruction] > 0
	for i := 0; i < len(l); {
		if !isName(s.byteAt(i)) {
			i++
			continue
		}
		ws := i
		for i < len(l) && isName(s.byteAt(i)) {
			i++
		}
		name := strings.ToLower(strings.TrimRight(string(l[ws:i]), "-."))
		servers := s.rules.tools[name]
		if len(servers) == 0 || contains(servers, s.rules.server) {
			continue
		}
		sev := s.pick(Medium, "", Low, Low)
		if phrase || s.instructedBefore(ws) {
			sev = s.pick(High, "", Low, Low)
		}
		s.emit(RuleCrossTool, sev, ws, ws+len(name), "names "+servers[0]+"/"+name)
	}
}

// A mention is an instruction when, in the same sentence, it follows a
// condition word ("when ... send_email", "before replying ... send_email")
// or directly follows a verb ("call send_email", "use the send_email tool").
var (
	conditionWords = map[string]bool{"when": true, "whenever": true, "before": true, "after": true, "instead": true}
	verbWords      = map[string]bool{"call": true, "use": true, "invoke": true, "run": true, "calling": true, "using": true}
	fillerWords    = map[string]bool{"the": true, "a": true, "an": true, "tool": true, "its": true}
)

// instructedBefore looks back from i to the start of the sentence (at most
// 120 bytes) for a condition word, or for a verb right before the name
// (only "the", "a", "tool" between).
func (s *scan) instructedBefore(i int) bool {
	lo := max(0, i-120)
	for j := i - 1; j >= lo; j-- {
		switch s.text[j] {
		case '.', '!', '?', '\n', ';':
			lo = j + 1
		}
	}
	adjacent := true
	for j := i - 1; j >= lo; {
		for j >= lo && !isWordByte(s.byteAt(j)) {
			j--
		}
		end := j + 1
		for j >= lo && isWordByte(s.byteAt(j)) {
			j--
		}
		if end <= j+1 {
			break
		}
		w := strings.ToLower(string(s.text[j+1 : end]))
		switch {
		case conditionWords[w], adjacent && verbWords[w]:
			return true
		case !fillerWords[w]:
			adjacent = false
		}
	}
	return false
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
