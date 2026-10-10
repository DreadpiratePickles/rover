package dlp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
)

// Format detectors: a fixed prefix found with bytes.Index, then the
// vendor's shape checked byte by byte. The shapes are written from the
// vendors' published token formats; no pattern is copied from another
// project (see THIRD_PARTY.md).

// prefixRule is one fixed prefix and the token body that must follow it.
type prefixRule struct {
	kind   string
	prefix string
	body   func(c byte) bool
	min    int  // body bytes at least
	exact  bool // body is exactly min bytes, then a boundary
	// sub is a second check on the bytes after the prefix (slack: the
	// type letter and the dash); it returns how many it consumed, or -1.
	sub func(rest []byte) int
}

func upperOrDigit(c byte) bool { return isUpper(c) || isDigit(c) }
func alnumUnder(c byte) bool   { return isAlnum(c) || c == '_' }
func alnumDash(c byte) bool    { return isAlnum(c) || c == '-' }
func webhookPath(c byte) bool  { return isAlnum(c) || c == '/' || c == '_' }

// slackType accepts the type letter and dash of xoxa-, xoxb-, xoxp-, xoxr-.
func slackType(rest []byte) int {
	if len(rest) >= 2 && bytes.IndexByte([]byte("abpr"), rest[0]) >= 0 && rest[1] == '-' {
		return 2
	}
	return -1
}

var prefixRules = []prefixRule{
	{kind: KindAWSAccessKey, prefix: "AKIA", body: upperOrDigit, min: 16, exact: true},
	{kind: KindAWSAccessKey, prefix: "ASIA", body: upperOrDigit, min: 16, exact: true},
	{kind: KindGitHubToken, prefix: "ghp_", body: isAlnum, min: 36},
	{kind: KindGitHubToken, prefix: "gho_", body: isAlnum, min: 36},
	{kind: KindGitHubToken, prefix: "ghs_", body: isAlnum, min: 36},
	{kind: KindGitHubToken, prefix: "ghu_", body: isAlnum, min: 36},
	{kind: KindGitHubToken, prefix: "ghr_", body: isAlnum, min: 36},
	{kind: KindGitHubToken, prefix: "github_pat_", body: alnumUnder, min: 82},
	{kind: KindSlackToken, prefix: "xox", body: alnumDash, min: 10, sub: slackType},
	{kind: KindSlackWebhook, prefix: "hooks.slack.com/services/", body: webhookPath, min: 20},
	{kind: KindStripe, prefix: "sk_live_", body: isAlnum, min: 24},
	{kind: KindStripe, prefix: "rk_live_", body: isAlnum, min: 24},
}

// maxToken bounds how far a token body is followed.
const maxToken = 1024

func findPrefixed(text []byte, ms []Match) []Match {
	for _, r := range prefixRules {
		p := []byte(r.prefix)
		for from := 0; from < len(text); {
			i := bytes.Index(text[from:], p)
			if i < 0 {
				break
			}
			start := from + i
			from = start + len(p)
			if start > 0 && isAlnum(text[start-1]) && r.kind != KindSlackWebhook {
				continue // inside a longer word
			}
			if end, ok := r.match(text, start+len(p)); ok {
				if r.kind == KindSlackWebhook && start >= len("https://") && string(text[start-len("https://"):start]) == "https://" {
					start -= len("https://")
				}
				ms = append(ms, Match{Kind: r.kind, Start: start, End: end})
				from = end
			}
		}
	}
	return ms
}

// match checks the body after the prefix (at) and returns its end.
func (r prefixRule) match(text []byte, at int) (int, bool) {
	if r.sub != nil {
		n := r.sub(text[at:])
		if n < 0 {
			return 0, false
		}
		at += n
	}
	end := at
	for end < len(text) && end-at < maxToken && r.body(text[end]) {
		end++
	}
	n := end - at
	if n < r.min {
		return 0, false
	}
	if r.exact {
		if n != r.min || (end < len(text) && isAlnum(text[end])) {
			return 0, false
		}
	}
	return end, true
}

// PEM private keys: "-----BEGIN [RSA |EC |OPENSSH |ENCRYPTED ]PRIVATE KEY-----"
// up to the matching END line. Without an END line the rest of the text is
// redacted: a key cut in half is still a key. For the same reason an END
// line before any BEGIN means the text starts inside a key: everything up
// to it is redacted.
var (
	pemBegin = []byte("-----BEGIN ")
	pemEnd   = []byte("-----END ")
	pemTail  = []byte("PRIVATE KEY-----")
)

// maxPEMLabel bounds the label between BEGIN and PRIVATE KEY.
const maxPEMLabel = 32

// span is a byte range [start, end).
type span struct{ start, end int }

// findPEM finds private key blocks, and returns the spans of public ones
// (certificates, public keys) for the entropy pass to skip.
func findPEM(text []byte, ms []Match) ([]Match, []span) {
	var public []span
	noEnd := false // no END line after here: stop looking (keeps this linear)
	for from := 0; from < len(text); {
		i := bytes.Index(text[from:], pemBegin)
		if i < 0 {
			break
		}
		start := from + i
		from = start + len(pemBegin)
		window := text[from:min(len(text), from+maxPEMLabel+len(pemTail))]
		line := window
		if nl := bytes.IndexByte(window, '\n'); nl >= 0 {
			line = window[:nl]
		}
		t := bytes.Index(line, pemTail)
		if t < 0 {
			if !noEnd && bytes.HasSuffix(line, []byte("-----")) && !bytes.Contains(line, []byte("PRIVATE")) {
				if e := bytes.Index(text[from:], pemEnd); e >= 0 {
					public = append(public, span{start, from + e})
					from += e
				} else {
					noEnd = true
				}
			}
			continue
		}
		body := from + t + len(pemTail)
		end := len(text)
		if e := bytes.Index(text[body:], pemEnd); e >= 0 {
			endLine := body + e + len(pemEnd)
			if k := bytes.Index(text[endLine:min(len(text), endLine+maxPEMLabel+len(pemTail))], pemTail); k >= 0 {
				end = endLine + k + len(pemTail)
			}
		}
		ms = append(ms, Match{Kind: KindPrivateKey, Start: start, End: end})
		from = end
	}
	return orphanPEMEnd(text, ms), public
}

// orphanPEMEnd adds the head of a text that starts inside a private key:
// an END ... PRIVATE KEY----- line before the first BEGIN.
func orphanPEMEnd(text []byte, ms []Match) []Match {
	e := bytes.Index(text, pemEnd)
	if e < 0 {
		return ms
	}
	if b := bytes.Index(text[:e], pemBegin); b >= 0 {
		return ms
	}
	line := text[e:min(len(text), e+len(pemEnd)+maxPEMLabel+len(pemTail))]
	t := bytes.Index(line, pemTail)
	if t < 0 || bytes.IndexByte(line[:t], '\n') >= 0 {
		return ms
	}
	return append(ms, Match{Kind: KindPrivateKey, Start: 0, End: e + t + len(pemTail)})
}

// JWTs: three base64url parts joined by dots, the first starting "eyJ"
// (the encoding of `{"`) and decoding to a JSON object with an "alg"
// member. The header check keeps base64 that merely starts with eyJ out.
var jwtPrefix = []byte("eyJ")

// maxJWTHeader bounds the header decoded.
const maxJWTHeader = 1024

func base64URL(c byte) bool { return isAlnum(c) || c == '-' || c == '_' }

func findJWT(text []byte, ms []Match) []Match {
	for from := 0; from < len(text); {
		i := bytes.Index(text[from:], jwtPrefix)
		if i < 0 {
			break
		}
		start := from + i
		from = start + len(jwtPrefix)
		if start > 0 && base64URL(text[start-1]) {
			continue
		}
		h := runOf(text, start, base64URL, maxJWTHeader)
		if h-start < 10 || h >= len(text) || text[h] != '.' || !jwtHeader(text[start:h]) {
			continue
		}
		p := runOf(text, h+1, base64URL, 64<<10)
		if p-(h+1) < 2 || p >= len(text) || text[p] != '.' {
			continue
		}
		end := runOf(text, p+1, base64URL, maxToken)
		ms = append(ms, Match{Kind: KindJWT, Start: start, End: end})
		from = end
	}
	return ms
}

// runOf returns the end of the run of ok bytes from at (at most limit).
func runOf(text []byte, at int, ok func(byte) bool, limit int) int {
	end := at
	for end < len(text) && end-at < limit && ok(text[end]) {
		end++
	}
	return end
}

// jwtHeader reports a base64url JSON object with an "alg" member.
func jwtHeader(part []byte) bool {
	dec, err := base64.RawURLEncoding.DecodeString(string(part))
	if err != nil {
		return false
	}
	var h map[string]json.RawMessage
	if json.Unmarshal(dec, &h) != nil {
		return false
	}
	_, ok := h["alg"]
	return ok
}
