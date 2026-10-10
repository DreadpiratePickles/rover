package dlp

import (
	"bytes"
	"strings"
)

// Generic credentials: a credential-sounding name, a separator, a value.
//
//	password=hunter2hunter2   api_key: "8f1c…"   "token": "abc123…"
//
// The name is one of credentialWords, possibly inside a longer identifier
// (DB_PASSWORD, access_token, x-api-key). Only the value is redacted, so
// the reader still sees which setting was there. Code that merely mentions
// a token is the common false positive (token = getToken(), token: string,
// tokens_used: 12345678), so a value must look like data, not code: see
// plausibleValue.

var credentialWords = [][]byte{
	[]byte("password"), []byte("passwd"), []byte("pwd"), []byte("secret"),
	[]byte("api_key"), []byte("api-key"), []byte("apikey"), []byte("token"),
}

const (
	minGenericValue = 8
	maxGenericValue = 512
	maxNameTail     = 32 // identifier bytes after the word: access_token_value
	maxSeparatorGap = 8  // spaces around the separator
)

func findGeneric(text, lower []byte, ms []Match) []Match {
	for _, w := range credentialWords {
		for from := 0; from < len(lower); {
			i := bytes.Index(lower[from:], w)
			if i < 0 {
				break
			}
			at := from + i
			from = at + len(w)
			if s, e, ok := genericValue(text, at+len(w)); ok {
				ms = append(ms, Match{Kind: KindGeneric, Start: s, End: e})
				from = e
			}
		}
	}
	return ms
}

// genericValue parses name-tail, separator and value after a credential
// word ending at at, and returns the value's span.
func genericValue(text []byte, at int) (int, int, bool) {
	i := runOf(text, at, func(c byte) bool { return isAlnum(c) || c == '_' || c == '-' }, maxNameTail)
	if i < len(text) && (text[i] == '"' || text[i] == '\'') {
		i++ // the closing quote of a quoted key: "token": ...
	}
	i = skipSpaces(text, i)
	if i >= len(text) || (text[i] != ':' && text[i] != '=') {
		return 0, 0, false
	}
	i++
	if i < len(text) && (text[i] == '=' || text[i] == '>') {
		i++ // := and =>
	}
	i = skipSpaces(text, i)
	if i >= len(text) {
		return 0, 0, false
	}
	if q := text[i]; q == '"' || q == '\'' || q == '`' {
		end := i + 1
		for end < len(text) && end-i <= maxGenericValue && text[end] != q && !isSpace(text[end]) {
			end++
		}
		if end >= len(text) || text[end] != q || !plausibleValue(text[i+1:end], true) {
			return 0, 0, false
		}
		return i + 1, end, true
	}
	end := i
	for end < len(text) && end-i <= maxGenericValue && !unquotedStop(text[end]) {
		end++
	}
	if !plausibleValue(text[i:end], false) {
		return 0, 0, false
	}
	return i, end, true
}

func skipSpaces(text []byte, i int) int {
	for n := 0; i < len(text) && n < maxSeparatorGap && (text[i] == ' ' || text[i] == '\t'); n++ {
		i++
	}
	return i
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}

func unquotedStop(c byte) bool {
	return isSpace(c) || strings.IndexByte("\"'`,;&)}]<>\\", c) >= 0
}

// plausibleValue says whether v looks like a credential rather than code,
// a placeholder or a number. A quoted value only has to be long enough and
// not a placeholder; an unquoted one must also hold a digit and a letter
// (getToken() and os.environ hold no digit) and not start like a path,
// variable or structure.
func plausibleValue(v []byte, quoted bool) bool {
	if len(v) < minGenericValue || len(v) > maxGenericValue || placeholder(v) {
		return false
	}
	var digit, letter, other bool
	for _, c := range v {
		switch {
		case isDigit(c):
			digit = true
		case isUpper(c) || isLower(c):
			letter = true
		default:
			other = true
		}
	}
	if !letter && !other {
		return false // a number: tokens_used=12345678
	}
	if quoted {
		return true
	}
	if bytes.IndexByte(v, '(') >= 0 || strings.IndexByte("/~$%{[<@.", v[0]) >= 0 {
		return false
	}
	return digit && letter
}

// placeholder: ${VAR}, {{ var }}, <your-token>, ********, xxxxxxxx.
func placeholder(v []byte) bool {
	if bytes.Contains(v, []byte("${")) || bytes.Contains(v, []byte("{{")) || (v[0] == '<' && v[len(v)-1] == '>') {
		return true
	}
	for _, c := range v[1:] {
		if c != v[0] {
			return false
		}
	}
	return true
}

// credentialName reports a JSON member name that holds a credential:
// "password", "client_secret", "X-Api-Key", "access_token". A plain
// "tokens" count or "max_tokens" is excluded.
func credentialName(key string) bool {
	k := strings.ToLower(key)
	if strings.Contains(k, "tokens") || strings.HasSuffix(k, "_count") || strings.HasSuffix(k, "_type") {
		return false
	}
	for _, w := range credentialWords {
		if strings.Contains(k, string(w)) {
			return true
		}
	}
	return false
}

// keyedValue is a JSON string under a credential name: the whole value
// is the secret when it is plausible (quoted rules: it was a string) and
// has no white space.
func keyedValue(key, s string) bool {
	if !credentialName(key) || strings.ContainsAny(s, " \t\r\n") {
		return false
	}
	return plausibleValue([]byte(s), true)
}
