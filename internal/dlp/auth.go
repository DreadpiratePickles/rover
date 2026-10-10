package dlp

import (
	"bytes"
	"encoding/base64"
)

// HTTP credentials in a header or a curl line:
//
//	Authorization: Bearer 9f8e7d6c...     Authorization: Basic ZGVwbG95Ok...
//
// A bearer token is opaque (any vendor), so it is recognised by the word
// in front of it; a Basic credential is base64 of "user:password" and is
// checked by decoding it. Like the generic rule, scanning continues after
// whatever was read, so each byte is read a constant number of times.
var (
	bearerWord = []byte("bearer ")
	basicWord  = []byte("basic ")
)

const (
	minBearer = 16
	minBasic  = 8
)

func bearerByte(c byte) bool {
	return isAlnum(c) || c == '.' || c == '_' || c == '~' || c == '+' || c == '/' || c == '-' || c == '='
}

func base64Byte(c byte) bool { return isAlnum(c) || c == '+' || c == '/' || c == '=' }

func findHTTPAuth(text, lower []byte, ms []Match) []Match {
	ms = findAfterWord(text, lower, bearerWord, bearerByte, func(v []byte) bool {
		return len(v) >= minBearer && hasDigitAndLetter(v)
	}, ms)
	return findAfterWord(text, lower, basicWord, base64Byte, basicCredential, ms)
}

// findAfterWord finds word (lowercase, at a word start) followed by a run
// of ok bytes that accept likes.
func findAfterWord(text, lower, word []byte, ok func(byte) bool, accept func([]byte) bool, ms []Match) []Match {
	for from := 0; from < len(lower); {
		i := bytes.Index(lower[from:], word)
		if i < 0 {
			break
		}
		at := from + i
		v := at + len(word)
		end := runOf(text, v, ok, maxToken)
		from = max(v, end)
		if at > 0 && isLower(lower[at-1]) {
			continue // "unbearer", "nonbasic"
		}
		if end > v && accept(text[v:end]) {
			ms = append(ms, Match{Kind: KindHTTPAuth, Start: v, End: end})
		}
	}
	return ms
}

func hasDigitAndLetter(v []byte) bool {
	var d, l bool
	for _, c := range v {
		d = d || isDigit(c)
		l = l || isUpper(c) || isLower(c)
	}
	return d && l
}

// basicCredential: base64 that decodes to printable "user:password".
func basicCredential(v []byte) bool {
	if len(v) < minBasic {
		return false
	}
	dec, err := base64.StdEncoding.DecodeString(string(v))
	if err != nil {
		if dec, err = base64.RawStdEncoding.DecodeString(string(bytes.TrimRight(v, "="))); err != nil {
			return false
		}
	}
	colon := bytes.IndexByte(dec, ':')
	if colon <= 0 || colon == len(dec)-1 {
		return false
	}
	for _, c := range dec {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}
