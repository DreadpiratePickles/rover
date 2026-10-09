package daemon

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"slices"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
)

// Reading server JSON for detection, fast and strictly.
//
// Everything read here is part of a line jsonrpc.Parse has already accepted,
// so it is valid JSON. That lets these helpers find the members and elements
// of an object or array by skipping strings with bytes.IndexByte instead of
// decoding the whole value once per level (review M7: a 64 KB result was
// decoded five times). They stay strict where it matters: keys are compared
// exactly, and two keys that are equal ignoring case are refused
// (jsonrpc.FoldKey), so no reader sees a copy Rover did not scan.
// Offsets are absolute in the buffer, so a value can be replaced in place.

// maxWalkDepth bounds how deep walkStrings descends; deeper is refused.
const maxWalkDepth = 64

// errTooDeep refuses JSON nested deeper than maxWalkDepth.
var errTooDeep = errors.New("JSON nested too deeply")

var errBadJSON = errors.New("malformed JSON")

func skipSpace(b []byte, i, end int) int {
	for i < end && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	return i
}

// skipString returns the index after the string that starts at b[i] == '"'.
func skipString(b []byte, i, end int) (int, error) {
	for j := i + 1; j < end; {
		k := bytes.IndexByte(b[j:end], '"')
		if k < 0 {
			return 0, errBadJSON
		}
		q, n := j+k, 0
		for p := q - 1; p > i && b[p] == '\\'; p-- {
			n++
		}
		if n%2 == 0 {
			return q + 1, nil
		}
		j = q + 1
	}
	return 0, errBadJSON
}

// skipValue returns the index after the value that starts at b[i].
func skipValue(b []byte, i, end int) (int, error) {
	if i >= end {
		return 0, errBadJSON
	}
	switch b[i] {
	case '"':
		return skipString(b, i, end)
	case '{', '[':
		depth := 0
		for j := i; j < end; {
			switch b[j] {
			case '"':
				k, err := skipString(b, j, end)
				if err != nil {
					return 0, err
				}
				j = k
				continue
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return j + 1, nil
				}
			}
			j++
		}
		return 0, errBadJSON
	}
	j := i
	for j < end && !isValueEnd(b[j]) {
		j++
	}
	return j, nil
}

// isValueEnd ends a number, true, false or null.
func isValueEnd(c byte) bool {
	switch c {
	case ',', '}', ']', ' ', '\t', '\n', '\r':
		return true
	}
	return false
}

// splitObject returns the members of the object b[start:end].
func splitObject(b []byte, start, end int) (jsonrpc.Fields, error) {
	i := skipSpace(b, start, end)
	if i >= end || b[i] != '{' {
		return nil, jsonrpc.ErrNotObject
	}
	var out jsonrpc.Fields
	seen := map[string]string{}
	for i = skipSpace(b, i+1, end); i < end && b[i] != '}'; {
		ke, err := skipString(b, i, end)
		if err != nil || b[i] != '"' {
			return nil, errBadJSON
		}
		key, ok := stringValue(b[i:ke])
		if !ok {
			return nil, errBadJSON
		}
		fk := jsonrpc.FoldKey(key)
		if first, dup := seen[fk]; dup {
			return nil, fmt.Errorf("%w: %q and %q", jsonrpc.ErrDuplicateKey, first, key)
		}
		seen[fk] = key
		i = skipSpace(b, ke, end)
		if i >= end || b[i] != ':' {
			return nil, errBadJSON
		}
		vs := skipSpace(b, i+1, end)
		ve, err := skipValue(b, vs, end)
		if err != nil {
			return nil, err
		}
		out = append(out, jsonrpc.Field{Key: key, Value: b[vs:ve], Start: vs, End: ve})
		i = skipSpace(b, ve, end)
		if i < end && b[i] == ',' {
			i = skipSpace(b, i+1, end)
		}
	}
	if i >= end {
		return nil, errBadJSON
	}
	return out, nil
}

// splitArray returns the [start, end) of every element of the array b[start:end].
func splitArray(b []byte, start, end int) ([][2]int, error) {
	i := skipSpace(b, start, end)
	if i >= end || b[i] != '[' {
		return nil, errors.New("not a JSON array")
	}
	var out [][2]int
	for i = skipSpace(b, i+1, end); i < end && b[i] != ']'; {
		ve, err := skipValue(b, i, end)
		if err != nil {
			return nil, err
		}
		out = append(out, [2]int{i, ve})
		i = skipSpace(b, ve, end)
		if i < end && b[i] == ',' {
			i = skipSpace(b, i+1, end)
		}
	}
	if i >= end {
		return nil, errBadJSON
	}
	return out, nil
}

// field returns the member key of an object, if present.
func field(fs jsonrpc.Fields, key string) (jsonrpc.Field, bool) {
	for _, f := range fs {
		if f.Key == key {
			return f, true
		}
	}
	return jsonrpc.Field{}, false
}

// stringValue decodes a JSON string; ok is false for any other value.
func stringValue(raw []byte) (string, bool) {
	t, ok := textValue(raw)
	return string(t), ok
}

// textValue is stringValue as bytes. A string without escapes is returned
// as a slice of raw itself (no copy): a 64 KB text block is the common case.
func textValue(raw []byte) ([]byte, bool) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil, false
	}
	body := raw[1 : len(raw)-1]
	if bytes.IndexByte(body, '\\') < 0 {
		return body, true
	}
	return unescape(body)
}

// unescape decodes the escapes of a JSON string body that encoding/json
// has already validated (the whole line went through jsonrpc.Parse): about
// four times faster than json.Unmarshal on a large text. A lone surrogate
// becomes U+FFFD, as encoding/json does.
func unescape(body []byte) ([]byte, bool) {
	out := make([]byte, 0, len(body))
	for i := 0; i < len(body); {
		k := bytes.IndexByte(body[i:], '\\')
		if k < 0 {
			return append(out, body[i:]...), true
		}
		out = append(out, body[i:i+k]...)
		i += k
		if i+1 >= len(body) {
			return nil, false
		}
		switch c := body[i+1]; c {
		case '"', '\\', '/':
			out = append(out, c)
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, n, ok := hexRune(body[i:])
			if !ok {
				return nil, false
			}
			out = utf8.AppendRune(out, r)
			i += n
			continue
		default:
			return nil, false
		}
		i += 2
	}
	return out, true
}

// hexRune decodes \uXXXX (or a \uXXXX\uXXXX surrogate pair) at the start
// of b and returns the rune and the bytes used.
func hexRune(b []byte) (rune, int, bool) {
	r, ok := hex4(b)
	if !ok {
		return 0, 0, false
	}
	if utf16.IsSurrogate(r) {
		if r2, ok2 := hex4(b[6:]); ok2 && len(b) >= 12 && b[6] == '\\' {
			if dec := utf16.DecodeRune(r, r2); dec != utf8.RuneError {
				return dec, 12, true
			}
		}
		return utf8.RuneError, 6, true
	}
	return r, 6, true
}

func hex4(b []byte) (rune, bool) {
	if len(b) < 6 || b[0] != '\\' || b[1] != 'u' {
		return 0, false
	}
	var r rune
	for _, c := range b[2:6] {
		switch {
		case c >= '0' && c <= '9':
			r = r<<4 | rune(c-'0')
		case c >= 'a' && c <= 'f':
			r = r<<4 | rune(c-'a'+10)
		case c >= 'A' && c <= 'F':
			r = r<<4 | rune(c-'A'+10)
		default:
			return 0, false
		}
	}
	return r, true
}

// walkStrings calls fn for every string value in raw (an object, array or
// scalar) whose member key is in keys, or every string when keys is nil.
// Nesting deeper than maxWalkDepth is an error.
func walkStrings(raw []byte, keys map[string]bool, fn func([]byte)) error {
	return walk(raw, 0, len(raw), "", keys, fn, 0)
}

func walk(b []byte, start, end int, key string, keys map[string]bool, fn func([]byte), depth int) error {
	if depth > maxWalkDepth {
		return errTooDeep
	}
	i := skipSpace(b, start, end)
	if i >= end {
		return nil
	}
	switch b[i] {
	case '"':
		if t, ok := textValue(b[i:end]); ok && (keys == nil || keys[key]) {
			fn(t)
		}
	case '{':
		fs, err := splitObject(b, i, end)
		if err != nil {
			return err
		}
		for _, f := range fs {
			if err := walk(b, f.Start, f.End, f.Key, keys, fn, depth+1); err != nil {
				return err
			}
		}
	case '[':
		els, err := splitArray(b, i, end)
		if err != nil {
			return err
		}
		for _, e := range els {
			if err := walk(b, e[0], e[1], key, keys, fn, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// edit replaces raw[start:end] with with.
type edit struct {
	start, end int
	with       []byte
}

// applyEdits returns raw with every edit applied. Edits must not overlap.
func applyEdits(raw []byte, edits []edit) ([]byte, error) {
	out := make([]byte, 0, len(raw))
	at := 0
	for _, e := range sortEdits(edits) {
		if e.start < at || e.end < e.start || e.end > len(raw) {
			return nil, fmt.Errorf("overlapping edit at %d", e.start)
		}
		out = append(out, raw[at:e.start]...)
		out = append(out, e.with...)
		at = e.end
	}
	return append(out, raw[at:]...), nil
}

func sortEdits(es []edit) []edit {
	out := append([]edit(nil), es...)
	slices.SortStableFunc(out, func(a, b edit) int { return cmp.Compare(a.start, b.start) })
	return out
}

// joinArray builds a JSON array from raw elements.
func joinArray(items [][]byte) []byte {
	var b bytes.Buffer
	b.WriteByte('[')
	for i, it := range items {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(it)
	}
	b.WriteByte(']')
	return b.Bytes()
}
