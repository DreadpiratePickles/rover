// Package jsonedit reads attacker-controlled JSON strictly (exact keys, no
// duplicates: see jsonrpc.Object) and knows where every value sits, so a
// caller can replace one string in a line and keep every other byte as it
// was. roverd uses it to rewrite results (M5) and DLP to redact secrets
// inside JSON strings (M10): only the strings that change are re-encoded.
package jsonedit

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"unicode"

	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
)

// MaxDepth bounds how deep the walkers descend; deeper is refused.
const MaxDepth = 64

// ErrTooDeep refuses JSON nested deeper than MaxDepth.
var ErrTooDeep = errors.New("JSON nested too deeply")

// Elem is one element of a JSON array and its offsets in the array's bytes.
type Elem struct {
	Raw        json.RawMessage
	Start, End int
}

// ArrayElems splits raw, which must be one JSON array, into its elements.
func ArrayElems(raw []byte) ([]Elem, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
		return nil, errors.New("not a JSON array")
	}
	var out []Elem
	for dec.More() {
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		end := int(dec.InputOffset())
		out = append(out, Elem{Raw: v, Start: end - len(v), End: end})
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim(']') {
		return nil, errors.New("unterminated array")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after the array")
	}
	return out, nil
}

// Field returns the member key of an object read strictly, if present.
func Field(fs jsonrpc.Fields, key string) (jsonrpc.Field, bool) {
	for _, f := range fs {
		if f.Key == key {
			return f, true
		}
	}
	return jsonrpc.Field{}, false
}

// StringValue decodes a JSON string; ok is false for any other value.
func StringValue(raw []byte) (string, bool) {
	var s string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// WalkStrings calls fn for every string value in raw (an object, array or
// scalar) whose member key is in keys, or every string when keys is nil.
// Objects are read strictly; nesting deeper than MaxDepth is an error.
func WalkStrings(raw []byte, keys map[string]bool, fn func(string)) error {
	return Strings(raw, func(key string, _, _ int, s string) error {
		if keys == nil || keys[key] {
			fn(s)
		}
		return nil
	})
}

// Strings calls fn for every string value in raw with the member key it
// belongs to ("" at the top or in a top-level array; an array element
// inherits its array's key) and its offsets in raw, quotes included.
// Member keys themselves are not visited (see Walk). An error from fn
// stops the walk.
func Strings(raw []byte, fn func(key string, start, end int, s string) error) error {
	return Walk(raw, func(s Str) error {
		if s.IsKey {
			return nil
		}
		return fn(s.Key, s.Start, s.End, s.Value)
	})
}

// Str is one string Walk visits: a value (Key is its member name) or a
// member name itself (IsKey; Obj is the offset of its object, so names of
// one object can be told apart from another's). Start and End are its
// offsets in the walked bytes, quotes included; Value is decoded.
type Str struct {
	Key        string
	IsKey      bool
	Obj        int
	Start, End int
	Value      string
}

// Walk calls fn for every string in raw: values and member names. A
// secret can sit in a name as easily as in a value.
func Walk(raw []byte, fn func(Str) error) error {
	trimmed := bytes.TrimLeftFunc(raw, unicode.IsSpace) // as bytes.TrimSpace
	lead := len(raw) - len(trimmed)
	return walk(bytes.TrimRightFunc(trimmed, unicode.IsSpace), lead, "", fn, 0)
}

// keySpan finds the member name string at or after from in an object's
// bytes (skipping white space and commas) and returns its end offset.
func keySpan(raw []byte, from int) (int, int, bool) {
	for from < len(raw) && (raw[from] == ',' || raw[from] == ' ' || raw[from] == '\t' || raw[from] == '\n' || raw[from] == '\r') {
		from++
	}
	if from >= len(raw) || raw[from] != '"' {
		return 0, 0, false
	}
	for i := from + 1; i < len(raw); i++ {
		switch raw[i] {
		case '\\':
			i++
		case '"':
			return from, i + 1, true
		}
	}
	return 0, 0, false
}

func walk(raw []byte, base int, key string, fn func(Str) error, depth int) error {
	if depth > MaxDepth {
		return ErrTooDeep
	}
	if len(raw) == 0 {
		return nil
	}
	switch raw[0] {
	case '"':
		if s, ok := StringValue(raw); ok {
			return fn(Str{Key: key, Obj: -1, Start: base, End: base + len(raw), Value: s})
		}
	case '{':
		fs, err := jsonrpc.Object(raw)
		if err != nil {
			return err
		}
		at := 1
		for _, f := range fs {
			ks, ke, ok := keySpan(raw, at)
			if !ok || ke > f.Start {
				return errors.New("member name not found") // cannot happen after Object
			}
			if err := fn(Str{IsKey: true, Obj: base, Start: base + ks, End: base + ke, Value: f.Key}); err != nil {
				return err
			}
			if err := walk(f.Value, base+f.Start, f.Key, fn, depth+1); err != nil {
				return err
			}
			at = f.End
		}
	case '[':
		els, err := ArrayElems(raw)
		if err != nil {
			return err
		}
		for _, e := range els {
			if err := walk(e.Raw, base+e.Start, key, fn, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// Edit replaces raw[Start:End] with With.
type Edit struct {
	Start, End int
	With       []byte
}

// Apply returns raw with every edit applied. Edits must not overlap.
func Apply(raw []byte, edits []Edit) ([]byte, error) {
	out := make([]byte, 0, len(raw))
	at := 0
	for _, e := range sortEdits(edits) {
		if e.Start < at || e.End < e.Start || e.End > len(raw) {
			return nil, fmt.Errorf("overlapping edit at %d", e.Start)
		}
		out = append(out, raw[at:e.Start]...)
		out = append(out, e.With...)
		at = e.End
	}
	return append(out, raw[at:]...), nil
}

func sortEdits(es []Edit) []Edit {
	out := append([]Edit(nil), es...)
	slices.SortFunc(out, func(a, b Edit) int { return cmp.Compare(a.Start, b.Start) })
	return out
}

// JoinArray builds a JSON array from raw elements.
func JoinArray(items []json.RawMessage) []byte {
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

// EncodeString is s as a JSON string, without HTML escaping (like the
// audit log), so '<' and '&' stay one byte.
func EncodeString(s string) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // a Go string always encodes (invalid UTF-8 becomes U+FFFD)
	return bytes.TrimRight(buf.Bytes(), "\n")
}
