package jsonrpc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
)

// LESSON (M2 review, C1): encoding/json matches object keys to struct fields
// case-insensitively, and when two keys match the same field the last one
// wins. Cedar, package convert and most MCP servers match keys exactly. So
// {"name":"echo","Name":"read_file"} was "echo" to one reader and
// "read_file" to another: a parser differential. Object reads an object the
// strict way: exact keys, and any two keys that are equal ignoring case are
// refused, so every reader is forced to see the same thing.

// Errors returned by Object. Every error wraps exactly one of them.
var (
	ErrDuplicateKey = errors.New("duplicate key")
	ErrNotObject    = errors.New("not a JSON object")
	ErrInvalidJSON  = errors.New("invalid JSON")
)

// Field is one member of a JSON object: its exact key, its value's original
// bytes, and where those bytes sit in the input (input[Start:End] == Value).
type Field struct {
	Key        string
	Value      json.RawMessage
	Start, End int
}

// Fields are the members of an object in input order.
type Fields []Field

// Get returns the value of the member whose key is exactly key.
func (fs Fields) Get(key string) (json.RawMessage, bool) {
	for _, f := range fs {
		if f.Key == key {
			return f.Value, true
		}
	}
	return nil, false
}

// Object splits raw, which must be exactly one JSON object (surrounding
// white space allowed), into its top-level members. It refuses duplicate
// keys, keys equal under Unicode case folding (strings.EqualFold), invalid
// JSON and trailing data. Values are not inspected beyond being valid JSON.
func Object(raw []byte) (Fields, error) {
	return object(raw, true)
}

// object is Object; with strict false it allows repeated keys (they are all
// returned). Only salvage uses that, to find the id of a refused request.
func object(raw []byte, strict bool) (Fields, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidJSON, err)
	}
	if tok != json.Delim('{') {
		return nil, ErrNotObject
	}
	var out Fields
	seen := map[string]string{} // folded key -> first key
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidJSON, err)
		}
		key, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("%w: object key is not a string", ErrInvalidJSON)
		}
		fk := FoldKey(key)
		if first, dup := seen[fk]; dup && strict {
			return nil, fmt.Errorf("%w: %q and %q", ErrDuplicateKey, first, key)
		}
		if _, dup := seen[fk]; !dup {
			seen[fk] = key
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidJSON, err)
		}
		end := int(dec.InputOffset())
		out = append(out, Field{Key: key, Value: v, Start: end - len(v), End: end})
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, fmt.Errorf("%w: unterminated object", ErrInvalidJSON)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing data after the object", ErrInvalidJSON)
	}
	return out, nil
}

// FoldKey maps every rune to the smallest rune of its case-folding orbit,
// so two strings have the same FoldKey exactly when strings.EqualFold says
// they are equal ("K", "k" and the Kelvin sign all become "K").
func FoldKey(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		lo := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < lo {
				lo = f
			}
		}
		b.WriteRune(lo)
	}
	return b.String()
}
