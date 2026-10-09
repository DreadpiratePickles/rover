package daemon

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
)

// Helpers to read server JSON strictly (exact keys, no duplicates: see
// jsonrpc.Object) and to know where every value sits, so roverd can replace
// one string in a line and forward every other byte untouched.

// maxWalkDepth bounds how deep walkStrings descends; deeper is refused.
const maxWalkDepth = 64

// errTooDeep refuses JSON nested deeper than maxWalkDepth.
var errTooDeep = errors.New("JSON nested too deeply")

// elem is one element of a JSON array and its offsets in the array's bytes.
type elem struct {
	raw        json.RawMessage
	start, end int
}

// arrayElems splits raw, which must be one JSON array, into its elements.
func arrayElems(raw []byte) ([]elem, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
		return nil, errors.New("not a JSON array")
	}
	var out []elem
	for dec.More() {
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		end := int(dec.InputOffset())
		out = append(out, elem{raw: v, start: end - len(v), end: end})
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim(']') {
		return nil, errors.New("unterminated array")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after the array")
	}
	return out, nil
}

// field returns the member key of an object read strictly, if present.
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
	var s string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// walkStrings calls fn for every string value in raw (an object, array or
// scalar) whose member key is in keys, or every string when keys is nil.
// Objects are read strictly; nesting deeper than maxWalkDepth is an error.
func walkStrings(raw []byte, keys map[string]bool, fn func(string)) error {
	return walk(bytes.TrimSpace(raw), "", keys, fn, 0)
}

func walk(raw []byte, key string, keys map[string]bool, fn func(string), depth int) error {
	if depth > maxWalkDepth {
		return errTooDeep
	}
	if len(raw) == 0 {
		return nil
	}
	switch raw[0] {
	case '"':
		if s, ok := stringValue(raw); ok && (keys == nil || keys[key]) {
			fn(s)
		}
	case '{':
		fs, err := jsonrpc.Object(raw)
		if err != nil {
			return err
		}
		for _, f := range fs {
			if err := walk(f.Value, f.Key, keys, fn, depth+1); err != nil {
				return err
			}
		}
	case '[':
		els, err := arrayElems(raw)
		if err != nil {
			return err
		}
		for _, e := range els {
			if err := walk(e.raw, key, keys, fn, depth+1); err != nil {
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
	slices.SortFunc(out, func(a, b edit) int { return cmp.Compare(a.start, b.start) })
	return out
}

// joinArray builds a JSON array from raw elements.
func joinArray(items []json.RawMessage) []byte {
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
