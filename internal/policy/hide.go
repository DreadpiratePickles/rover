package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
)

// ErrToolsList wraps every FilterToolsList parse failure. On this error the
// caller must not forward the original result (it may list a hidden tool):
// it should replace it with an error or drop it.
var ErrToolsList = errors.New("tools/list result rejected")

// HiddenTools returns the sorted names of the tools of server hidden by a
// @rover_hide("true") forbid.
func (e *Engine) HiddenTools(server string) []string {
	h := e.hidden[server]
	if len(h) == 0 {
		return nil
	}
	out := make([]string, 0, len(h))
	for t := range h {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// FilterToolsList removes the hidden tools of server from the "result"
// member of a tools/list response.
//
// When nothing is hidden it returns changed=false and the caller forwards
// the original message untouched. Otherwise the result is rebuilt from the
// original bytes of every other member and every remaining tool, so nothing
// but the hidden entries changes (nextCursor and unknown keys included).
//
// The result comes from the server, so it is parsed strictly: duplicate keys
// at the top level or in a tool's "name" are an error, because a client that
// read a different duplicate could see a hidden tool.
func (e *Engine) FilterToolsList(server string, resultRaw []byte) (replacement []byte, hidden []string, changed bool, err error) {
	h := e.hidden[server]
	if len(h) == 0 {
		return resultRaw, nil, false, nil
	}
	members, err := objectMembers(resultRaw)
	if err != nil {
		return nil, nil, false, fmt.Errorf("%w: %w", ErrToolsList, err)
	}
	toolsAt := -1
	for i, m := range members {
		if m.key == "tools" {
			toolsAt = i
		}
	}
	if toolsAt < 0 {
		return nil, nil, false, fmt.Errorf("%w: no tools array", ErrToolsList)
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(members[toolsAt].value, &tools); err != nil {
		return nil, nil, false, fmt.Errorf("%w: tools: %w", ErrToolsList, err)
	}
	kept := make([]json.RawMessage, 0, len(tools))
	for i, t := range tools {
		name, err := toolName(t)
		if err != nil {
			return nil, nil, false, fmt.Errorf("%w: tool %d: %w", ErrToolsList, i, err)
		}
		if h[name] {
			hidden = append(hidden, name)
			continue
		}
		kept = append(kept, t)
	}
	if len(hidden) == 0 {
		return resultRaw, nil, false, nil
	}
	members[toolsAt].value = joinArray(kept)
	return encodeObject(members), hidden, true, nil
}

type member struct {
	key   string
	value json.RawMessage
}

// objectMembers splits a JSON object into its members, in order, keeping
// each value's original bytes. Duplicate keys are an error.
func objectMembers(raw []byte) ([]member, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	var out []member
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, errors.New("object key is not a string")
		}
		if seen[key] {
			return nil, fmt.Errorf("duplicate key %q", key)
		}
		seen[key] = true
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		out = append(out, member{key: key, value: v})
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, errors.New("unterminated object")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after object")
	}
	return out, nil
}

// toolName returns the "name" string of one tool object.
func toolName(raw json.RawMessage) (string, error) {
	members, err := objectMembers(raw)
	if err != nil {
		return "", err
	}
	for _, m := range members {
		if m.key == "name" {
			var name string
			if err := json.Unmarshal(m.value, &name); err != nil {
				return "", errors.New("name is not a string")
			}
			return name, nil
		}
	}
	return "", errors.New("tool has no name")
}

func joinArray(items []json.RawMessage) json.RawMessage {
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, it := range items {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(it)
	}
	buf.WriteByte(']')
	return buf.Bytes()
}

func encodeObject(members []member) []byte {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, m := range members {
		if i > 0 {
			buf.WriteByte(',')
		}
		k, _ := json.Marshal(m.key) // marshalling a string cannot fail
		buf.Write(k)
		buf.WriteByte(':')
		buf.Write(m.value)
	}
	buf.WriteByte('}')
	return buf.Bytes()
}
