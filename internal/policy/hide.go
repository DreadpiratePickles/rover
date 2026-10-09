package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
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
// The result comes from the server, so it is parsed strictly with
// jsonrpc.Object: duplicate or case-colliding keys ("tools" and "Tools") at
// the top level or in a tool object are an error, because a client that read
// the other copy could see a hidden tool.
func (e *Engine) FilterToolsList(server string, resultRaw []byte) (replacement []byte, hidden []string, changed bool, err error) {
	h := e.hidden[server]
	if len(h) == 0 {
		return resultRaw, nil, false, nil
	}
	members, err := jsonrpc.Object(resultRaw)
	if err != nil {
		return nil, nil, false, fmt.Errorf("%w: %w", ErrToolsList, err)
	}
	toolsAt := -1
	for i, m := range members {
		if m.Key == "tools" {
			toolsAt = i
		}
	}
	if toolsAt < 0 {
		return nil, nil, false, fmt.Errorf("%w: no tools array", ErrToolsList)
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(members[toolsAt].Value, &tools); err != nil {
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
	return spliceValue(resultRaw, members[toolsAt], joinArray(kept)), hidden, true, nil
}

// toolName returns the exact "name" string of one tool object, read strictly.
func toolName(raw json.RawMessage) (string, error) {
	fields, err := jsonrpc.Object(raw)
	if err != nil {
		return "", err
	}
	v, ok := fields.Get("name")
	if !ok {
		return "", errors.New("tool has no name")
	}
	var name string
	if err := json.Unmarshal(v, &name); err != nil {
		return "", errors.New("name is not a string")
	}
	return name, nil
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

// spliceValue returns raw with the bytes of member f replaced by v.
func spliceValue(raw []byte, f jsonrpc.Field, v []byte) []byte {
	out := make([]byte, 0, len(raw)-(f.End-f.Start)+len(v))
	out = append(out, raw[:f.Start]...)
	out = append(out, v...)
	return append(out, raw[f.End:]...)
}
