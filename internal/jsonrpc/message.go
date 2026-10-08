// Package jsonrpc classifies JSON-RPC 2.0 messages as they cross the gateway.
//
// LESSON (A0): MCP is JSON-RPC 2.0. There are exactly four shapes of message:
//
//	request       {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{...}}
//	notification  {"jsonrpc":"2.0","method":"notifications/initialized"}      <- no id, no reply expected
//	result        {"jsonrpc":"2.0","id":1,"result":{...}}
//	error         {"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"..."}}
//
// A security gateway must classify every message correctly, because a policy
// that only looks at "requests" is bypassed by anything it mis-classifies.
// Anything we cannot classify is KindInvalid, and later modules (A2) treat
// invalid as "deny", never as "probably fine".
package jsonrpc

import (
	"bytes"
	"encoding/json"
)

type Kind string

const (
	KindRequest      Kind = "request"
	KindNotification Kind = "notification"
	KindResult       Kind = "result"
	KindError        Kind = "error"
	KindInvalid      Kind = "invalid"
)

// Message is our parsed view of one line. Raw is kept byte-for-byte so the
// proxy can forward exactly what it received (re-marshalling could silently
// change numbers, key order or unicode escapes - and then the thing we
// inspected is not the thing the server executes).
type Message struct {
	Kind   Kind
	ID     json.RawMessage // nil for notifications; may be a number or a string
	Method string
	Params json.RawMessage
	Result json.RawMessage
	Error  *RPCError
	Raw    []byte
}

type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

type wire struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  *string         `json:"method"`
	Params  json.RawMessage `json:"params"`
	Result  json.RawMessage `json:"result"`
	Error   *RPCError       `json:"error"`
}

// Parse classifies a single JSON-RPC message. It never returns an error:
// unparseable input comes back as KindInvalid so the caller decides what to do.
func Parse(line []byte) Message {
	raw := bytes.TrimSpace(line)
	m := Message{Raw: raw, Kind: KindInvalid}

	var w wire
	if err := json.Unmarshal(raw, &w); err != nil || w.JSONRPC != "2.0" {
		return m
	}
	hasID := len(w.ID) > 0 && !bytes.Equal(w.ID, []byte("null"))

	switch {
	case w.Method != nil && w.Result == nil && w.Error == nil:
		m.Method, m.Params = *w.Method, w.Params
		if hasID {
			m.Kind, m.ID = KindRequest, w.ID
		} else {
			m.Kind = KindNotification
		}
	case w.Method == nil && hasID && w.Result != nil && w.Error == nil:
		m.Kind, m.ID, m.Result = KindResult, w.ID, w.Result
	case w.Method == nil && w.Error != nil && w.Result == nil:
		// An error may have a null id (e.g. a parse error), so hasID is not required.
		m.Kind, m.Error = KindError, w.Error
		if hasID {
			m.ID = w.ID
		}
	}
	return m
}

// ToolName returns params.name for a tools/call request, or "".
func (m Message) ToolName() string {
	if m.Kind != KindRequest || m.Method != "tools/call" {
		return ""
	}
	var p struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(m.Params, &p)
	return p.Name
}
