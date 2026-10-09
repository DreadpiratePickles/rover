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
	"fmt"
)

// Kind is the shape of a JSON-RPC message: one of the Kind* constants.
type Kind string

// The four JSON-RPC message shapes, plus KindInvalid for anything else.
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
//
// For a KindInvalid message, Invalid says why, and ID and Method are still
// filled in when the line had a usable exact "id" and "method", so the
// requester can be told its request was refused (see InvalidRequest). An
// invalid line with no "method" keeps a usable, unambiguous "id" alone, so
// roverd can answer the request it claims to answer (see salvage).
type Message struct {
	Kind    Kind
	ID      json.RawMessage // nil for notifications; may be a number or a string
	Method  string
	Params  json.RawMessage
	Result  json.RawMessage
	Error   *RPCError
	Raw     []byte
	Invalid string // why the message is KindInvalid; "" otherwise
	// ResultAt and ErrorAt are where the "result" or "error" value sits in
	// Raw (Raw[ResultAt[0]:ResultAt[1]]), so a caller can rewrite it without
	// parsing the line again. Zero unless Kind is KindResult or KindError.
	ResultAt, ErrorAt [2]int
}

// RPCError is the "error" member of a JSON-RPC error response.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// envelope holds the exact members of one message; nil means absent.
type envelope struct {
	jsonrpc, id, method, params, result, err json.RawMessage
	resultAt, errAt                          [2]int
}

// Parse classifies a single JSON-RPC message. It never returns an error:
// unparseable or ambiguous input comes back as KindInvalid, with the reason
// in Invalid, so the caller decides what to do (roverd blocks it).
//
// Parsing is strict (see Object): exact member names only, no duplicate or
// case-colliding keys at the top level or in params, and no members beyond
// the six JSON-RPC defines. Anything a looser parser could read differently
// is invalid.
func Parse(line []byte) Message {
	raw := bytes.TrimSpace(line)
	m := Message{Raw: raw, Kind: KindInvalid}
	env, reason := readEnvelope(raw)
	if reason == "" {
		reason = m.classify(env)
	}
	if reason != "" {
		m.Invalid = reason
		m.Kind, m.Params, m.Result, m.Error = KindInvalid, nil, nil, nil
		m.ResultAt, m.ErrorAt = [2]int{}, [2]int{}
		m.salvage()
	}
	return m
}

// readEnvelope splits raw into the six JSON-RPC members, or returns why not.
func readEnvelope(raw []byte) (envelope, string) {
	var env envelope
	fields, err := Object(raw)
	if err != nil {
		return env, err.Error()
	}
	for _, f := range fields {
		switch f.Key {
		case "jsonrpc":
			env.jsonrpc = f.Value
		case "id":
			env.id = f.Value
		case "method":
			env.method = f.Value
		case "params":
			env.params = f.Value
		case "result":
			env.result, env.resultAt = f.Value, [2]int{f.Start, f.End}
		case "error":
			env.err, env.errAt = f.Value, [2]int{f.Start, f.End}
		default:
			return env, fmt.Sprintf("unknown member %q", f.Key)
		}
	}
	return env, ""
}

// classify fills m from env and returns "" or why env is not a valid message.
func (m *Message) classify(env envelope) string {
	var version string
	if json.Unmarshal(env.jsonrpc, &version) != nil || version != "2.0" {
		return `"jsonrpc" is not "2.0"`
	}
	if env.id != nil && !validID(env.id) {
		return `"id" is not a string, number or null`
	}
	hasID := env.id != nil && !bytes.Equal(env.id, []byte("null"))
	switch {
	case env.method != nil && env.result == nil && env.err == nil:
		if json.Unmarshal(env.method, &m.Method) != nil {
			return `"method" is not a string`
		}
		if why := checkParams(env.params); why != "" {
			return why
		}
		if m.Method == "initialize" {
			if _, _, why := clientInfo(env.params); why != "" {
				return why
			}
		}
		m.Params = env.params
		if hasID {
			m.Kind, m.ID = KindRequest, env.id
		} else {
			m.Kind = KindNotification
		}
	case env.method == nil && hasID && env.result != nil && env.err == nil && env.params == nil:
		m.Kind, m.ID, m.Result, m.ResultAt = KindResult, env.id, env.result, env.resultAt
	case env.method == nil && env.err != nil && env.result == nil && env.params == nil:
		e, why := parseError(env.err)
		if why != "" {
			return why
		}
		// An error may have a null id (e.g. a parse error), so hasID is not required.
		m.Kind, m.Error, m.ErrorAt = KindError, e, env.errAt
		if hasID {
			m.ID = env.id
		}
	default:
		return "not a request, notification, result or error"
	}
	return ""
}

// salvage keeps the exact id and method of an invalid message, when each
// appears exactly once and is usable, so roverd can answer an invalid
// request with -32600. They are never used to judge the message.
//
// Without a method the line may be an invalid response, and roverd answers
// the request it names (if one is pending) with an error. The id is then kept
// only when no key other than "id" folds to it ("Id", "ID"): a receiver that
// reads keys case-insensitively must not see a different id than we do.
func (m *Message) salvage() {
	m.ID, m.Method = nil, ""
	fields, err := object(m.Raw, false)
	if err != nil {
		return
	}
	var id, method json.RawMessage
	var ids, idVariants, methods int
	foldedID := FoldKey("id")
	for _, f := range fields {
		switch {
		case f.Key == "id":
			id, ids = f.Value, ids+1
		case f.Key == "method":
			method, methods = f.Value, methods+1
		case FoldKey(f.Key) == foldedID:
			idVariants++
		}
	}
	usableID := ids == 1 && validID(id) && !bytes.Equal(id, []byte("null"))
	if methods == 0 {
		if usableID && idVariants == 0 {
			m.ID = id
		}
		return
	}
	if methods != 1 || json.Unmarshal(method, &m.Method) != nil {
		m.Method = ""
		return
	}
	if usableID {
		m.ID = id
	}
}

// InvalidRequest reports whether m is KindInvalid but still carries an exact
// id and method: a request the requester is waiting for an answer to.
func (m Message) InvalidRequest() bool {
	return m.Kind == KindInvalid && m.ID != nil && m.Method != ""
}

// validID: JSON-RPC ids are strings, numbers or null.
func validID(id json.RawMessage) bool {
	switch id[0] {
	case '"', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'n':
		return true
	}
	return false
}

// checkParams: params, when present, is an object read strictly (no
// duplicate or case-colliding keys) or an array.
func checkParams(p json.RawMessage) string {
	if p == nil || p[0] == '[' {
		return ""
	}
	if _, err := Object(p); err != nil {
		return "params: " + err.Error()
	}
	return ""
}

// parseError reads the error object strictly, with exact member names.
func parseError(raw json.RawMessage) (*RPCError, string) {
	fields, err := Object(raw)
	if err != nil {
		return nil, "error: " + err.Error()
	}
	var e RPCError
	code, ok := fields.Get("code")
	if !ok || json.Unmarshal(code, &e.Code) != nil {
		return nil, `error: "code" is not an integer`
	}
	msg, ok := fields.Get("message")
	if !ok || json.Unmarshal(msg, &e.Message) != nil {
		return nil, `error: "message" is not a string`
	}
	e.Data, _ = fields.Get("data")
	return &e, ""
}

// clientInfo reads params.clientInfo of an initialize strictly: an object
// without duplicate or case-colliding keys whose exact "name" and "version",
// when present, are strings. A missing clientInfo, name or version is "".
// The name becomes the Cedar principal, so a reader that saw "Name" instead
// must be impossible (review C1).
func clientInfo(params json.RawMessage) (name, version, why string) {
	if params == nil || params[0] != '{' {
		return "", "", ""
	}
	pf, err := Object(params)
	if err != nil {
		return "", "", "params: " + err.Error()
	}
	raw, ok := pf.Get("clientInfo")
	if !ok {
		return "", "", ""
	}
	cf, err := Object(raw)
	if err != nil {
		return "", "", "clientInfo: " + err.Error()
	}
	for key, dst := range map[string]*string{"name": &name, "version": &version} {
		v, ok := cf.Get(key)
		if ok && (v[0] != '"' || json.Unmarshal(v, dst) != nil) { // null is not a string
			return "", "", "clientInfo: \"" + key + "\" is not a string"
		}
	}
	return name, version, ""
}

// ClientInfo returns the exact params.clientInfo name and version of an
// initialize request, or "" for each.
func (m Message) ClientInfo() (name, version string) {
	if m.Kind != KindRequest || m.Method != "initialize" {
		return "", ""
	}
	name, version, why := clientInfo(m.Params)
	if why != "" {
		return "", ""
	}
	return name, version
}

// ToolName returns the exact params.name of a tools/call request, or "".
func (m Message) ToolName() string {
	v := m.toolParam("name")
	var name string
	if v == nil || json.Unmarshal(v, &name) != nil {
		return ""
	}
	return name
}

// ToolArguments returns the original bytes of the exact params.arguments of
// a tools/call request, or nil.
func (m Message) ToolArguments() json.RawMessage {
	return m.toolParam("arguments")
}

func (m Message) toolParam(key string) json.RawMessage {
	if m.Kind != KindRequest || m.Method != "tools/call" {
		return nil
	}
	fields, err := Object(m.Params)
	if err != nil {
		return nil
	}
	v, _ := fields.Get(key)
	return v
}
