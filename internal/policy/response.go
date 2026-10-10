package policy

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
)

// CodeBlocked is the JSON-RPC error code Rover uses for a blocked request
// that is answered with an error rather than a tool result (plan §5.1).
const CodeBlocked = -32001

// blockText is the tool result text of a blocked tools/call. It speaks to
// the model: it explains the block and asks it not to retry, so an agent does
// not loop on the same forbidden call.
func blockText(reason string, ids []string) string {
	rule := "none"
	if len(ids) > 0 {
		rule = strings.Join(ids, ", ")
	}
	return "Blocked by Rover policy (rule " + rule + "): " + reason +
		". Do not retry this call; tell the user what you were trying to do."
}

type textContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type toolResult struct {
	Content []textContent `json:"content"`
	IsError bool          `json:"isError"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// blockResponse builds the JSON-RPC message sent back to the requester of a
// blocked request, or nil when the message has no id to answer (a
// notification, a result or an unparseable line).
//
// tools/call gets a normal result with isError: true, so the model reads the
// explanation; every other request gets error -32001.
//
// The id is spliced in as the request's original bytes (already a valid JSON
// value, checked by jsonrpc.Parse). Marshalling it would compact it and
// escape "<", ">" and "&" in a string id, and a client matches replies to
// requests by id.
func blockResponse(m jsonrpc.Message, reason string, ids []string) []byte {
	if m.Kind != jsonrpc.KindRequest || len(m.ID) == 0 {
		return nil
	}
	var member string
	var body any
	if m.Method == "tools/call" {
		member = "result"
		body = toolResult{Content: []textContent{{Type: "text", Text: blockText(reason, ids)}}, IsError: true}
	} else {
		member = "error"
		body = rpcError{Code: CodeBlocked, Message: "blocked by rover: " + reason}
	}
	enc, err := json.Marshal(body)
	if err != nil {
		// Unreachable: the body holds only strings, ints and bools. Still,
		// answer with a fixed error rather than nothing.
		member = "error"
		enc = []byte(`{"code":-32001,"message":"blocked by rover"}`)
	}
	var buf bytes.Buffer
	buf.Grow(len(enc) + len(m.ID) + 40)
	buf.WriteString(`{"jsonrpc":"2.0","id":`)
	buf.Write(m.ID)
	buf.WriteString(`,"` + member + `":`)
	buf.Write(enc)
	buf.WriteByte('}')
	return buf.Bytes()
}

// BlockResponse is the reply to a request blocked outside Decide (for
// example by roverd when no policy is loaded), in the same shape Decide
// uses: an isError result for tools/call, error -32001 otherwise. It is nil
// when the message has no id to answer.
func BlockResponse(m jsonrpc.Message, reason string, ids []string) []byte {
	return blockResponse(m, reason, ids)
}

// ErrorResponse is a JSON-RPC error -32001 reply carrying id (original
// bytes, which must be a valid JSON id) and "blocked by rover: <reason>".
// roverd uses it to replace a server response it refuses to forward, such
// as a tools/list result FilterToolsList could not parse.
func ErrorResponse(id []byte, reason string) []byte {
	if len(id) == 0 {
		id = []byte("null")
	}
	return blockResponse(jsonrpc.Message{Kind: jsonrpc.KindRequest, ID: id, Method: "rover/blocked"}, reason, nil)
}

// CodeInvalidRequest is JSON-RPC's "Invalid Request" error code.
const CodeInvalidRequest = -32600

// InvalidRequestResponse is the JSON-RPC error -32600 reply to a request
// roverd refused as invalid JSON-RPC (an ambiguous line), carrying id
// (original bytes, which must be a valid JSON id) and the reason.
func InvalidRequestResponse(id []byte, reason string) []byte {
	enc, err := json.Marshal(rpcError{Code: CodeInvalidRequest, Message: "Invalid Request: " + reason})
	if err != nil {
		enc = []byte(`{"code":-32600,"message":"Invalid Request"}`) // unreachable: strings and an int
	}
	var buf bytes.Buffer
	buf.WriteString(`{"jsonrpc":"2.0","id":`)
	buf.Write(id)
	buf.WriteString(`,"error":`)
	buf.Write(enc)
	buf.WriteByte('}')
	return buf.Bytes()
}
