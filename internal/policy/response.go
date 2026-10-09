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
