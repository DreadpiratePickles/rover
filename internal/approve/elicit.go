package approve

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
)

// ElicitIDPrefix starts the id of every elicitation Rover sends; the
// wrapper and roverd key on it.
const ElicitIDPrefix = ipc.InjectIDPrefix

// NewElicitID returns "rover-<uuid>".
func NewElicitID() string { return ElicitIDPrefix + NewID() }

// BuildElicitation is the elicitation/create request Rover sends to the
// agent app for r (MCP 2025-06-18). The form asks nothing: the only answer
// that matters is accept or decline, and accept does not approve anything
// by itself (the OS dialog still has to succeed).
func BuildElicitation(id string, r Request) ([]byte, error) {
	msg := "rover: " + Clean(orUnknown(r.Client)) + " wants to run " + Clean(r.Server) + "." + Clean(r.Tool)
	if r.Summary != "" {
		msg += " (" + Clean(r.Summary) + ")"
	}
	msg += ". decline to refuse. to allow, accept and then confirm in the system authentication dialog."
	type schema struct {
		Type       string         `json:"type"`
		Properties map[string]any `json:"properties"`
	}
	type params struct {
		Message         string `json:"message"`
		RequestedSchema schema `json:"requestedSchema"`
	}
	out := struct {
		JSONRPC string `json:"jsonrpc"`
		ID      string `json:"id"`
		Method  string `json:"method"`
		Params  params `json:"params"`
	}{"2.0", id, "elicitation/create", params{msg, schema{"object", map[string]any{}}}}
	return json.Marshal(out)
}

// ErrBadElicitReply is a reply Rover cannot read; the OS dialog decides.
var ErrBadElicitReply = errors.New("unreadable elicitation reply")

// ParseElicitReply reads the client's answer: accepted is true only for a
// result whose action is exactly "accept"; "decline" and "cancel" are
// false. Anything else (an error reply, an unknown action, a duplicate
// key) is an error, which is never an approval.
func ParseElicitReply(m jsonrpc.Message) (accepted bool, err error) {
	if m.Kind == jsonrpc.KindError {
		return false, fmt.Errorf("%w: the client answered with an error", ErrBadElicitReply)
	}
	if m.Kind != jsonrpc.KindResult {
		return false, fmt.Errorf("%w: not a result", ErrBadElicitReply)
	}
	fields, err := jsonrpc.Object(m.Result)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrBadElicitReply, err)
	}
	raw, ok := fields.Get("action")
	var action string
	if !ok || json.Unmarshal(raw, &action) != nil {
		return false, fmt.Errorf("%w: no action", ErrBadElicitReply)
	}
	switch action {
	case "accept":
		return true, nil
	case "decline", "cancel":
		return false, nil
	}
	return false, fmt.Errorf("%w: unknown action %q", ErrBadElicitReply, Clean(action))
}
