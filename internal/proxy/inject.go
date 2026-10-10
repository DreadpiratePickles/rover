package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
)

// LESSON (M9): roverd sometimes needs to ask the agent app (the MCP client)
// a question of its own: "approve this call?" as an MCP elicitation. Only
// the wrapper is connected to the client, so roverd pushes the request in an
// inject frame and the wrapper writes it to the client side. The client's
// answer comes back on the client->server pipe like any other message, and
// this is the dangerous moment: forwarded to the server, it would tell a
// possibly hostile server what the human decided, and the server could have
// asked the same question itself. So a reply whose id starts with "rover-"
// goes to roverd (which matches it to the request it sent) and NEVER to the
// server, whatever the verdict says. roverd refuses such replies too, and
// blocks a server request that tries to borrow the "rover-" prefix.

// ErrBadInject refuses an inject frame that is not one Rover request.
var ErrBadInject = errors.New("refusing to inject")

// injectMethod is the only request roverd injects.
const injectMethod = "elicitation/create"

// Inject writes raw, a request roverd sends to the client, to toClient.
// It must be exactly one elicitation/create request with a string id that
// starts with ipc.InjectIDPrefix: the wrapper does not take roverd's word
// for it, so a bug in roverd cannot make it write anything else.
func (w *Wrapper) Inject(raw []byte, toClient io.Writer) error {
	if bytes.ContainsAny(raw, "\r\n") {
		return fmt.Errorf("%w: the message contains a newline", ErrBadInject)
	}
	m := jsonrpc.Parse(raw)
	if m.Kind != jsonrpc.KindRequest || m.Method != injectMethod || !ipc.IsInjectID(m.ID) {
		return fmt.Errorf("%w: want an %s request with a %q id", ErrBadInject, injectMethod, ipc.InjectIDPrefix)
	}
	_, err := toClient.Write(append(append([]byte{}, raw...), '\n'))
	return err
}

// isRoverReply reports whether a client->server line is a reply (result or
// error) to a request Rover injected. A cheap byte search first, so the
// common line costs no extra parse.
func isRoverReply(line []byte) bool {
	if !bytes.Contains(line, []byte(ipc.InjectIDPrefix)) {
		return false
	}
	m := jsonrpc.Parse(line)
	return (m.Kind == jsonrpc.KindResult || m.Kind == jsonrpc.KindError) && ipc.IsInjectID(m.ID)
}
