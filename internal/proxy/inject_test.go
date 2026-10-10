package proxy

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/rover/internal/ipc"
)

const roverElicit = `{"jsonrpc":"2.0","id":"rover-6f1c","method":"elicitation/create","params":{"message":"approve?","requestedSchema":{"type":"object","properties":{}}}}`

func TestInjectWritesOneRoverRequestToTheClient(t *testing.T) {
	// Arrange
	var client bytes.Buffer
	w := New(&fakeDecider{})

	// Act
	err := w.Inject([]byte(roverElicit), &client)

	// Assert
	if err != nil || client.String() != roverElicit+"\n" {
		t.Fatalf("err %v, client got %q", err, client.String())
	}
}

func TestInjectRefusesAnythingElse(t *testing.T) {
	bad := map[string]string{
		"not rover id":   `{"jsonrpc":"2.0","id":"x-1","method":"elicitation/create","params":{}}`,
		"number id":      `{"jsonrpc":"2.0","id":7,"method":"elicitation/create","params":{}}`,
		"other method":   `{"jsonrpc":"2.0","id":"rover-1","method":"sampling/createMessage","params":{}}`,
		"a notification": `{"jsonrpc":"2.0","method":"elicitation/create","params":{}}`,
		"two lines":      roverElicit + "\n" + roverElicit,
		"not json":       `rover-`,
	}
	for name, raw := range bad {
		var client bytes.Buffer
		if err := New(&fakeDecider{}).Inject([]byte(raw), &client); !errors.Is(err, ErrBadInject) || client.Len() != 0 {
			t.Errorf("%s: err %v, wrote %q", name, err, client.String())
		}
	}
}

// The client's reply to Rover's elicitation goes to roverd and never to the
// server, even if roverd (wrongly) said forward.
func TestReplyToRoverRequestNeverReachesTheServer(t *testing.T) {
	// Arrange
	reply := `{"jsonrpc":"2.0","id":"rover-6f1c","result":{"action":"accept","content":{}}}` + "\n"
	errReply := `{"jsonrpc":"2.0","id":"rover-6f1d","error":{"code":-1,"message":"no"}}` + "\n"
	normal := `{"jsonrpc":"2.0","id":"rover-is-just-a-name","method":"tools/call","params":{"name":"echo"}}` + "\n"
	d := &fakeDecider{verdicts: []ipc.Frame{{Action: ipc.ActionForward}, {Action: ipc.ActionForward}}}
	var server bytes.Buffer

	// Act
	err := New(d).Pump(strings.NewReader(reply+errReply+normal), &server, io.Discard, ClientToServer)

	// Assert
	if err != nil {
		t.Fatal(err)
	}
	if len(d.seen) != 3 || string(d.seen[0]) != reply {
		t.Fatalf("roverd must see every line, saw %q", d.seen)
	}
	if server.String() != normal {
		t.Fatalf("server got %q, want only the ordinary request", server.String())
	}
}

func TestServerToClientRoverIDIsNotSpecialInTheWrapper(t *testing.T) {
	// The wrapper only drops client replies; a server's message with a
	// rover- id is roverd's to judge (it blocks requests that borrow it).
	line := `{"jsonrpc":"2.0","id":"rover-1","result":{}}` + "\n"
	var client bytes.Buffer
	if err := New(&fakeDecider{}).Pump(strings.NewReader(line), &client, io.Discard, ServerToClient); err != nil {
		t.Fatal(err)
	}
	if client.String() != line {
		t.Fatalf("got %q", client.String())
	}
}

// Review M9 LOW: a release that says drop writes nothing to anyone.
func TestDropReleaseWritesNothing(t *testing.T) {
	line := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"x"}}` + "\n"
	var server, client bytes.Buffer
	if err := New(&fakeDecider{}).apply(ipc.Frame{Action: ipc.ActionBlock, Drop: true, Reason: "cancelled by client"}, []byte(line), &server, &client); err != nil {
		t.Fatal(err)
	}
	if server.Len() != 0 || client.Len() != 0 {
		t.Fatalf("server %q client %q", server.String(), client.String())
	}
}

func TestInjectAllowsCancellingRoversOwnRequestOnly(t *testing.T) {
	var client bytes.Buffer
	w := New(&fakeDecider{})
	if err := w.Inject([]byte(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"rover-1","reason":"decided"}}`), &client); err != nil {
		t.Fatal(err)
	}
	if err := w.Inject([]byte(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7}}`), &client); !errors.Is(err, ErrBadInject) {
		t.Fatalf("cancelling someone else's request: %v", err)
	}
}
