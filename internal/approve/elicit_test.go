package approve

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
)

func TestBuildElicitationIsAnMCPRequestWithARoverID(t *testing.T) {
	id := NewElicitID()
	raw, err := BuildElicitation(id, Request{Client: "claude-code", Server: "github", Tool: "push_files"})
	if err != nil {
		t.Fatal(err)
	}
	m := jsonrpc.Parse(raw)
	var got string
	_ = json.Unmarshal(m.ID, &got)
	if m.Kind != jsonrpc.KindRequest || m.Method != "elicitation/create" || got != id || !strings.HasPrefix(id, "rover-") {
		t.Fatalf("%s", raw)
	}
	if !strings.Contains(string(m.Params), `"requestedSchema":{"type":"object","properties":{}}`) {
		t.Fatalf("params %s", m.Params)
	}
}

func TestParseElicitReply(t *testing.T) {
	for line, want := range map[string]struct{ accepted, isErr bool }{
		`{"jsonrpc":"2.0","id":"rover-1","result":{"action":"accept","content":{}}}`:          {accepted: true},
		`{"jsonrpc":"2.0","id":"rover-1","result":{"action":"decline"}}`:                      {},
		`{"jsonrpc":"2.0","id":"rover-1","result":{"action":"cancel"}}`:                       {},
		`{"jsonrpc":"2.0","id":"rover-1","result":{"action":"ACCEPT"}}`:                       {isErr: true},
		`{"jsonrpc":"2.0","id":"rover-1","result":{"action":"decline","action":"accept"}}`:    {isErr: true},
		`{"jsonrpc":"2.0","id":"rover-1","result":{}}`:                                        {isErr: true},
		`{"jsonrpc":"2.0","id":"rover-1","error":{"code":-32601,"message":"no elicitation"}}`: {isErr: true},
	} {
		accepted, err := ParseElicitReply(jsonrpc.Parse([]byte(line)))
		if accepted != want.accepted || (err != nil) != want.isErr {
			t.Errorf("%s: accepted %v err %v", line, accepted, err)
		}
	}
}

// FuzzElicitReply: the client's reply is parsed in roverd; whatever it is,
// only an exact "accept" result may come back true.
func FuzzElicitReply(f *testing.F) {
	f.Add([]byte(`{"jsonrpc":"2.0","id":"rover-1","result":{"action":"accept"}}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":"rover-1","result":{"action":"accept"}}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":"rover-1","error":{"code":1,"message":"x"}}`))
	f.Fuzz(func(t *testing.T, line []byte) {
		m := jsonrpc.Parse(line)
		accepted, err := ParseElicitReply(m)
		if accepted && err != nil {
			t.Fatal("accepted with an error")
		}
		if accepted {
			fields, ferr := jsonrpc.Object(m.Result)
			raw, _ := fields.Get("action")
			var a string
			if ferr != nil || json.Unmarshal(raw, &a) != nil || a != "accept" {
				t.Fatalf("accepted %q", line)
			}
		}
	})
}
