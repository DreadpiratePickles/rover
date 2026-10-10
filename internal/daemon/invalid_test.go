package daemon

import (
	"bytes"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/config"
	"github.com/DreadpiratePickles/rover/internal/ipc"
)

// The review's bypasses (C1): encoding/json read keys case-insensitively
// with last-wins, while Cedar and the server read them exactly. Each line
// below was judged as one thing and acted on as another. Now each is
// invalid JSON-RPC and blocked, whatever the mode and with or without a
// policy.
func TestKeyDifferentialsAreBlockedAsInvalid(t *testing.T) {
	cases := []struct {
		name, dir, msg string
		wantReply      bool
	}{
		{"Name beside name", "c2s", `{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"echo","Name":"read_file","arguments":{}}}`, true},
		{"Method beside method", "c2s", `{"jsonrpc":"2.0","id":11,"method":"tools/call","Method":"ping","params":{"name":"read_file","arguments":{}}}`, true},
		{"Method instead of method", "c2s", `{"jsonrpc":"2.0","id":11,"Method":"tools/call","params":{"name":"read_file","arguments":{}}}`, false},
		{"Result beside result", "s2c", `{"jsonrpc":"2.0","id":11,"result":{"tools":[{"name":"read_file"}]},"Result":{"tools":[]}}`, false},
		{"invalid notification", "s2c", `{"jsonrpc":"2.0","method":"notifications/x","extra":true}`, false},
	}
	configs := map[string]Options{
		"enforce":   {Policy: engine(t, hidingPolicy), Config: enforce()},
		"observe":   {Policy: engine(t, hidingPolicy), Config: config.Default()},
		"no policy": {},
	}
	for mode, opts := range configs {
		for _, c := range cases {
			t.Run(mode+"/"+c.name, func(t *testing.T) {
				// Arrange
				log := &syncBuf{}
				o := opts
				o.Audit = audit.New(log)
				o.Config.Labels = map[string]map[string][]string{"echo": {"read_file": {"reads_private"}}}
				s := start(t, o)
				cl := dial(t, s)

				// Act
				v := decide(t, cl, c.dir, c.msg)

				// Assert
				if v.Action != ipc.ActionBlock || !strings.HasPrefix(v.Reason, ReasonInvalidJSONRPC+": ") {
					t.Fatalf("verdict %+v", v)
				}
				if c.wantReply != (len(v.ResponseRaw) > 0) {
					t.Fatalf("response_raw = %s, want a reply: %v", v.ResponseRaw, c.wantReply)
				}
				if c.wantReply && (!bytes.Contains(v.ResponseRaw, []byte(`"code":-32600`)) || !bytes.HasPrefix(v.ResponseRaw, []byte(`{"jsonrpc":"2.0","id":11,"error":`))) {
					t.Fatalf("response_raw = %s", v.ResponseRaw)
				}
				e := log.entries(t)[0]
				if e.Action != ipc.ActionBlock || e.Kind != "invalid" || !strings.HasPrefix(e.Reason, ReasonInvalidJSONRPC) || e.Tool != "" {
					t.Fatalf("audit = %+v", e)
				}
				// M1: the blocked call is not counted and not labelled
				// with the tool the server would have run (read_file).
				if f := s.Sessions()[0].Flags(); f.TouchedPrivate || f.Calls != 0 {
					t.Fatalf("session flags = %+v", f)
				}
			})
		}
	}
}

func TestInitializeWithCollidingClientInfoIsBlocked(t *testing.T) {
	// Arrange
	s := start(t, Options{Audit: audit.New(&syncBuf{}), Policy: engine(t, hidingPolicy), Config: enforce()})
	c := dial(t, s)

	// Act
	bad := decide(t, c, "c2s", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"a","Name":"b"}}}`)

	// Assert
	if bad.Action != ipc.ActionBlock || !strings.Contains(bad.Reason, "clientInfo") || !bytes.Contains(bad.ResponseRaw, []byte(`-32600`)) {
		t.Fatalf("verdict %+v", bad)
	}
	if name, _ := s.Sessions()[0].Client(); name != "" {
		t.Fatalf("client name %q recorded from an ambiguous initialize", name)
	}
	good := decide(t, c, "c2s", `{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"clientInfo":{"name":"a","version":"1"}}}`)
	if name, ver := s.Sessions()[0].Client(); good.Action != ipc.ActionForward || name != "a" || ver != "1" {
		t.Fatalf("good %+v, client %q %q", good, name, ver)
	}
}
