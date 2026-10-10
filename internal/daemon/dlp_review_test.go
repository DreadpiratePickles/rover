package daemon

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cedar-policy/cedar-go/types"

	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/learn"
	"github.com/DreadpiratePickles/rover/internal/state"
)

// Review findings (verification of M10): each was red before its fix.

// H1: a secret in a member name.
func TestSecretInMemberNameIsRedactedAndBlocksEgress(t *testing.T) {
	// Arrange
	log := &syncBuf{}
	s := start(t, Options{Audit: audit.New(log), Policy: engine(t, dlpPolicy), Config: dlpConfig(), LogBodies: true})
	c := dial(t, s)
	decide(t, c, "c2s", call("1", "echo"))

	// Act
	res := decide(t, c, "s2c", `{"jsonrpc":"2.0","id":1,"result":{"content":[],"structuredContent":{"`+fakeAKIA+`":"owner","[REDACTED:aws-access-key]":"taken"}}}`)
	egress := decide(t, c, "c2s", callArgsLine("2", "send", `{"`+fakeGHP+`":"x"}`))
	plain := decide(t, c, "c2s", callArgsLine("3", "echo", `{"`+fakeGHP+`":"x"}`))

	// Assert
	var v struct {
		Result struct{ StructuredContent map[string]string } `json:"result"`
	}
	if res.Action != ipc.ActionReplace || json.Unmarshal(res.ReplacementRaw, &v) != nil || len(v.Result.StructuredContent) != 2 ||
		v.Result.StructuredContent["[REDACTED:aws-access-key]#2"] != "owner" {
		t.Fatalf("result %+v %s", res, res.ReplacementRaw)
	}
	if egress.Action != ipc.ActionBlock || egress.Reason != "secret_in_egress_args:github-token" || plain.Action != ipc.ActionForward {
		t.Fatalf("egress %+v plain %+v", egress, plain)
	}
	if strings.Contains(log.String(), fakeAKIA) || strings.Contains(log.String(), fakeGHP) {
		t.Fatalf("audit holds a member-name secret:\n%s", log.String())
	}
}

// H2: redaction growing a result past the 16 MiB message cap.
func TestRedactionThatWouldOutgrowTheCapReplacesTheResult(t *testing.T) {
	for _, bodies := range []bool{true, false} {
		// Arrange: the verifier's input, 7.8 MB of "pwd=a1234567 ". Under
		// -race (which makes this take minutes) the cap and the input are
		// scaled down 16 times; the audit's own cut is tested in package audit.
		log := &syncBuf{}
		s := start(t, Options{Audit: audit.New(log), Policy: engine(t, dlpPolicy), Config: dlpConfig(), LogBodies: bodies})
		count := 600000
		if raceBuild {
			s.maxLine, count = maxReplacement/16, count/16
		}
		c := dial(t, s)
		text := strings.Repeat("pwd=a1234567 ", count)
		decide(t, c, "c2s", call("1", "echo"))

		// Act
		v := decide(t, c, "s2c", `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"`+text+`"}]}}`)
		req := decide(t, c, "c2s", callArgsLine("2", "echo", `{"text":"`+text+`"}`))
		after := decide(t, c, "c2s", `{"jsonrpc":"2.0","id":3,"method":"ping"}`)

		// Assert
		if v.Action != ipc.ActionReplace || len(v.ReplacementRaw) > s.maxLine ||
			!strings.Contains(string(v.ReplacementRaw), fmt.Sprintf("[Rover removed content: too many secrets to redact (%d matches)]", count)) ||
			!strings.Contains(string(v.ReplacementRaw), `"isError":false`) {
			t.Fatalf("bodies=%v: verdict %s %.300s", bodies, v.Action, v.ReplacementRaw)
		}
		// The request is refused by argument conversion (a string over
		// 1 MiB); what matters is that its audit entry, 20 MB once
		// redacted, is written (cut) and roverd stays healthy.
		if strings.Contains(req.Reason, "audit") || after.Action != ipc.ActionForward {
			t.Fatalf("bodies=%v: roverd must stay healthy: %+v %+v", bodies, req, after)
		}
		for _, line := range strings.Split(strings.TrimSpace(log.String()), "\n") {
			if len(line) > audit.MaxLine {
				t.Fatalf("audit line of %d bytes", len(line))
			}
		}
		if bodies && !raceBuild && !strings.Contains(log.String(), `"body_truncated":true`) {
			t.Fatal("the 20 MB redacted request body must be cut, not refused")
		}
		if res := audit.Verify(strings.NewReader(log.String())); res.Err != nil {
			t.Fatal(res.Err)
		}
	}
}

// M9 decided it, M10 keeps it: learn mode records nothing of a resource
// URI, not even scheme and host (a path or query is where a token, a
// customer name or a file name sits), and `rover policy propose` says so.
func TestLearnRecordsNoResourceURI(t *testing.T) {
	db, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := start(t, Options{Audit: audit.New(&syncBuf{}), State: db, Config: observe(),
		Policy: engine(t, `@id("r") permit (principal, action == Action::"read_resource", resource);`)})
	c := dial(t, s)
	decide(t, c, "c2s", `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"s3://backups/`+fakeAKIA+`/db.sql?token=hunter2hunter2"}}`)
	decide(t, c, "c2s", `{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"https://`+fakeGHP+`@github.com/acme/app?x=1"}}`)
	s.Close()
	var got []string
	for _, o := range dump(t, s) {
		got = append(got, o.Shape["uri"].Type+":"+o.Shape["uri"].Value)
		if o.Action != learn.ActionRead {
			t.Fatalf("%+v", o)
		}
	}
	if strings.Join(got, ",") != "string:,string:" {
		t.Fatalf("%v", got)
	}
}

// M2: sampling and elicitation requests reach the client redacted.
func TestServerRequestsAreRedactedTowardTheClient(t *testing.T) {
	pol := `@id("s") permit (principal, action == Action::"server_sampling", resource);
@id("e") permit (principal, action == Action::"server_elicitation", resource);`
	s := start(t, Options{Audit: audit.New(&syncBuf{}), Policy: engine(t, pol), Config: dlpConfig()})
	c := dial(t, s)
	for _, line := range []string{
		`{"jsonrpc":"2.0","id":"s1","method":"sampling/createMessage","params":{"systemPrompt":"key ` + fakeAKIA + `","messages":[{"role":"user","content":{"type":"text","text":"` + fakeGHP + `"}}],"maxTokens":10}}`,
		`{"jsonrpc":"2.0","id":"e1","method":"elicitation/create","params":{"message":"paste ` + fakeGHP + `","requestedSchema":{"type":"object","properties":{}}}}`,
	} {
		v := decide(t, c, "s2c", line)
		if v.Action != ipc.ActionReplace || strings.Contains(string(v.ReplacementRaw), fakeGHP) || !json.Valid(v.ReplacementRaw) {
			t.Fatalf("%+v %s", v, v.ReplacementRaw)
		}
	}
}

// The joint of two text blocks: a secret split across it is caught, with
// or without a credential name in front (re-verification NEW-1), and a
// complete secret does not swallow the next block across a line break.
func TestJointScanCatchesSplitsAndKeepsTheNextBlock(t *testing.T) {
	for _, tc := range []struct{ a, b, gone, kept string }{
		{"export GITHUB_TOKEN=ghp_a1b2c3", "d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8\n", "d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8", ""},
		{"token: ghp_a1b2c3d4e5f6g7h8", "i9j0k1l2m3n4o5p6q7r8 end", "i9j0k1l2m3n4o5p6q7r8", " end"},
		{"password=hunter2hu", "nter2x and more", "nter2x", " and more"},
		{"password=", "hunter2hunter2 and more", "hunter2hunter2", " and more"},
		{"key AKIAEXAMPLE", "000000001 end", "000000001", " end"},
		{"password=hunter2hunter2\n", "[default]\nregion=eu", "hunter2", "[default]\\nregion=eu"},
		{"password=hunter2hunter2 ", "[default] x", "hunter2", "[default] x"},
	} {
		s := start(t, Options{Audit: audit.New(&syncBuf{}), Policy: engine(t, dlpPolicy), Config: dlpConfig()})
		c := dial(t, s)
		decide(t, c, "c2s", call("1", "echo"))
		a, _ := json.Marshal(tc.a)
		b, _ := json.Marshal(tc.b)
		v := decide(t, c, "s2c", `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":`+string(a)+`},{"type":"text","text":`+string(b)+`}]}}`)
		out := string(v.ReplacementRaw)
		if v.Action != ipc.ActionReplace || strings.Contains(out, tc.gone) || !strings.Contains(out, tc.kept) {
			t.Errorf("%q | %q: %s", tc.a, tc.b, out)
		}
	}
}

// NEW-2: a rewritten sampling request is audited as replace, even in
// observe mode, with would_deny kept in the reason.
func TestRedactedServerRequestIsAuditedAsReplace(t *testing.T) {
	log := &syncBuf{}
	s := start(t, Options{Audit: audit.New(log), Policy: engine(t, `@id("n") forbid (principal, action == Action::"server_sampling", resource);`), Config: observe()})
	c := dial(t, s)
	v := decide(t, c, "s2c", `{"jsonrpc":"2.0","id":"s1","method":"sampling/createMessage","params":{"systemPrompt":"key `+fakeAKIA+`","messages":[],"maxTokens":1}}`)
	es := log.entries(t)
	e := es[len(es)-1]
	if v.Action != ipc.ActionReplace || e.Action != ipc.ActionReplace || !strings.Contains(e.Reason, AuditWouldDeny) || !strings.Contains(e.Reason, "redacted") {
		t.Fatalf("verdict %s, audit %+v", v.Action, e)
	}
}

func TestLearnShapeNamesAreRedacted(t *testing.T) {
	s := New(Options{})
	r := types.NewRecord(types.RecordMap{types.String(fakeAKIA): types.String("x"), "[REDACTED:aws-access-key]": types.Long(1)})
	out := s.redactRecord(r)
	if out.Len() != 2 || strings.Contains(fmt.Sprint(out), fakeAKIA) {
		t.Fatalf("%v", out)
	}
}
