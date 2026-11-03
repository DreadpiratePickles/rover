package daemon

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/config"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/policy"
	policyfiles "github.com/DreadpiratePickles/rover/policy"
)

// hidingPolicy permits echo and listing, and hides read_file.
const hidingPolicy = `
@id("echo-list") permit (principal, action == Action::"list_tools", resource == Server::"echo");
@id("echo-call") permit (principal, action == Action::"call_tool", resource == Tool::"echo/echo");
@id("hide-read-file") @rover_hide("true")
forbid (principal, action == Action::"call_tool", resource == Tool::"echo/read_file");
`

func engine(t *testing.T, src string) *policy.Engine {
	t.Helper()
	e, err := policy.Load([]byte(src), "test.cedar", policyfiles.Schema)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// syncBuf is a goroutine-safe audit sink.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *syncBuf) entries(t *testing.T) []audit.Entry {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if res := audit.Verify(bytes.NewReader(s.b.Bytes())); res.Err != nil {
		t.Fatalf("audit chain: %+v", res)
	}
	var out []audit.Entry
	for _, l := range bytes.Split(bytes.TrimSpace(s.b.Bytes()), []byte("\n")) {
		var e audit.Entry
		if err := json.Unmarshal(l, &e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

func dial(t *testing.T, s *Server) *ipc.Client {
	t.Helper()
	c, err := ipc.Dial(s.Addr(), hello(1, "echo"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func decide(t *testing.T, c *ipc.Client, dir, msg string) ipc.Frame {
	t.Helper()
	v, _, err := c.Decide(dir, []byte(msg))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func call(id, tool string) string {
	return `{"jsonrpc":"2.0","id":` + id + `,"method":"tools/call","params":{"name":"` + tool + `","arguments":{}}}`
}

func enforce() config.Config {
	c := config.Default()
	c.Mode = policy.ModeEnforce
	return c
}

func TestNoPolicyBlocksPolicedMessagesOnly(t *testing.T) {
	// Arrange
	var logged []string
	var mu sync.Mutex
	logf := func(f string, _ ...any) { mu.Lock(); logged = append(logged, f); mu.Unlock() }
	log := &syncBuf{}
	s := start(t, Options{Audit: audit.New(log), Logf: logf})
	c := dial(t, s)

	// Act
	blocked := decide(t, c, "c2s", call("1", "echo"))
	again := decide(t, c, "c2s", call("2", "echo"))
	ping := decide(t, c, "c2s", `{"jsonrpc":"2.0","id":3,"method":"ping"}`)

	// Assert
	if blocked.Action != ipc.ActionBlock || blocked.Reason != ReasonNoPolicy || again.Action != ipc.ActionBlock {
		t.Fatalf("tools/call without a policy: %+v", blocked)
	}
	if !bytes.Contains(blocked.ResponseRaw, []byte(`"isError":true`)) || !bytes.Contains(blocked.ResponseRaw, []byte(ReasonNoPolicy)) {
		t.Fatalf("response_raw = %s", blocked.ResponseRaw)
	}
	if ping.Action != ipc.ActionForward {
		t.Fatalf("ping must be forwarded: %+v", ping)
	}
	es := log.entries(t)
	if es[0].Action != "block" || es[0].Reason != ReasonNoPolicy || es[2].Action != "forward" {
		t.Fatalf("audit = %+v", es)
	}
	warnings := 0
	mu.Lock()
	for _, l := range logged {
		if strings.Contains(l, "NO POLICY") {
			warnings++
		}
	}
	mu.Unlock()
	if warnings != 1 {
		t.Fatalf("want one rate-limited warning, got %d", warnings)
	}
}

func TestHiddenToolIsBlockedAndFilteredFromList(t *testing.T) {
	// Arrange
	log := &syncBuf{}
	s := start(t, Options{Audit: audit.New(log), Policy: engine(t, hidingPolicy), Config: enforce()})
	c := dial(t, s)
	echoTool := `{"name":"echo","description":"Echo  text","inputSchema":{"type":"object"}}`
	list := `{"jsonrpc":"2.0","id":5,"result":{"tools":[` + echoTool + `,{"name":"read_file"}],"nextCursor":"x","extra":1}}`

	// Act
	read := decide(t, c, "c2s", call("4", "read_file"))
	echo := decide(t, c, "c2s", call("6", "echo"))
	listReq := decide(t, c, "c2s", `{"jsonrpc":"2.0","id":5,"method":"tools/list"}`)
	listRes := decide(t, c, "s2c", list)

	// Assert
	if read.Action != ipc.ActionBlock || len(read.RuleIDs) != 1 || read.RuleIDs[0] != "hide-read-file" {
		t.Fatalf("read_file verdict: %+v", read)
	}
	var r struct {
		ID     int `json:"id"`
		Result struct {
			IsError bool `json:"isError"`
			Content []struct{ Text string }
		} `json:"result"`
	}
	if err := json.Unmarshal(read.ResponseRaw, &r); err != nil || r.ID != 4 || !r.Result.IsError || !strings.Contains(r.Result.Content[0].Text, "hide-read-file") {
		t.Fatalf("response_raw %s (%v)", read.ResponseRaw, err)
	}
	if echo.Action != ipc.ActionForward || listReq.Action != ipc.ActionForward {
		t.Fatalf("echo %+v list %+v", echo, listReq)
	}
	want := `{"jsonrpc":"2.0","id":5,"result":{"tools":[` + echoTool + `],"nextCursor":"x","extra":1}}`
	if listRes.Action != ipc.ActionReplace || string(listRes.ReplacementRaw) != want {
		t.Fatalf("tools/list result:\n got %s\nwant %s", listRes.ReplacementRaw, want)
	}
	es := log.entries(t)
	if es[0].Action != "block" || es[0].RuleIDs[0] != "hide-read-file" || es[0].Reason == "" {
		t.Fatalf("audit of the block: %+v", es[0])
	}
	// The first list also pins both tools (M4): two "pin" entries come
	// before the entry of the list itself.
	if len(es) != 6 || es[3].Kind != AuditKindPin || es[4].Kind != AuditKindPin {
		t.Fatalf("pin entries: %+v", es)
	}
	if es[5].Action != "replace" || es[5].ReplyTo != "tools/list" {
		t.Fatalf("audit of the list: %+v", es[5])
	}
}

func TestObserveModeAuditsWouldDeny(t *testing.T) {
	// Arrange
	log := &syncBuf{}
	s := start(t, Options{Audit: audit.New(log), Policy: engine(t, hidingPolicy), Config: config.Default()})
	c := dial(t, s)

	// Act
	v := decide(t, c, "c2s", call("1", "read_file"))

	// Assert
	if v.Action != ipc.ActionForward || len(v.ResponseRaw) != 0 {
		t.Fatalf("observe mode must forward: %+v", v)
	}
	e := log.entries(t)[0]
	if e.Action != AuditWouldDeny || e.Reason != policy.ReasonWouldDeny || len(e.RuleIDs) != 1 {
		t.Fatalf("audit = %+v", e)
	}
}

func TestReadsPrivateToolSetsTouchedPrivateForTheNextDecision(t *testing.T) {
	// Arrange: a trifecta-style guard: no egress after private data.
	src := `
@id("all") permit (principal, action == Action::"call_tool", resource);
@id("no-egress-after-private") forbid (principal, action == Action::"call_tool", resource)
when { context.session.touched_private && resource.labels.contains("egress") };`
	cfg := enforce()
	cfg.Labels = map[string]map[string][]string{"echo": {"read_file": {"reads_private"}, "send": {"egress"}}}
	s := start(t, Options{Audit: audit.New(&syncBuf{}), Policy: engine(t, src), Config: cfg})
	c := dial(t, s)

	// Act
	before := decide(t, c, "c2s", call("1", "send"))
	decide(t, c, "s2c", okResult("1"))
	read := decide(t, c, "c2s", call("2", "read_file"))
	whilePending := decide(t, c, "c2s", call("3", "send"))
	decide(t, c, "s2c", okResult("2"))
	after := decide(t, c, "c2s", call("4", "send"))

	// Assert
	if before.Action != ipc.ActionForward || read.Action != ipc.ActionForward || whilePending.Action != ipc.ActionForward {
		t.Fatalf("before %+v read %+v pending %+v", before, read, whilePending)
	}
	if after.Action != ipc.ActionBlock || after.RuleIDs[0] != "no-egress-after-private" {
		t.Fatalf("egress after a successful reads_private must be blocked: %+v", after)
	}
	f := s.Sessions()[0].Flags()
	if !f.TouchedPrivate || f.SawUntrusted || f.Calls != 3 {
		t.Fatalf("session flags = %+v (blocked calls must not count)", f)
	}
}

func TestReloadSwapsPolicy(t *testing.T) {
	// Arrange
	s := start(t, Options{Audit: audit.New(&syncBuf{})})
	c := dial(t, s)
	if v := decide(t, c, "c2s", call("1", "echo")); v.Action != ipc.ActionBlock {
		t.Fatalf("no policy must block: %+v", v)
	}

	// Act
	if err := s.Reload(engine(t, hidingPolicy), enforce()); err != nil {
		t.Fatal(err)
	}

	// Assert
	if v := decide(t, c, "c2s", call("2", "echo")); v.Action != ipc.ActionForward {
		t.Fatalf("after reload echo must be permitted: %+v", v)
	}
}

func TestUnfilterableToolsListIsReplacedWithError(t *testing.T) {
	cases := map[string]string{
		"duplicate tools key": `{"jsonrpc":"2.0","id":9,"result":{"tools":[],"tools":[{"name":"read_file"}]}}`,
		"no tools array":      `{"jsonrpc":"2.0","id":9,"result":{"other":1}}`,
		"Tools beside tools":  `{"jsonrpc":"2.0","id":9,"result":{"tools":[{"name":"read_file"}],"Tools":[]}}`,
		"Name beside name":    `{"jsonrpc":"2.0","id":9,"result":{"tools":[{"name":"echo","Name":"read_file"}]}}`,
	}
	for name, res := range cases {
		t.Run(name, func(t *testing.T) {
			// Arrange
			log := &syncBuf{}
			s := start(t, Options{Audit: audit.New(log), Policy: engine(t, hidingPolicy), Config: enforce()})
			c := dial(t, s)
			decide(t, c, "c2s", `{"jsonrpc":"2.0","id":9,"method":"tools/list"}`)

			// Act
			v := decide(t, c, "s2c", res)

			// Assert
			if v.Action != ipc.ActionReplace || !bytes.Contains(v.ReplacementRaw, []byte(`"code":-32001`)) || !bytes.HasPrefix(v.ReplacementRaw, []byte(`{"jsonrpc":"2.0","id":9,`)) {
				t.Fatalf("verdict %+v (%s)", v, v.ReplacementRaw)
			}
			if e := log.entries(t)[1]; e.Action != "block" || !strings.HasPrefix(e.Reason, ReasonToolsListRejected) {
				t.Fatalf("audit = %+v", e)
			}
		})
	}
}

func TestUncorrelatedResultIsFilteredToo(t *testing.T) {
	// Arrange: a server "replies" to a tools/list nobody sent (or twice).
	s := start(t, Options{Audit: audit.New(&syncBuf{}), Policy: engine(t, hidingPolicy), Config: enforce()})
	c := dial(t, s)

	// Act
	v := decide(t, c, "s2c", `{"jsonrpc":"2.0","id":77,"result":{"tools":[{"name":"read_file"}]}}`)

	// Assert
	if v.Action != ipc.ActionReplace || bytes.Contains(v.ReplacementRaw, []byte("read_file")) {
		t.Fatalf("verdict %+v (%s)", v, v.ReplacementRaw)
	}
}

func TestSpliceResultRefusesAmbiguousMessages(t *testing.T) {
	for name, raw := range map[string]string{
		"duplicate result":  `{"jsonrpc":"2.0","id":1,"result":{},"result":{}}`,
		"Result and result": `{"jsonrpc":"2.0","id":1,"Result":{},"result":{}}`,
		"only Result":       `{"jsonrpc":"2.0","id":1,"Result":{}}`,
		"no result":         `{"jsonrpc":"2.0","id":1}`,
		"trailing data":     `{"jsonrpc":"2.0","id":1,"result":{}} {}`,
		"not an object":     `[]`,
	} {
		if _, err := spliceResult([]byte(raw), []byte(`{}`)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	got, err := spliceResult([]byte(`{ "id" : 1 , "result" : {"a": 1} , "z":2}`), []byte(`{"b":2}`))
	if err != nil || string(got) != `{ "id" : 1 , "result" : {"b":2} , "z":2}` {
		t.Fatalf("splice = %s, %v", got, err)
	}
}

// Review M2: `rm config.yaml && rover policy apply` reloaded the default
// config (observe) into an enforcing daemon. Until M9 adds OS
// authentication, a reload may tighten the mode but never loosen it.
func TestReloadRefusesEnforceToObserve(t *testing.T) {
	// Arrange
	s := start(t, Options{Audit: audit.New(&syncBuf{}), Policy: engine(t, hidingPolicy), Config: enforce()})
	c := dial(t, s)
	permitAll := engine(t, `permit (principal, action, resource);`)

	// Act
	err := s.Reload(permitAll, config.Default())

	// Assert: refused, and the previous policy and mode still apply.
	if !errors.Is(err, ErrModeDowngrade) || !strings.Contains(err.Error(), "refused: switching enforce -> observe needs OS authentication (M9)") {
		t.Fatalf("Reload err = %v", err)
	}
	if v := decide(t, c, "c2s", call("1", "read_file")); v.Action != ipc.ActionBlock {
		t.Fatalf("after a refused reload read_file must still be blocked: %+v", v)
	}
	// Enforce -> enforce and observe -> enforce are fine.
	if err := s.Reload(permitAll, enforce()); err != nil {
		t.Fatalf("enforce -> enforce: %v", err)
	}
	if v := decide(t, c, "c2s", call("2", "read_file")); v.Action != ipc.ActionForward {
		t.Fatalf("new enforce policy not applied: %+v", v)
	}
}

func TestReloadAllowsObserveToEnforce(t *testing.T) {
	s := start(t, Options{Audit: audit.New(&syncBuf{}), Policy: engine(t, hidingPolicy), Config: config.Default()})
	if err := s.Reload(engine(t, hidingPolicy), enforce()); err != nil {
		t.Fatalf("observe -> enforce: %v", err)
	}
	if err := s.Reload(engine(t, hidingPolicy), config.Default()); !errors.Is(err, ErrModeDowngrade) {
		t.Fatalf("enforce -> observe after the upgrade: %v", err)
	}
}
