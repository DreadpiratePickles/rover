package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/policy/normalize"
	policyfiles "github.com/DreadpiratePickles/rover/policy"
)

const permitEcho = `@id("allow-echo")
permit (principal, action == Action::"call_tool", resource == Tool::"echo/echo");`

func TestStarterDeniesServerRequestsAndToolCalls(t *testing.T) {
	// Arrange
	e, err := Load(policyfiles.Starter, "starter.cedar", policyfiles.Schema)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, dir, line, rule string
	}{
		{"sampling", DirS2C, `{"jsonrpc":"2.0","id":7,"method":"sampling/createMessage","params":{"messages":[]}}`, "starter-deny-sampling"},
		{"elicitation", DirS2C, `{"jsonrpc":"2.0","id":"e-1","method":"elicitation/create","params":{"message":"pin?"}}`, "starter-deny-elicitation"},
		{"tools/call", DirC2S, toolsCall("3", "echo", `{"text":"hi"}`), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Act
			out := e.Decide(input(c.dir, c.line))

			// Assert
			if out.Action != ipc.ActionBlock {
				t.Fatalf("action %q, want block", out.Action)
			}
			if c.rule == "" {
				if out.Reason != ReasonNoPermit || len(out.RuleIDs) != 0 {
					t.Fatalf("reason %q ids %v, want default deny", out.Reason, out.RuleIDs)
				}
				return
			}
			if !contains(out.RuleIDs, c.rule) || out.Reason != "forbid "+c.rule {
				t.Fatalf("reason %q ids %v, want %s", out.Reason, out.RuleIDs, c.rule)
			}
			var resp struct {
				ID    json.RawMessage
				Error struct {
					Code    int
					Message string
				}
			}
			if err := json.Unmarshal(out.Response, &resp); err != nil {
				t.Fatal(err)
			}
			if resp.Error.Code != CodeBlocked || resp.Error.Message != "blocked by rover: forbid "+c.rule {
				t.Fatalf("response %s", out.Response)
			}
		})
	}
}

func TestPermitLetsEchoThroughButReadFileIsBlockedWithRuleID(t *testing.T) {
	// Arrange
	e := mustLoad(t, permitEcho+`
@id("no-read-file") forbid (principal, action == Action::"call_tool", resource == Tool::"echo/read_file");`)

	// Act
	echo := e.Decide(input(DirC2S, toolsCall("1", "echo", `{"text":"hi"}`)))
	read := e.Decide(input(DirC2S, toolsCall(`"req-<2>"`, "read_file", `{"path":"/etc/passwd"}`)))

	// Assert
	if echo.Action != ipc.ActionForward || !contains(echo.RuleIDs, "allow-echo") {
		t.Fatalf("echo: %+v", echo)
	}
	if read.Action != ipc.ActionBlock {
		t.Fatalf("read_file: %+v", read)
	}
	want := `{"jsonrpc":"2.0","id":"req-<2>","result":{"content":[{"type":"text","text":"Blocked by Rover policy (rule no-read-file): forbid no-read-file. Do not retry this call; tell the user what you were trying to do."}],"isError":true}}`
	if string(read.Response) != want {
		t.Fatalf("response\n got %s\nwant %s", read.Response, want)
	}
}

func TestListToolsAndResourcesReadBlockWithJSONRPCError(t *testing.T) {
	// Arrange
	e := mustLoad(t, permitEcho)
	lines := []string{
		`{"jsonrpc":"2.0","id":4,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":5,"method":"resources/read","params":{"uri":"file:///etc/hosts"}}`,
	}
	for _, line := range lines {
		// Act
		out := e.Decide(input(DirC2S, line))

		// Assert
		if out.Action != ipc.ActionBlock {
			t.Fatalf("%s: %+v", line, out)
		}
		mustContain(t, out.Response, `"error":{"code":-32001,"message":"blocked by rover: no permit matched"}`)
	}
}

func TestUnpolicedMessagesAreForwarded(t *testing.T) {
	// Arrange
	e := mustLoad(t, permitEcho)
	cases := []struct{ dir, line string }{
		{DirC2S, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`},
		{DirC2S, `{"jsonrpc":"2.0","method":"notifications/initialized"}`},
		{DirS2C, `{"jsonrpc":"2.0","id":1,"result":{}}`},
		{DirS2C, `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"x"}}`}, // tools/call is a c2s method
	}
	for _, c := range cases {
		// Act
		out := e.Decide(input(c.dir, c.line))

		// Assert
		if out.Action != ipc.ActionForward || out.Reason != "" {
			t.Errorf("%s: %+v", c.line, out)
		}
	}
}

func TestObserveModeForwardsDenyAsWouldDeny(t *testing.T) {
	// Arrange
	e := mustLoad(t, permitEcho)
	in := input(DirC2S, toolsCall("1", "read_file", `{"path":"/x"}`))
	in.Mode = ModeObserve

	// Act
	out := e.Decide(in)

	// Assert
	if out.Action != ipc.ActionForward || !out.WouldDeny || out.Reason != ReasonWouldDeny || out.Response != nil {
		t.Fatalf("%+v", out)
	}
}

func TestConversionFailuresBlockEvenInObserveMode(t *testing.T) {
	// Arrange
	e := mustLoad(t, `permit (principal, action == Action::"call_tool", resource);`)
	cases := map[string]string{
		"args_duplicate_keys": toolsCall("1", "echo", `{"text":"a","text":"b"}`),
		"args_not_object":     toolsCall("1", "echo", `["a"]`),
		"args_too_complex":    toolsCall("1", "echo", deepJSON(17)),
	}
	for reason, line := range cases {
		in := input(DirC2S, line)
		in.Mode = ModeObserve

		// Act
		out := e.Decide(in)

		// Assert
		if out.Action != ipc.ActionBlock || out.Reason != reason || out.WouldDeny {
			t.Errorf("%s: %+v", reason, out)
		}
	}
}

func TestDuplicateToolNameInEnvelopeBlocks(t *testing.T) {
	// Arrange: a parser keeping the first "name" would run read_file.
	e := mustLoad(t, permitEcho)
	line := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","name":"echo","arguments":{}}}`

	// Act
	out := e.Decide(input(DirC2S, line))

	// Assert: the strict envelope parse already refuses it (review C1).
	if out.Action != ipc.ActionBlock || out.Reason != ReasonInvalidJSONRPC+`: params: duplicate key: "name" and "name"` {
		t.Fatalf("%+v", out)
	}
	mustContain(t, out.Response, `"code":-32600`)
}

func TestInvalidLinesBlockInEveryMode(t *testing.T) {
	// Arrange: before review C1 these were judged as echo / ping.
	e := mustLoad(t, permitEcho)
	lines := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","Name":"read_file","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","Method":"ping","params":{"name":"read_file","arguments":{}}}`,
	}
	for _, mode := range []Mode{ModeEnforce, ModeObserve} {
		for _, l := range lines {
			in := input(DirC2S, l)
			in.Mode = mode

			// Act
			out := e.Decide(in)

			// Assert
			if out.Action != ipc.ActionBlock || !strings.HasPrefix(out.Reason, ReasonInvalidJSONRPC+": ") || out.WouldDeny || !Policed(DirC2S, in.Msg) {
				t.Errorf("%s %s: %+v", mode, l, out)
			}
		}
	}
}

func TestDepthSixteenArgumentsAreAllowed(t *testing.T) {
	// Arrange
	e := mustLoad(t, permitEcho)

	// Act
	out := e.Decide(input(DirC2S, toolsCall("1", "echo", deepJSON(16))))

	// Assert
	if out.Action != ipc.ActionForward {
		t.Fatalf("%+v", out)
	}
}

// deepJSON returns an object nested depth levels deep, counting itself.
func deepJSON(depth int) string {
	s := `1`
	for i := 0; i < depth; i++ {
		s = `{"a":` + s + `}`
	}
	return s
}

func TestNormalisedPathDecidesProjectAccess(t *testing.T) {
	// Arrange
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "notes.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := mustLoad(t, `@id("fs-projects")
permit (principal, action == Action::"call_tool", resource in Server::"echo")
when { context.norm.path.under_projects };`)
	base := func(path string) Input {
		args, _ := json.Marshal(map[string]string{"path": path})
		in := input(DirC2S, toolsCall("1", "read_file", string(args)))
		in.Roots = []normalize.Root{{Name: "projects", Path: root}}
		in.Normalizers = normalize.Rules{"path": normalize.KindPath}
		return in
	}

	// Act
	escape := e.Decide(base(filepath.Join(root, "..", "etc", "passwd")))
	relative := e.Decide(base("../etc/passwd"))
	inside := e.Decide(base(filepath.Join(root, "notes.txt")))

	// Assert
	if escape.Action != ipc.ActionBlock || relative.Action != ipc.ActionBlock {
		t.Fatalf("escape %+v\nrelative %+v", escape, relative)
	}
	if !contains(relative.Findings, "path_relative") {
		t.Errorf("relative findings %v, want path_relative", relative.Findings)
	}
	if inside.Action != ipc.ActionForward || !contains(inside.RuleIDs, "fs-projects") {
		t.Fatalf("inside %+v", inside)
	}
}

// Review H1: "~/projects/../.ssh" used to be joined onto the root and judged
// under_projects, while the server expands "~" to $HOME and reads ~/.ssh.
func TestTildePathIsDeniedUnderProjectsPermit(t *testing.T) {
	// Arrange
	root := t.TempDir()
	e := mustLoad(t, `@id("fs-projects")
permit (principal, action == Action::"call_tool", resource in Server::"echo")
when { context.norm.path.under_projects };`)
	for _, mode := range []Mode{ModeEnforce, ModeObserve} {
		in := input(DirC2S, toolsCall("1", "read_file", `{"path":"~/projects/../.ssh"}`))
		in.Mode = mode
		in.Roots = []normalize.Root{{Name: "projects", Path: root}}
		in.Normalizers = normalize.Rules{"path": normalize.KindPath}

		// Act
		out := e.Decide(in)

		// Assert
		if out.Action != ipc.ActionBlock || out.Reason != ReasonNormReject {
			t.Fatalf("%s: %+v", mode, out)
		}
	}
}

func TestNormaliserRejectBlocks(t *testing.T) {
	// Arrange
	e := mustLoad(t, `permit (principal, action == Action::"call_tool", resource);`)
	in := input(DirC2S, toolsCall("1", "read_file", `{"path":"/tmp/a\u0000b"}`))
	in.Roots = []normalize.Root{{Name: "projects", Path: t.TempDir()}}
	in.Normalizers = normalize.Rules{"path": normalize.KindPath}
	in.Mode = ModeObserve

	// Act
	out := e.Decide(in)

	// Assert
	if out.Action != ipc.ActionBlock || out.Reason != ReasonNormReject {
		t.Fatalf("%+v", out)
	}
}

func TestApprovalAnnotationBlocksUntilM9(t *testing.T) {
	// Arrange
	e := mustLoad(t, `@id("ask") @rover_require("approval")
permit (principal, action == Action::"call_tool", resource == Tool::"echo/echo");`)

	// Act
	out := e.Decide(input(DirC2S, toolsCall("1", "echo", `{}`)))

	// Assert
	if out.Action != ipc.ActionBlock || out.Reason != ReasonApprovalM2 || !contains(out.RuleIDs, "ask") {
		t.Fatalf("%+v", out)
	}
}

func TestErroringForbidCountsAsFired(t *testing.T) {
	// Arrange: the call has no "url" argument, so the forbid cannot evaluate.
	e := mustLoad(t, permitEcho+`
@id("no-evil-host") forbid (principal, action == Action::"call_tool", resource)
when { context.norm.url.host == "evil.example" };`)

	// Act
	out := e.Decide(input(DirC2S, toolsCall("1", "echo", `{}`)))

	// Assert
	if out.Action != ipc.ActionBlock || !contains(out.RuleIDs, "no-evil-host") {
		t.Fatalf("%+v", out)
	}
}

func TestTimeContextUsesInjectedClock(t *testing.T) {
	// Arrange
	e := mustLoad(t, `permit (principal, action == Action::"call_tool", resource) when { context.time.hour < 6 };`)
	night := input(DirC2S, toolsCall("1", "echo", `{}`))
	night.Now = fixedNow.Add(-10 * time.Hour) // 04:30
	day := input(DirC2S, toolsCall("1", "echo", `{}`))

	// Act
	atNight, atDay := e.Decide(night), e.Decide(day)

	// Assert
	if atNight.Action != ipc.ActionForward || atDay.Action != ipc.ActionBlock {
		t.Fatalf("night %+v\nday %+v", atNight, atDay)
	}
}

func TestLabelsAndSessionReachThePolicy(t *testing.T) {
	// Arrange
	src, err := os.ReadFile(filepath.Join("..", "..", "policy", "templates", "trifecta-guard.cedar"))
	if err != nil {
		t.Fatal(err)
	}
	e := mustLoad(t, permitEcho+"\n"+string(src))
	in := input(DirC2S, toolsCall("1", "echo", `{}`))
	in.Labels = map[string][]string{"echo": {"egress"}}
	in.Session = SessionCtx{TouchedPrivate: true, SawUntrusted: true, Calls: 3}

	// Act
	out := e.Decide(in)

	// Assert
	if out.Action != ipc.ActionBlock || !contains(out.RuleIDs, "trifecta-no-egress") {
		t.Fatalf("%+v", out)
	}
}

func TestInvalidDirectionBlocks(t *testing.T) {
	// Arrange
	e := mustLoad(t, permitEcho)

	// Act
	out := e.Decide(input("sideways", toolsCall("1", "echo", `{}`)))

	// Assert
	if out.Action != ipc.ActionBlock || out.Reason != ReasonInvalidDirection {
		t.Fatalf("%+v", out)
	}
}
