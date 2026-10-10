package daemon

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/DreadpiratePickles/rover/internal/approve"
	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/config"
	"github.com/DreadpiratePickles/rover/internal/ipc"
)

// Fake secrets: right shape, valid nowhere.
const (
	fakeAKIA = "AKIAEXAMPLE000000001"
	fakeGHP  = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
)

const dlpPolicy = `@id("all") permit (principal, action == Action::"call_tool", resource);`

// dlpConfig labels echo.send egress and echo.echo plain.
func dlpConfig() config.Config {
	c := enforce()
	c.Labels = map[string]map[string][]string{"echo": {"send": {"egress"}, "echo": {}}}
	return c
}

func callArgsLine(id, tool, args string) string {
	return `{"jsonrpc":"2.0","id":` + id + `,"method":"tools/call","params":{"name":"` + tool + `","arguments":` + args + `}}`
}

func TestSecretsInResponsesAreRedactedBeforeTheAgentAndTheLog(t *testing.T) {
	for _, tc := range []struct{ name, reply string }{
		{"text block", `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"key=` + fakeAKIA + `"}]}}`},
		{"structuredContent", `{"jsonrpc":"2.0","id":1,"result":{"content":[],"structuredContent":{"creds":{"id":"` + fakeAKIA + `"}}}}`},
		{"resource block", `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"resource","resource":{"uri":"file:///x","text":"` + fakeAKIA + `"}}]}}`},
		{"error message", `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"bad key ` + fakeAKIA + `"}}`},
		{"split across two blocks", `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"key AKIAEXAMPLE"},{"type":"text","text":"000000001 end"}]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange: bodies logged.
			log := &syncBuf{}
			s := start(t, Options{Audit: audit.New(log), Policy: engine(t, dlpPolicy), Config: dlpConfig(), LogBodies: true})
			c := dial(t, s)
			decide(t, c, "c2s", call("1", "echo"))

			// Act
			v := decide(t, c, "s2c", tc.reply)

			// Assert
			if v.Action != ipc.ActionReplace || !strings.Contains(string(v.ReplacementRaw), "[REDACTED:aws-access-key]") ||
				strings.Contains(string(v.ReplacementRaw), "000000001") {
				t.Fatalf("verdict %+v\n%s", v, v.ReplacementRaw)
			}
			es := log.entries(t)
			last := es[len(es)-1]
			if strings.Contains(log.String(), "000000001") || strings.Join(last.Findings, ",") != "dlp:aws-access-key" ||
				!strings.Contains(string(last.Body), "[REDACTED:aws-access-key]") {
				t.Fatalf("audit %+v\n%s", last, log.String())
			}
		})
	}
}

func TestSecretInEgressArgsIsBlockedAndElsewhereAllowed(t *testing.T) {
	for _, mode := range []config.Config{dlpConfig(), func() config.Config { c := dlpConfig(); c.Mode = "observe"; return c }()} {
		// Arrange
		log := &syncBuf{}
		s := start(t, Options{Audit: audit.New(log), Policy: engine(t, dlpPolicy), Config: mode, LogBodies: true})
		c := dial(t, s)

		// Act
		blocked := decide(t, c, "c2s", callArgsLine("1", "send", `{"to":"a@example.com","body":"token `+fakeGHP+`"}`))
		allowed := decide(t, c, "c2s", callArgsLine("2", "echo", `{"text":"`+fakeGHP+`"}`))
		keyed := decide(t, c, "c2s", callArgsLine("3", "send", `{"password":"hunter2hunter2"}`))
		clean := decide(t, c, "c2s", callArgsLine("4", "send", `{"to":"a@example.com"}`))

		// Assert
		if blocked.Action != ipc.ActionBlock || blocked.Reason != "secret_in_egress_args:github-token" ||
			!strings.Contains(string(blocked.ResponseRaw), `"isError":true`) {
			t.Fatalf("%s: egress with a token: %+v", mode.Mode, blocked)
		}
		if allowed.Action != ipc.ActionForward || keyed.Reason != "secret_in_egress_args:generic-credential" || clean.Action != ipc.ActionForward {
			t.Fatalf("%s: %+v / %+v / %+v", mode.Mode, allowed, keyed, clean)
		}
		es := log.entries(t)
		if strings.Contains(log.String(), fakeGHP) || strings.Contains(log.String(), "hunter2") ||
			strings.Join(es[1].Findings, ",") != "dlp:github-token" {
			t.Fatalf("%s: audit %+v", mode.Mode, es)
		}
	}
}

// capturePrompter records the approval requests and denies each once go
// is closed (the release must come after the hold verdict).
type capturePrompter struct {
	mu      sync.Mutex
	reqs    []approve.Request
	proceed chan struct{}
}

func (p *capturePrompter) Prompt(ctx context.Context, r approve.Request) (approve.Decision, error) {
	p.mu.Lock()
	p.reqs = append(p.reqs, r)
	p.mu.Unlock()
	select {
	case <-p.proceed:
	case <-ctx.Done():
	}
	return approve.Decision{Method: "test", Reason: approve.ReasonDenied}, nil
}

func TestApprovalRecordHoldsRedactedArgs(t *testing.T) {
	// Arrange
	p := &capturePrompter{proceed: make(chan struct{})}
	s := start(t, Options{Audit: audit.New(&syncBuf{}), Policy: engine(t, approvalPolicy), Config: dlpConfig(), Prompter: p})
	c := dialEcho(t, s, "")

	// Act
	v, rel, err := c.Decide("c2s", []byte(callArgsLine("1", "echo", `{"text":"`+fakeAKIA+`","n":1}`)))
	close(p.proceed)
	if v.Action != ipc.ActionHold {
		t.Fatalf("verdict %+v", v)
	}
	waitRelease(t, rel)

	// Assert
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil || v.Action != ipc.ActionHold || len(p.reqs) != 1 {
		t.Fatalf("%+v %v %d", v, err, len(p.reqs))
	}
	if got := string(p.reqs[0].Args); got != `{"text":"[REDACTED:aws-access-key]","n":1}` {
		t.Fatalf("args %s", got)
	}
}

func TestLogLinesAreRedacted(t *testing.T) {
	var got []string
	logf := redactingLogf(s0().dlp, func(f string, _ ...any) { got = append(got, f) })
	logf("approval %s: %v", "x", "token "+fakeGHP)
	logf("plain %d", 1)
	if len(got) != 2 || strings.Contains(got[0], fakeGHP) || got[1] != "plain %d" {
		t.Fatalf("%q", got)
	}
}

func s0() *Server { return New(Options{}) }
