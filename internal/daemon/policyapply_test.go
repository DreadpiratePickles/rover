package daemon

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/rover/internal/approve"
	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/config"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/state"
)

type errAuth struct{ err error }

func (a errAuth) Authenticate(context.Context, string) (bool, string, error) {
	return false, "test", a.err
}

// Acceptance (M9 change): a client that speaks only the admin frame (no
// CLI, no nonce, nothing else) cannot get a policy approved or loaded
// unless roverd's own Authenticate says allow.
func TestPolicyApplyFrameAloneApprovesNothing(t *testing.T) {
	permitAll := engine(t, `permit (principal, action, resource);`)
	observe := config.Default()
	hash := strings.Repeat("ab", 32)
	for name, tc := range map[string]struct {
		auth     approve.Authenticator
		decision string
		reason   string
	}{
		"dialog says no":     {&testAuth{ok: false}, ApplyDenied, "OS authentication did not succeed"},
		"headless linux":     {errAuth{approve.ErrNoAuthAgent}, ApplyNoAuthAgent, "no_auth_agent"},
		"daemon cannot show": {errAuth{approve.ErrNotInteractive}, ApplyDenied, approve.ReasonNotInteractive},
		"dialog says yes":    {&testAuth{ok: true}, ApplyAllowed, ""},
	} {
		t.Run(name, func(t *testing.T) {
			// Arrange: enforcing, hiding policy; the files on disk permit all in observe.
			db, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()
			s := start(t, Options{Audit: audit.New(&syncBuf{}), Policy: engine(t, hidingPolicy), Config: enforce(), State: db,
				Authenticator: tc.auth, PolicyLoader: func() (Policy, config.Config, string, error) { return permitAll, observe, hash, nil }})
			c := dial(t, s)

			// Act
			wrong, werr := ipc.Admin(s.Addr(), ipc.Frame{Op: ipc.OpPolicyApply, Hash: strings.Repeat("cd", 32)})
			res, err := ipc.Admin(s.Addr(), ipc.Frame{Op: ipc.OpPolicyApply, Hash: hash})

			// Assert
			if werr == nil || !strings.Contains(werr.Error(), "changed since you looked") {
				t.Fatalf("a hash other than the files' must be refused before any dialog: %+v %v", wrong, werr)
			}
			if err != nil {
				t.Fatal(err)
			}
			var r ApplyResult
			if err := json.Unmarshal(res.Result, &r); err != nil || r.Decision != tc.decision || !strings.Contains(r.Reason, tc.reason) {
				t.Fatalf("result %s (%v)", res.Result, err)
			}
			cur, found, _ := approve.CurrentPolicy(db)
			v := decide(t, c, "c2s", call("1", "read_file"))
			if tc.decision == ApplyAllowed {
				if !found || cur.Hash != hash || cur.Method != "osauth:test" || v.Action != ipc.ActionForward {
					t.Fatalf("allowed: approved %+v (%v), read_file %+v", cur, found, v)
				}
				ta, _ := tc.auth.(*testAuth)
				ta.mu.Lock()
				defer ta.mu.Unlock()
				if len(ta.reasons) != 1 || ta.reasons[0] != "Rover: approve policy "+hash[:12]+" (1 permits, 0 forbids, mode observe)?" {
					t.Fatalf("dialog %q", ta.reasons)
				}
				return
			}
			if found || v.Action != ipc.ActionBlock {
				t.Fatalf("refused: approved %+v (%v) and read_file %+v; nothing may change", cur, found, v)
			}
		})
	}
}

func TestPolicyApplyWithoutLoaderIsRefused(t *testing.T) {
	s := start(t, Options{Audit: audit.New(&syncBuf{}), Authenticator: &testAuth{ok: true}})
	if _, err := ipc.Admin(s.Addr(), ipc.Frame{Op: ipc.OpPolicyApply, Hash: strings.Repeat("ab", 32)}); err == nil {
		t.Fatal("policy_apply without a loader and a state DB must fail")
	}
}

// Plan §4.3: notifications/cancelled naming a held id drops the hold.
func TestCancelledNotificationDropsTheHold(t *testing.T) {
	// Arrange
	auth := &testAuth{gate: map[string]chan bool{"echo.echo": make(chan bool)}}
	s, _ := approvalServer(t, auth, nil)
	c := dialEcho(t, s, "")
	v, rel, err := c.Decide("c2s", []byte(call("7", "echo")))
	if err != nil || v.Action != ipc.ActionHold {
		t.Fatalf("%+v %v", v, err)
	}

	// Act
	other := decide(t, c, "c2s", `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":8}}`)
	cancel := decide(t, c, "c2s", `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId": 7,"reason":"user stopped"}}`)
	var r ipc.Frame
	select {
	case r = <-rel:
	case <-time.After(10 * time.Second):
		t.Fatal("the cancelled hold was never released")
	}

	// Assert
	if other.Action != ipc.ActionForward || cancel.Action != ipc.ActionForward {
		t.Fatalf("the notifications themselves flow: %+v %+v", other, cancel)
	}
	if r.Action != ipc.ActionBlock || r.Reason != ReasonCancelledByClient {
		t.Fatalf("release %+v", r)
	}
}
