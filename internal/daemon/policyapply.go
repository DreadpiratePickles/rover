package daemon

import (
	"errors"
	"fmt"

	"github.com/DreadpiratePickles/rover/internal/approve"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/policy"
)

// LESSON (M9): `rover policy apply` is only a messenger. It tells roverd
// "the human wants the files with hash H", and roverd itself shows the OS
// dialog. Anything the agent can reach (the socket, the CLI, a file in
// run/) can carry that message, and none of it can answer the dialog. So
// sending the admin frame from a script is exactly as powerless as sending
// it from the CLI. When no roverd runs, the CLI runs this same code
// in-process, and then the CLI is the process that shows the dialog.

// Policy apply decisions in the admin reply.
const (
	ApplyAllowed     = "allow"
	ApplyDenied      = "deny"
	ApplyNoAuthAgent = "no_auth_agent"
)

// AuditPolicyApproved is the audit action of an approved policy; its
// digest is the approved bundle hash.
const AuditPolicyApproved = "approved"

// ApplyResult is the admin reply to policy_apply.
type ApplyResult struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
	Hash     string `json:"hash"`
	Mode     string `json:"mode,omitempty"`
	Method   string `json:"method,omitempty"`
}

// applyPolicy loads the files on disk, checks they are the ones the human
// looked at (f.Hash), shows the dialog, and only on its yes records the
// hash as approved and loads the policy (an enforce -> observe switch
// included: it is just another approved policy).
func (s *Server) applyPolicy(f ipc.Frame) ipc.Frame {
	fail := func(err error) ipc.Frame { return ipc.Frame{Type: ipc.TypeError, Message: err.Error()} }
	if s.o.PolicyLoader == nil || s.o.State == nil {
		return fail(errors.New("policy_apply is not available in this process"))
	}
	pol, cfg, hash, err := s.o.PolicyLoader()
	if err != nil {
		return fail(fmt.Errorf("not applied: %w", err))
	}
	if hash != f.Hash {
		return fail(fmt.Errorf("not applied: the policy files changed since you looked (on disk %s, asked for %s)", short12(hash), short12(f.Hash)))
	}
	res := ApplyResult{Hash: hash, Mode: string(cfg.Mode)}
	method, err := s.authenticate(fmt.Sprintf("Rover: approve policy %s (%s, mode %s)?", short12(hash), policySummary(pol), cfg.Mode))
	if err != nil {
		res.Decision, res.Reason = ApplyDenied, err.Error()
		switch {
		case errors.Is(err, approve.ErrNoAuthAgent):
			res.Decision = ApplyNoAuthAgent
		case errors.Is(err, approve.ErrNotInteractive):
			res.Reason = approve.ReasonNotInteractive
		}
		_ = s.AuditPolicy("refused", "hash "+hash+": "+res.Reason, "")
		s.o.Logf("policy apply %s REFUSED: %s", short12(hash), res.Reason)
		return adminResult(res, "")
	}
	if err := approve.RecordPolicy(s.o.State, hash, method, s.o.Now()); err != nil {
		return fail(fmt.Errorf("not applied: recording the approval: %w", err))
	}
	if err := s.AuditPolicy(AuditPolicyApproved, "hash "+hash+" method "+method, hash); err != nil {
		return fail(err)
	}
	if err := s.ReloadWith(pol, cfg, true); err != nil {
		return fail(err)
	}
	if s.o.OnPolicyLoaded != nil {
		s.o.OnPolicyLoaded(cfg)
	}
	s.o.Logf("policy reloaded (mode %s); approved hash %s by %s", cfg.Mode, short12(hash), method)
	res.Decision, res.Method = ApplyAllowed, method
	return adminResult(res, "")
}

func short12(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// policySummary is "N permits, M forbids" for the apply dialog, so the
// human sees at a glance whether the policy they approve is the one they
// wrote (a permit-everything policy is one permit and no forbids).
func policySummary(p Policy) string {
	lister, ok := p.(interface{ Policies() []policy.Info })
	if !ok {
		return "policy"
	}
	var permits, forbids int
	for _, i := range lister.Policies() {
		if i.Effect == "forbid" {
			forbids++
		} else {
			permits++
		}
	}
	return fmt.Sprintf("%d permits, %d forbids", permits, forbids)
}
