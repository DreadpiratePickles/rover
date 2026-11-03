package daemon

import (
	"github.com/DreadpiratePickles/rover/internal/audit"
)

// AuditKindState is the audit "kind" of events about roverd's own state.
const AuditKindState = "state"

// stateLossReason is the audit reason when state.db vanished (review M4).
const stateLossReason = "state.db missing: all pins and approvals lost; every server is back to trust-on-first-use"

// reportStateLoss runs once at start. An audit history (the anchor file
// exists) with no state.db means the database was deleted or lost: every
// pin is gone and every server will be trusted on first use again, which
// an attacker who can delete one file would love to arrange quietly. So it
// is audited, logged loudly and notified. A failed audit write stops roverd.
//
// From M9 the same report covers a state.db roverd distrusts although it
// exists (Options.StateResetReason): one with no approved policy while the
// log has history, or with an approval newer than the log. roverd then runs
// with no policy in enforce mode.
func (s *Server) reportStateLoss() error {
	reason := s.o.StateResetReason
	if s.o.StateDBCreated && s.o.AuditHadHistory {
		reason = stateLossReason
	}
	if reason == "" {
		return nil
	}
	s.o.Logf("STATE LOST: %s", reason)
	e := audit.Entry{Time: s.o.Now().UTC(), Session: adminSession, Kind: AuditKindState, Action: "reset", Reason: reason}
	if err := s.writeAudit(e); err != nil {
		return err
	}
	s.o.Notifier.Notify("rover: state reset, no policy loaded", reason+". run `rover doctor`.")
	return nil
}

// writeAudit appends entries in order. On failure roverd turns unhealthy:
// every later decision is a block.
func (s *Server) writeAudit(entries ...audit.Entry) error {
	for _, e := range entries {
		if err := s.o.Audit.Write(e); err != nil {
			s.mu.Lock()
			s.unhealthy = true
			s.mu.Unlock()
			s.o.Logf("AUDIT LOG FAILED, blocking everything from now on: %v", err)
			return err
		}
	}
	return nil
}
