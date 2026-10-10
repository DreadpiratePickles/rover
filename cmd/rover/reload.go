package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/DreadpiratePickles/rover/internal/approve"
	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/config"
	"github.com/DreadpiratePickles/rover/internal/daemon"
	"github.com/DreadpiratePickles/rover/internal/paths"
	"github.com/DreadpiratePickles/rover/internal/policy"
	"github.com/DreadpiratePickles/rover/internal/state"
)

// notApproved is the config roverd runs with when the policy on disk is
// not the approved one: no policy (every policed message is blocked) and
// enforce, so nothing about the unapproved config.yaml takes effect.
func notApproved() config.Config {
	c := config.Default()
	c.Mode = policy.ModeEnforce
	return c
}

// policyLoader is daemon.Options.PolicyLoader: the files as they are on
// disk now, and their bundle hash.
func policyLoader(dirs paths.Dirs) func() (daemon.Policy, config.Config, string, error) {
	return func() (daemon.Policy, config.Config, string, error) {
		pol, cfg, _, hash, err := loadAll(dirs)
		return pol, cfg, hash, err
	}
}

// startFacts are what roverd knows about its own history at start.
type startFacts struct {
	lastAudit    time.Time // the newest audit entry's time
	stateCreated bool      // state.db was just created
	history      auditHistory
}

// auditHistory is what the audit log says about Rover's past (review M9).
type auditHistory struct {
	// any: at least one entry other than a refused policy: something a
	// roverd session recorded, a pin or tamper change, or an approved
	// policy. A declined init dialog alone is not history.
	any bool
	// approved is the hash of the latest `policy approved` entry, "" if none.
	approved string
	last     time.Time // the newest entry's time
}

// readHistory scans the audit log (all rotated files).
func readHistory(logPath string) (auditHistory, error) {
	var h auditHistory
	err := audit.Scan(logPath, func(e audit.Entry) {
		if e.Time.After(h.last) {
			h.last = e.Time
		}
		switch {
		case e.Kind == daemon.AuditKindPolicy && e.Action == daemon.AuditPolicyApproved:
			h.approved, h.any = e.Digest, true
		case e.Kind != daemon.AuditKindPolicy:
			h.any = true
		}
	})
	return h, err
}

// loadApprovedAtStart loads the policy and checks its hash against
// approved_policy (M9). A policy nobody approved is not loaded; roverd
// then blocks every policed message until `rover policy apply`.
//
// It also distrusts approved_policy itself when the database cannot be the
// one roverd wrote (review M9 HIGH): it was just created while the audit
// log has history, it has no approval while the log has history, or its
// approval is newer than the newest audit entry (roverd audits every
// approval it records, so a newer record was written by someone else).
// reset is then the reason, which roverd audits and notifies (state reset).
func loadApprovedAtStart(dirs paths.Dirs, db *state.DB, f startFacts, logf func(string, ...any)) (pol daemon.Policy, cfg config.Config, note, reset string) {
	pol, cfg, note, hash, err := loadAll(dirs)
	if note != "" {
		logf("policy precedence: %s", note)
	}
	cur, found, derr := approve.CurrentPolicy(db)
	reset = distrust(cur, found, derr, f)
	if f.stateCreated && f.history.any {
		reset = "" // reportStateLoss already reports a recreated state.db
	}
	switch {
	case err != nil:
		logf("POLICY NOT LOADED: %v; every tools/call, tools/list, resources/read, sampling and elicitation request is blocked (no_policy)", err)
		return nil, notApproved(), note, reset
	case reset != "":
		logf("POLICY NOT LOADED: %s; every policed request is blocked until you run `rover policy apply`", reset)
		return nil, notApproved(), note, reset
	}
	if why := unapproved(db, hash); why != "" {
		logf("POLICY NOT LOADED: %s; every policed request is blocked until you run `rover policy apply`", why)
		return nil, notApproved(), note, ""
	}
	logf("policy loaded (mode %s); approved hash %s", cfg.Mode, short(hash))
	return pol, cfg, note, ""
}

// distrust says why the approved policy in state.db cannot be trusted, or
// "". roverd runs it at start and on reload, and `rover doctor` runs it
// too, so doctor fails exactly when roverd would refuse:
//   - no approval although the audit log has history: approvals lost;
//   - an approval newer than the newest audit entry: roverd audits every
//     approval it records, so someone else wrote it;
//   - an approval that is not the one in the latest `policy approved`
//     audit entry: an older state.db (and its policy files) put back
//     after a human approved something else. The audit chain is the record
//     an agent cannot rewrite without breaking the anchor.
func distrust(cur approve.PolicyApproval, found bool, err error, f startFacts) string {
	switch {
	case err != nil:
		return "approved_policy unreadable: " + err.Error()
	case !found && f.history.any:
		return "state.db has no approved policy although the audit log has history: approvals were lost or removed"
	case !found:
		return ""
	case !f.lastAudit.IsZero() && cur.ApprovedAt.After(f.lastAudit):
		return fmt.Sprintf("approved_policy says %s was approved at %s, after the newest audit entry (%s): roverd did not write that record",
			short(cur.Hash), cur.ApprovedAt.UTC().Format(time.RFC3339Nano), f.lastAudit.UTC().Format(time.RFC3339Nano))
	case f.history.approved != cur.Hash:
		return fmt.Sprintf("approved_policy says %s, but the latest `policy approved` audit entry says %s: state.db was replaced (an older copy put back?)",
			short(cur.Hash), orDash(short(f.history.approved)))
	}
	return ""
}

// unapproved says why hash may not be loaded, or "" if it is the approved
// policy.
func unapproved(db *state.DB, hash string) string {
	cur, found, err := approve.CurrentPolicy(db)
	switch {
	case err != nil:
		return "approved_policy unreadable: " + err.Error()
	case !found:
		return "no policy has been approved yet (hash " + short(hash) + ")"
	case cur.Hash != hash:
		return fmt.Sprintf("the policy files changed: hash %s is not the approved %s (approved %s by %s)",
			short(hash), short(cur.Hash), cur.ApprovedAt.Format(time.RFC3339), cur.Method)
	}
	return ""
}

func short(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}

// reloader is what a SIGHUP needs.
type reloader struct {
	dirs   paths.Dirs
	db     *state.DB
	srv    *daemon.Server
	onLoad func(config.Config)
	logf   func(string, ...any)
}

// reloadOnHUP reloads on every SIGHUP (see reload). The precedence note is
// logged again only when it changes.
func reloadOnHUP(hup <-chan os.Signal, r reloader, lastNote string) {
	for range hup {
		if note := r.reload(); note != "" && note != lastNote {
			r.logf("policy precedence: %s", note)
			lastNote = note
		}
	}
}

// reload reloads config.yaml and the policy, but only the approved
// policy: a SIGHUP approves nothing. It is for the files a human already
// approved (say, after restoring them); it may not switch enforce to
// observe. Approving new files is `rover policy apply`, which makes roverd
// show the OS dialog (daemon policy_apply). An edited policy.cedar and a
// bare SIGHUP, or a policy that fails to load, keep whatever ran before.
func (r reloader) reload() string {
	pol, cfg, note, hash, err := loadAll(r.dirs)
	if err != nil {
		r.logf("policy reload FAILED, keeping the previous policy: %v", err)
		return note
	}
	why := unapproved(r.db, hash)
	if why == "" {
		why = r.distrusted()
	}
	if why != "" {
		why = "policy reload REFUSED: " + why + "; run `rover policy apply` (OS authentication)"
		r.logf("%s", why)
		_ = r.srv.AuditPolicy("refused", why, "")
		return note
	}
	if err := r.srv.Reload(pol, cfg); err != nil {
		r.logf("policy reload %v; keeping the previous policy and mode", err)
		return note
	}
	r.onLoad(cfg)
	r.logf("policy reloaded (mode %s); approved hash %s", cfg.Mode, short(hash))
	return note
}

// distrusted runs distrust with the audit log as it is now.
func (r reloader) distrusted() string {
	h, err := readHistory(filepath.Join(r.dirs.State, "audit.jsonl"))
	if err != nil {
		return "audit log unreadable: " + err.Error()
	}
	cur, found, derr := approve.CurrentPolicy(r.db)
	return distrust(cur, found, derr, startFacts{history: h})
}
