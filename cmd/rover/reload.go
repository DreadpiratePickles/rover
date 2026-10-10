package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/DreadpiratePickles/rover/internal/approve"
	"github.com/DreadpiratePickles/rover/internal/approve/page"
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

// loadApprovedAtStart loads the policy and checks its hash against
// approved_policy (M9). A policy nobody approved is not loaded; roverd
// then blocks every policed message until `rover policy apply`.
func loadApprovedAtStart(dirs paths.Dirs, db *state.DB, logf func(string, ...any)) (daemon.Policy, config.Config, string) {
	// A nonce left from before this start is never valid now.
	if _, err := approve.ConsumeNonce(dirs.Run, time.Now()); err != nil && !errors.Is(err, approve.ErrNoNonce) {
		logf("discarded an old apply nonce: %v", err)
	}
	pol, cfg, note, hash, err := loadAll(dirs)
	if note != "" {
		logf("policy precedence: %s", note)
	}
	if err != nil {
		logf("POLICY NOT LOADED: %v; every tools/call, tools/list, resources/read, sampling and elicitation request is blocked (no_policy)", err)
		return nil, notApproved(), note
	}
	if why := unapproved(db, hash); why != "" {
		logf("POLICY NOT LOADED: %s; every policed request is blocked until you run `rover policy apply`", why)
		return nil, notApproved(), note
	}
	logf("policy loaded (mode %s); approved hash %s", cfg.Mode, short(hash))
	return pol, cfg, note
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
	dirs paths.Dirs
	db   *state.DB
	srv  *daemon.Server
	flow *approve.Flow
	page *page.Server
	logf func(string, ...any)
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

// reload loads config.yaml and the policy (policy.cedar, else policy.yaml).
// It loads them only if
//   - an apply nonce is present, fresh, and names the hash of these exact
//     files: an authenticated `rover policy apply` (or, for the very first
//     policy, `rover policy init`). The hash is then recorded as approved,
//     and a switch from enforce to observe is allowed; or
//   - the files are the policy approved already (a reload of the same
//     thing), which may not switch enforce to observe.
//
// Anything else (an edited policy.cedar and a bare SIGHUP, a forged or
// stale nonce, a policy that fails to load) keeps whatever ran before.
func (r reloader) reload() string {
	now := time.Now()
	nonce, nerr := approve.ConsumeNonce(r.dirs.Run, now)
	if nerr != nil && !errors.Is(nerr, approve.ErrNoNonce) {
		r.refuse("apply nonce refused: " + nerr.Error())
	}
	pol, cfg, note, hash, err := loadAll(r.dirs)
	if err != nil {
		r.logf("policy reload FAILED, keeping the previous policy: %v", err)
		return note
	}
	cur, found, derr := approve.CurrentPolicy(r.db)
	authorized := false
	switch {
	case derr != nil:
		r.refuse("policy reload REFUSED: approved_policy unreadable: " + derr.Error())
		return note
	case nerr == nil && nonce.Hash != hash:
		r.refuse(fmt.Sprintf("policy reload REFUSED: the files changed after `rover policy apply` authenticated (approved %s, on disk %s)", short(nonce.Hash), short(hash)))
		return note
	case nerr == nil && nonce.Method == approve.MethodInit && found:
		r.refuse("policy reload REFUSED: `rover policy init` may only approve the first policy; run `rover policy apply`")
		return note
	case nerr == nil:
		authorized = true
	case !found || cur.Hash != hash:
		r.refuse("policy reload REFUSED: " + unapproved(r.db, hash) + "; run `rover policy apply` (OS authentication)")
		return note
	}
	if authorized {
		if err := approve.RecordPolicy(r.db, hash, nonce.Method, now); err != nil {
			r.logf("policy reload FAILED: recording the approval: %v; keeping the previous policy", err)
			return note
		}
		_ = r.srv.AuditPolicy("approved", "hash "+hash+" method "+nonce.Method)
	}
	if err := r.srv.ReloadWith(pol, cfg, authorized); err != nil {
		r.logf("policy reload %v; keeping the previous policy and mode", err)
		return note
	}
	r.flow.SetTimeout(cfg.Approvals.Timeout())
	r.page.SetShowArgs(cfg.Approvals.ShowArgs)
	r.logf("policy reloaded (mode %s); approved hash %s", cfg.Mode, short(hash))
	return note
}

// refuse logs and audits a refused reload.
func (r reloader) refuse(why string) {
	r.logf("%s", why)
	_ = r.srv.AuditPolicy("refused", why)
}
