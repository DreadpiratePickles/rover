package main

import (
	"fmt"
	"os"
	"time"

	"github.com/DreadpiratePickles/rover/internal/approve"
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

// loadApprovedAtStart loads the policy and checks its hash against
// approved_policy (M9). A policy nobody approved is not loaded; roverd
// then blocks every policed message until `rover policy apply`.
func loadApprovedAtStart(dirs paths.Dirs, db *state.DB, logf func(string, ...any)) (daemon.Policy, config.Config, string) {
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
	if why := unapproved(r.db, hash); why != "" {
		why = "policy reload REFUSED: " + why + "; run `rover policy apply` (OS authentication)"
		r.logf("%s", why)
		_ = r.srv.AuditPolicy("refused", why)
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
