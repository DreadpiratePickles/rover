package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/clients"
	"github.com/DreadpiratePickles/rover/internal/daemon"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/paths"
	"github.com/DreadpiratePickles/rover/internal/pin"
	"github.com/DreadpiratePickles/rover/internal/state"
)

// runDaemon is roverd. It is normally started by the first wrapper that
// finds no daemon, but can be run by hand for a visible log.
func runDaemon(args []string) int {
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	logBodies := fs.Bool("log-bodies", false, "record full message bodies in the audit log (off until M10 adds redaction)")
	_ = fs.Parse(args)

	logf := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, time.Now().UTC().Format("2006-01-02T15:04:05.000Z")+" roverd "+format+"\n", a...)
	}

	// Everything roverd creates is owner-only, whatever the inherited umask.
	syscall.Umask(0o077)

	dirs, err := paths.Resolve()
	if err == nil {
		err = paths.Ensure(dirs)
	}
	if err != nil {
		logf("%v", err)
		return 1
	}
	// Files that already exist must still be owner-only (§4.2).
	for _, f := range []string{filepath.Join(dirs.State, "audit.jsonl"), filepath.Join(dirs.State, "state.db"), filepath.Join(dirs.State, "roverd.log")} {
		if perr := paths.CheckPrivate(f, 0o600); perr != nil && !errors.Is(perr, os.ErrNotExist) {
			logf("%v", perr)
			return 1
		}
	}
	// A history without a database means the pins were lost (review M4):
	// note both before either file is opened (and so created).
	logPath := filepath.Join(dirs.State, "audit.jsonl")
	_, serr := os.Stat(filepath.Join(dirs.State, "state.db"))
	_, aerr := os.Stat(anchorPath(logPath))
	stateCreated, hadHistory := errors.Is(serr, os.ErrNotExist), aerr == nil
	db, err := state.Open(filepath.Join(dirs.State, "state.db"))
	if errors.Is(err, state.ErrLocked) {
		logf("another roverd holds the state database; exiting")
		return 0
	}
	if err != nil {
		logf("%v", err)
		return 1
	}
	defer func() { _ = db.Close() }()

	log, err := audit.Open(logPath)
	if err != nil {
		logf("audit log: %v", err)
		return 1
	}
	defer func() { _ = log.Close() }()
	log.AnchorPath = anchorPath(logPath)

	// Install the SIGHUP handler before the pid file exists: `rover policy
	// apply` must never hit the default action, which would kill roverd.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	pol, cfg, note, err := loadAll(dirs)
	if note != "" {
		logf("policy precedence: %s", note)
	}
	if err != nil {
		logf("POLICY NOT LOADED: %v; every tools/call, tools/list, resources/read, sampling and elicitation request is blocked (no_policy)", err)
		pol = nil
	} else {
		logf("policy loaded (mode %s)", cfg.Mode)
	}

	sock, err := paths.SocketPath(dirs)
	if err != nil {
		logf("%v", err)
		return 1
	}
	srv := daemon.New(daemon.Options{
		SocketPath: sock,
		Audit:      log,
		LogBodies:  *logBodies,
		SelfUID:    uint32(os.Getuid()), //nolint:gosec // G115: uid fits in uint32 on all supported platforms
		PeerCreds:  ipc.PeerCreds,
		ParentPID:  ipc.ParentPID,
		Logf:       logf,
		Policy:     pol,
		Config:     cfg,
		State:      db,
		Notifier:   pin.OSNotifier{Logf: logf},

		TamperFiles: watchedConfigs(dirs, logf),
		RoverPath:   roverPathForDaemon(logf),

		StateDBCreated:  stateCreated,
		AuditHadHistory: hadHistory,
	})
	go reloadOnHUP(hup, dirs, srv, note, logf)
	if err := srv.Listen(); err != nil {
		logf("%v", err)
		return 1
	}
	pidPath := filepath.Join(dirs.Run, "roverd.pid")
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		logf("write pid file: %v", err)
	}
	defer func() { _ = os.Remove(pidPath) }()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logf("listening on %s (pid %d, bodies=%v)", sock, os.Getpid(), *logBodies)
	if err := srv.Serve(ctx); err != nil {
		logf("serve: %v", err)
		return 1
	}
	logf("stopped")
	return 0
}

// watchedConfigs are the client configs roverd watches for tampering
// (M7): every file `rover install` has written and not since uninstalled
// (from the backup manifests, which include project configs in other
// directories). A config rover never installed into is not watched: its
// servers were never wrapped, so there is nothing to tamper with, and
// `rover doctor` reports it. A manifest that cannot be read is logged and
// the others are still watched. `rover install` adds new files to a running
// roverd (tamper_resolve).
func watchedConfigs(dirs paths.Dirs, logf func(string, ...any)) []clients.ConfigFile {
	files, errs := clients.InstalledFiles(filepath.Join(dirs.State, "backups"))
	for _, err := range errs {
		logf("tamper watch: %v; that config is not watched", err)
	}
	if len(files) > 0 {
		logf("tamper watch: watching %d client config file(s)", len(files))
	}
	return files
}

// reloadOnHUP reloads config.yaml and the policy (policy.cedar, else
// policy.yaml) on every SIGHUP. A failed reload, including a policy.yaml
// that does not compile, keeps whatever was running before (a policy, or
// none), and so does a reload that would switch enforce to observe
// (daemon.ErrModeDowngrade). The precedence note is logged again only when
// it changes.
// TODO(M9): policy changes must be confirmed with OS authentication.
func reloadOnHUP(hup <-chan os.Signal, dirs paths.Dirs, srv *daemon.Server, lastNote string, logf func(string, ...any)) {
	for range hup {
		pol, cfg, note, err := loadAll(dirs)
		if note != "" && note != lastNote {
			logf("policy precedence: %s", note)
			lastNote = note
		}
		if err != nil {
			logf("policy reload FAILED, keeping the previous policy: %v", err)
			continue
		}
		if err := srv.Reload(pol, cfg); err != nil {
			logf("policy reload %v; keeping the previous policy and mode", err)
			continue
		}
		logf("policy reloaded (mode %s)", cfg.Mode)
	}
}

// roverPathForDaemon is the binary wrapped servers must run: this one.
// Without it (a `go run` binary) the watch falls back to the command each
// server had when it was first seen wrapped.
func roverPathForDaemon(logf func(string, ...any)) string {
	p, err := selfPath("")
	if err != nil {
		logf("tamper watch: %v; checking wrapped servers against their first-seen command instead", err)
		return ""
	}
	return p
}
