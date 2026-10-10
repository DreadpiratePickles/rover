package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/DreadpiratePickles/rover/internal/clients"
)

func runUninstall(args []string) int {
	cf := parseClientFlags("uninstall", args)
	if cf.service {
		return uninstallService(os.Stdout, cf)
	}
	env, _, err := clientEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "rover uninstall:", err)
		return 1
	}
	return uninstallClients(os.Stdout, bufio.NewReader(os.Stdin), cf, env)
}

// uninstallClients undoes install for every detected or previously written
// config of the selected clients. The newest backup is put back when the
// file is exactly what rover wrote; if it changed since (Claude Code
// rewrites ~/.claude.json all the time), the wrapping is undone in place so
// the later changes survive. A backup that fails its checksum is never
// used and never silently bypassed: uninstall stops for that file and says
// why.
func uninstallClients(out io.Writer, in *bufio.Reader, cf clientFlags, env clients.Env) int {
	adapters, err := selectAdapters(cf.only, env)
	if err != nil {
		_, _ = fmt.Fprintln(out, err)
		return 2
	}
	installed, err := clients.InstalledFiles(env.BackupDir)
	if err != nil {
		_, _ = fmt.Fprintf(out, "fail  reading backup manifests: %v\n", err)
		return 1
	}
	rc, settings := 0, false
	for _, a := range adapters {
		settings = settings || a.Name() == clients.NameClaudeCode
		files, err := a.Detect()
		if err != nil && !errors.Is(err, clients.ErrUnsupported) {
			_, _ = fmt.Fprintf(out, "fail  %s: %v\n", a.Name(), err)
			rc = 1
		}
		seen := map[string]bool{}
		for _, f := range append(files, installed...) {
			if f.Adapter != a.Name() || seen[f.Path] {
				continue
			}
			seen[f.Path] = true
			if !uninstallOne(out, in, cf, env, a, f) {
				rc = 1
			}
		}
	}
	if settings && !uninstallDeny(out, in, cf, env) {
		rc = 1
	}
	return rc
}

func uninstallOne(out io.Writer, in *bufio.Reader, cf clientFlags, env clients.Env, a clients.Adapter, f clients.ConfigFile) bool {
	_, _ = fmt.Fprintf(out, "\n%s  %s  %s\n", a.Name(), f.Scope, f.Path)
	if _, err := os.Stat(f.Path); errors.Is(err, os.ErrNotExist) {
		_, _ = fmt.Fprintln(out, "ok    file is gone; nothing to undo")
		return true
	}
	if clients.HasBackup(env, f) {
		diff, err := clients.RestorePreview(env, f)
		switch {
		case err == nil:
			_, _ = fmt.Fprint(out, diff)
			if !confirm(out, in, cf, "restore the backup of "+f.Path+"?") {
				return true
			}
			if err = a.Restore(f); err != nil {
				_, _ = fmt.Fprintf(out, "fail  %v\n", err)
				return false
			}
			_, _ = fmt.Fprintln(out, "ok    restored from backup")
			return true
		case errors.Is(err, clients.ErrBackupCorrupt):
			_, _ = fmt.Fprintf(out, "fail  refusing to restore: %v\n      the backup was changed after rover made it; inspect it, or undo the wrapping by hand\n", err)
			return false
		case errors.Is(err, clients.ErrChangedSinceInstall):
			_, _ = fmt.Fprintln(out, "note  the file changed since rover wrote it; undoing the wrapping in place instead of restoring the backup")
		default:
			_, _ = fmt.Fprintf(out, "fail  %v\n", err)
			return false
		}
	}
	doc, err := a.Read(f)
	if err != nil {
		_, _ = fmt.Fprintf(out, "fail  cannot read it: %v\n", err)
		return false
	}
	p, err := clients.PlanUnwrap(doc)
	if err != nil {
		_, _ = fmt.Fprintf(out, "fail  %v\n", err)
		return false
	}
	if !p.HasChanges() {
		_, _ = fmt.Fprintln(out, "ok    no wrapped servers")
		return true
	}
	_, _ = fmt.Fprint(out, p.Diff)
	if !confirm(out, in, cf, fmt.Sprintf("unwrap %d server(s) in %s?", len(p.Changed), f.Path)) {
		return true
	}
	if err := a.Apply(p); err != nil {
		_, _ = fmt.Fprintf(out, "fail  %v\n", err)
		return false
	}
	_, _ = fmt.Fprintf(out, "ok    unwrapped %d server(s)\n", len(p.Changed))
	return true
}

// uninstallDeny restores ~/.claude/settings.json if rover's hardening is
// the last change to it; otherwise it says which rules to remove by hand.
func uninstallDeny(out io.Writer, in *bufio.Reader, cf clientFlags, env clients.Env) bool {
	f := clients.ConfigFile{Adapter: clients.NameClaudeSettings, Path: clients.SettingsPath(env.Home), Scope: "user"}
	if !clients.HasBackup(env, f) {
		return true
	}
	_, _ = fmt.Fprintf(out, "\nclaude-code  hardening  %s\n", f.Path)
	diff, err := clients.RestorePreview(env, f)
	if errors.Is(err, clients.ErrChangedSinceInstall) {
		_, _ = fmt.Fprintln(out, "note  settings.json changed since rover added its deny rules; remove the Edit(...) rules rover added from permissions.deny by hand if you want them gone")
		return true
	}
	if err != nil {
		_, _ = fmt.Fprintf(out, "fail  refusing to restore: %v\n", err)
		return false
	}
	_, _ = fmt.Fprint(out, diff)
	if !confirm(out, in, cf, "remove rover's deny rules (restore the backup)?") {
		return true
	}
	if err := clients.Restore(env, f); err != nil {
		_, _ = fmt.Fprintf(out, "fail  %v\n", err)
		return false
	}
	_, _ = fmt.Fprintln(out, "ok    restored")
	return true
}
