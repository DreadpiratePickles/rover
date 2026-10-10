package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/DreadpiratePickles/rover/internal/clients"
	"github.com/DreadpiratePickles/rover/internal/ipc"
)

func runUninstall(args []string) int {
	cf := parseClientFlags("uninstall", args)
	if cf.service {
		return uninstallService(os.Stdout, bufio.NewReader(os.Stdin), cf)
	}
	env, _, err := clientEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "rover uninstall:", err)
		return 1
	}
	return uninstallClients(os.Stdout, bufio.NewReader(os.Stdin), cf, env)
}

// uninstallClients undoes install for every detected or previously written
// config of the selected clients, so that no server in them runs through
// rover any more (clients.Uninstall): the newest backup is put back when the
// file is exactly what rover wrote, then anything still wrapped (an older
// install, a server added and wrapped later) is unwrapped in place. A backup
// that fails its checksum is never used: uninstall stops for that file and
// says why. A manifest that cannot be read is reported and the rest go on.
func uninstallClients(out io.Writer, in *bufio.Reader, cf clientFlags, env clients.Env) int {
	adapters, err := selectAdapters(cf.only, env)
	if err != nil {
		_, _ = fmt.Fprintln(out, err)
		return 2
	}
	rc, settings := 0, false
	installed, errs := clients.InstalledFiles(env.BackupDir)
	for _, err := range errs {
		_, _ = fmt.Fprintf(out, "fail  %v\n", err)
		rc = 1
	}
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
	diff, err := uninstallPreview(env, a, f)
	if err != nil {
		_, _ = fmt.Fprintf(out, "fail  refusing: %v\n", err)
		return false
	}
	if diff == "" {
		_, _ = fmt.Fprintln(out, "ok    no wrapped servers")
		return true
	}
	_, _ = fmt.Fprint(out, diff)
	if !confirm(out, in, cf, "undo rover's changes to "+f.Path+"?") {
		return true
	}
	steps, err := clients.Uninstall(env, f)
	for _, s := range steps {
		_, _ = fmt.Fprintln(out, "ok    "+s)
	}
	if err != nil {
		_, _ = fmt.Fprintf(out, "fail  %v\n", err)
		return false
	}
	tellRoverd(out, f, ipc.OpTamperForget)
	return true
}

// uninstallPreview is what the user is shown before confirming: the
// restore of the newest backup when it applies, else the in-place unwrap.
// A corrupt backup is an error here, before anything is written.
func uninstallPreview(env clients.Env, a clients.Adapter, f clients.ConfigFile) (string, error) {
	if clients.HasBackup(env, f) {
		diff, err := clients.RestorePreview(env, f)
		switch {
		case err == nil:
			return diff + "(then anything still wrapped is unwrapped in place)\n", nil
		case !errors.Is(err, clients.ErrChangedSinceInstall):
			return "", err
		}
	}
	doc, err := a.Read(f)
	if err != nil {
		return "", err
	}
	p, err := clients.PlanUnwrap(doc)
	if err != nil {
		return "", err
	}
	return p.Diff, nil
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
