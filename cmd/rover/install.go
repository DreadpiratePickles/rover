package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/DreadpiratePickles/rover/internal/clients"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/paths"
)

// `rover install` and `rover uninstall` (plan M7, D11).

// clientFlags are the flags install and uninstall share.
type clientFlags struct {
	only    []string
	yes     bool
	dryRun  bool
	service bool
	rover   string
}

func parseClientFlags(name string, args []string) clientFlags {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	var cf clientFlags
	fs.Func("client", "only this client: "+strings.Join(clients.Names(), ", ")+" (repeatable)", func(s string) error {
		cf.only = append(cf.only, s)
		return nil
	})
	fs.BoolVar(&cf.yes, "yes", false, "apply without asking (otherwise each change is shown and asked about y/N on a terminal)")
	fs.BoolVar(&cf.dryRun, "dry-run", false, "show what would change and write nothing")
	fs.BoolVar(&cf.service, "service", false, "the roverd login service (launchd agent on macOS, systemd user unit on Linux) instead of client configs")
	if name == "install" {
		fs.StringVar(&cf.rover, "rover", "", "absolute path of the rover binary written into configs (default: this binary)")
	}
	_ = fs.Parse(args)
	return cf
}

// clientEnv is the real environment: the home and working directory, and
// backups under the state directory.
func clientEnv() (clients.Env, paths.Dirs, error) {
	dirs, err := paths.Resolve()
	if err == nil {
		err = paths.Ensure(dirs)
	}
	if err != nil {
		return clients.Env{}, dirs, err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return clients.Env{}, dirs, err
	}
	cwd, _ := os.Getwd()
	return clients.Env{Home: home, Cwd: cwd, GOOS: runtime.GOOS, BackupDir: filepath.Join(dirs.State, "backups")}, dirs, nil
}

func selectAdapters(only []string, env clients.Env) ([]clients.Adapter, error) {
	if len(only) == 0 {
		return clients.All(env), nil
	}
	var out []clients.Adapter
	for _, n := range only {
		a, err := clients.Get(n, env)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// selfPath is the rover binary configs will run: absolute, existing, and
// not a `go run` temporary that disappears when the command ends.
func selfPath(override string) (string, error) {
	p := override
	if p == "" {
		exe, err := os.Executable()
		if err != nil {
			return "", err
		}
		p = exe
	}
	p, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(p)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("%s is not an executable file", p)
	}
	if strings.Contains(p, string(filepath.Separator)+"go-build") {
		return "", fmt.Errorf("%s is a `go run` temporary; build rover (make build) and run that binary, or pass --rover", p)
	}
	return p, nil
}

// confirm asks a y/N question on a terminal. Without a terminal it never
// guesses yes: the answer is --yes or nothing happens.
var stdinIsTTY = func() bool { return isTerminal(os.Stdin) }

func confirm(out io.Writer, in *bufio.Reader, cf clientFlags, question string) bool {
	if cf.dryRun {
		return false
	}
	if cf.yes {
		return true
	}
	if !stdinIsTTY() {
		_, _ = fmt.Fprintln(out, "not a terminal and no --yes: nothing written")
		return false
	}
	_, _ = fmt.Fprintf(out, "%s [y/N] ", question)
	line, _ := in.ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

func runInstall(args []string) int {
	cf := parseClientFlags("install", args)
	rover, err := selfPath(cf.rover)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rover install:", err)
		return 1
	}
	if cf.service {
		return installService(os.Stdout, bufio.NewReader(os.Stdin), cf, rover)
	}
	env, dirs, err := clientEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "rover install:", err)
		return 1
	}
	return installClients(os.Stdout, bufio.NewReader(os.Stdin), cf, env, dirs, rover)
}

func installClients(out io.Writer, in *bufio.Reader, cf clientFlags, env clients.Env, dirs paths.Dirs, rover string) int {
	adapters, err := selectAdapters(cf.only, env)
	if err != nil {
		_, _ = fmt.Fprintln(out, err)
		return 2
	}
	rc, found, hardening := 0, 0, false
	for _, a := range adapters {
		hardening = hardening || a.Name() == clients.NameClaudeCode
		files, err := a.Detect()
		if errors.Is(err, clients.ErrUnsupported) {
			_, _ = fmt.Fprintf(out, "skip  %v\n", err)
			continue
		}
		if err != nil {
			_, _ = fmt.Fprintf(out, "fail  %s: %v\n", a.Name(), err)
			rc = 1
			continue
		}
		for _, f := range files {
			found++
			if !installOne(out, in, cf, a, f, rover) {
				rc = 1
			}
		}
	}
	if found == 0 {
		_, _ = fmt.Fprintln(out, "no client configs found (looked for "+strings.Join(clients.Names(), ", ")+")")
	}
	if hardening && !installDeny(out, in, cf, env, dirs) {
		rc = 1
	}
	return rc
}

func installOne(out io.Writer, in *bufio.Reader, cf clientFlags, a clients.Adapter, f clients.ConfigFile, rover string) bool {
	_, _ = fmt.Fprintf(out, "\n%s  %s  %s\n", a.Name(), f.Scope, f.Path)
	doc, err := a.Read(f)
	if err != nil {
		_, _ = fmt.Fprintf(out, "fail  cannot read it, left alone: %v\n", err)
		return false
	}
	p, err := a.Plan(doc, rover)
	if err != nil {
		_, _ = fmt.Fprintf(out, "fail  %v\n", err)
		return false
	}
	for _, w := range p.Warnings {
		_, _ = fmt.Fprintln(out, "warn  "+cell(w))
	}
	if !p.HasChanges() {
		_, _ = fmt.Fprintf(out, "ok    nothing to do (%d servers)\n", len(doc.Servers))
		tellRoverd(out, f, ipc.OpTamperResolve)
		return true
	}
	_, _ = fmt.Fprint(out, p.Diff)
	if !confirm(out, in, cf, fmt.Sprintf("wrap %d server(s) in %s?", len(p.Changed), f.Path)) {
		return true
	}
	if err := a.Apply(p); err != nil {
		_, _ = fmt.Fprintf(out, "fail  %v\n", err)
		return false
	}
	_, _ = fmt.Fprintf(out, "ok    wrapped %d server(s); the original is kept as a backup (rover uninstall)\n", len(p.Changed))
	tellRoverd(out, f, ipc.OpTamperResolve)
	return true
}

// tellRoverd tells a running roverd that rover itself just changed f, so
// its tamper watch takes the new state as the baseline (install) or stops
// watching the file (uninstall) instead of alerting. No roverd is fine: it
// reads the manifests when it starts.
func tellRoverd(out io.Writer, f clients.ConfigFile, op string) {
	dirs, err := paths.Resolve()
	if err != nil {
		return
	}
	sock, err := paths.SocketPath(dirs)
	if err != nil {
		return
	}
	req := ipc.Frame{Op: op, Path: f.Path}
	if op == ipc.OpTamperResolve {
		req.Adapter, req.Scope = f.Adapter, f.Scope
	}
	res, err := ipc.Admin(sock, req)
	switch {
	case errors.Is(err, ipc.ErrNoDaemon):
		if op == ipc.OpTamperResolve {
			_, _ = fmt.Fprintln(out, "note  roverd is not running; it watches this file from its next start")
		}
		return
	case err != nil:
		_, _ = fmt.Fprintf(out, "WARN  roverd's tamper watch was NOT updated: %v; restart roverd\n", err)
		return
	}
	var r struct{ Watching bool }
	if jerr := json.Unmarshal(res.Result, &r); jerr != nil {
		_, _ = fmt.Fprintf(out, "WARN  roverd answered something unexpected (%v); restart roverd\n", jerr)
		return
	}
	switch {
	case op == ipc.OpTamperResolve && r.Watching:
		_, _ = fmt.Fprintln(out, "ok    roverd is watching this file for tampering")
	case op == ipc.OpTamperResolve:
		_, _ = fmt.Fprintf(out, "WARN  roverd is NOT watching %s for tampering (%s); restart roverd\n", f.Path, orDash(res.Message))
	default:
		_, _ = fmt.Fprintln(out, "ok    roverd stopped watching this file")
	}
}

// installDeny proposes the Claude Code permissions.deny hardening.
func installDeny(out io.Writer, in *bufio.Reader, cf clientFlags, env clients.Env, dirs paths.Dirs) bool {
	path := clients.SettingsPath(env.Home)
	rules, err := clients.DenyRules(env.Home, dirs.Config, dirs.State)
	if err != nil {
		_, _ = fmt.Fprintf(out, "\nwarn  claude-code hardening skipped: %v\n", err)
		return true
	}
	_, _ = fmt.Fprintf(out, "\nclaude-code  hardening  %s\nthese deny rules stop Claude Code's own file tools from editing rover's files and the client configs:\n%s", path, clients.DenyJSON(rules))
	p, err := clients.PlanDeny(path, rules)
	if err != nil {
		_, _ = fmt.Fprintf(out, "warn  not merged: %v\n      add the rules above to permissions.deny by hand\n", err)
		return true
	}
	if !p.HasChanges() {
		_, _ = fmt.Fprintln(out, "ok    already present")
		return true
	}
	_, _ = fmt.Fprint(out, p.Diff)
	if !confirm(out, in, cf, fmt.Sprintf("add %d deny rule(s) to %s?", len(p.Changed), path)) {
		return true
	}
	if err := clients.ApplyPlan(env, p); err != nil {
		_, _ = fmt.Fprintf(out, "fail  %v\n", err)
		return false
	}
	_, _ = fmt.Fprintf(out, "ok    added %d deny rule(s)\n", len(p.Changed))
	return true
}
