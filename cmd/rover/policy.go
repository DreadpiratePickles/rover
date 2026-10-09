package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/config"
	"github.com/DreadpiratePickles/rover/internal/daemon"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
	"github.com/DreadpiratePickles/rover/internal/paths"
	"github.com/DreadpiratePickles/rover/internal/policy"
	policyfiles "github.com/DreadpiratePickles/rover/policy"
)

const policyUsage = `usage:
  rover policy init [--force]          write policy.cedar, config.yaml, the schema and templates
  rover policy validate [--policy FILE] load and type-check a policy
  rover policy test <audit.jsonl>       replay logged messages through the current policy
  rover policy apply                    ask roverd to reload config.yaml and policy.cedar`

// runPolicy dispatches `rover policy <sub>`.
func runPolicy(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, policyUsage)
		return 2
	}
	switch args[0] {
	case "init":
		return policyInit(args[1:])
	case "validate":
		return policyValidate(args[1:])
	case "test":
		return policyTest(args[1:])
	case "apply":
		return policyApply(args[1:])
	default:
		fmt.Fprintln(os.Stderr, policyUsage)
		return 2
	}
}

type initFile struct {
	rel  string
	data []byte
}

func starterFiles() ([]initFile, error) {
	files := []initFile{
		{policyFile, policyfiles.Starter},
		{config.FileName, []byte(starterConfig)},
		{schemaFile, policyfiles.Schema},
	}
	tmpl, err := fs.ReadDir(policyfiles.Templates, ".")
	if err != nil {
		return nil, err
	}
	for _, d := range tmpl {
		b, err := fs.ReadFile(policyfiles.Templates, d.Name())
		if err != nil {
			return nil, err
		}
		files = append(files, initFile{filepath.Join("templates", d.Name()), b})
	}
	return files, nil
}

// policyInit writes the starter files, refusing to overwrite any of them
// unless --force is given.
func policyInit(args []string) int {
	fset := flag.NewFlagSet("policy init", flag.ExitOnError)
	force := fset.Bool("force", false, "overwrite existing files")
	_ = fset.Parse(args)

	dirs, err := paths.Resolve()
	if err == nil {
		err = paths.Ensure(dirs)
	}
	files, ferr := starterFiles()
	if err == nil {
		err = ferr
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var existing []string
	for _, f := range files {
		if _, err := os.Lstat(filepath.Join(dirs.Config, f.rel)); err == nil {
			existing = append(existing, filepath.Join(dirs.Config, f.rel))
		}
	}
	if len(existing) > 0 && !*force {
		fmt.Fprintln(os.Stderr, "refusing to overwrite existing files (use --force):")
		for _, p := range existing {
			fmt.Fprintln(os.Stderr, "  "+p)
		}
		return 1
	}
	if err := os.MkdirAll(filepath.Join(dirs.Config, "templates"), 0o700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	for _, f := range files {
		p := filepath.Join(dirs.Config, f.rel)
		if err := writeNew(p, f.data); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println("wrote " + p)
	}
	fmt.Println("next: edit policy.cedar (it permits nothing yet), run `rover policy validate`, then `rover policy apply`.")
	fmt.Println("config.yaml starts in observe mode: denials are logged as would_deny, not blocked.")
	return 0
}

// writeNew replaces path with a fresh 0600 file. Removing first and creating
// with O_EXCL means a symlink planted at path is replaced, never followed.
func writeNew(path string, data []byte) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: path is inside Rover's config directory
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// policyValidate loads a policy the way roverd would and lists it.
func policyValidate(args []string) int {
	dirs, err := paths.Resolve()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fset := flag.NewFlagSet("policy validate", flag.ExitOnError)
	file := fset.String("policy", filepath.Join(dirs.Config, policyFile), "policy file to validate")
	_ = fset.Parse(args)

	eng, schemaName, err := loadEngine(*file, dirs.Config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	infos := eng.Policies()
	for _, p := range infos {
		fmt.Printf("%s  %s\n", p.ID, p.Effect)
	}
	fmt.Printf("ok: %d policies (schema: %s)\n", len(infos), schemaName)
	if _, err := config.Load(dirs.Config); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

// replaySession is what `policy test` remembers per logged session.
type replaySession struct {
	client, version string
	flags           policy.SessionCtx
}

type replayCounts struct{ replayed, forwarded, blocked, unpoliced, skipped int }

// policyTest replays logged messages through the current policy in enforce
// mode and prints the decision for each policed one.
func policyTest(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: rover policy test <audit.jsonl>")
		return 2
	}
	dirs, err := paths.Resolve()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	eng, _, err := loadEngine(filepath.Join(dirs.Config, policyFile), dirs.Config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	cfg, err := config.Load(dirs.Config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	f, err := os.Open(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = f.Close() }()

	configured := cfg.Mode
	cfg.Mode = policy.ModeEnforce
	fmt.Printf("replaying %s in enforce mode (config.yaml says %s)\n", args[0], configured)
	var n replayCounts
	sessions := map[string]*replaySession{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), audit.MaxLine)
	for sc.Scan() {
		var e audit.Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil || len(e.Body) == 0 || e.Session == "" {
			n.skipped++
			continue
		}
		replayEntry(eng, cfg, e, sessions, &n)
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("%d replayed: %d forward, %d block; %d not policed; %d skipped (no body)\n",
		n.replayed, n.forwarded, n.blocked, n.unpoliced, n.skipped)
	if n.skipped > 0 {
		fmt.Println("to record bodies, run roverd as `rover daemon --log-bodies` (bodies can hold secrets until M10 adds redaction)")
	}
	return 0
}

func replayEntry(eng *policy.Engine, cfg config.Config, e audit.Entry, sessions map[string]*replaySession, n *replayCounts) {
	st := sessions[e.Session]
	if st == nil {
		st = &replaySession{}
		sessions[e.Session] = st
	}
	m := jsonrpc.Parse(e.Body)
	if e.Dir == policy.DirC2S && m.Kind == jsonrpc.KindRequest && m.Method == "initialize" {
		var p struct {
			ClientInfo struct{ Name, Version string } `json:"clientInfo"`
		}
		if json.Unmarshal(m.Params, &p) == nil {
			st.client, st.version = p.ClientInfo.Name, p.ClientInfo.Version
		}
	}
	if !policy.Policed(e.Dir, m) {
		n.unpoliced++
		return
	}
	o := eng.Decide(daemon.InputFor(cfg, e.Server, "stdio", e.Dir, m, st.client, st.version, st.flags, e.Time))
	n.replayed++
	if o.Action == ipc.ActionForward {
		n.forwarded++
		if m.Method == "tools/call" {
			st.flags = daemon.NextFlags(st.flags, cfg.ToolLabels(e.Server, m.ToolName()))
		}
	} else {
		n.blocked++
	}
	what := m.Method
	if t := m.ToolName(); t != "" {
		what += " " + t
	}
	rules := "-"
	if len(o.RuleIDs) > 0 {
		rules = strings.Join(o.RuleIDs, ",")
	}
	fmt.Printf("%s  %-12s %-28s %-7s rules=%s (logged: %s)\n",
		e.Time.Local().Format(time.DateTime), e.Server, what, o.Action, rules, e.Action)
}

// policyApply asks the running roverd to reload its policy.
func policyApply(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "usage: rover policy apply")
		return 2
	}
	dirs, err := paths.Resolve()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	b, err := os.ReadFile(filepath.Join(dirs.Run, "roverd.pid"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "roverd is not running (no pid file):", err)
		return 1
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		fmt.Fprintf(os.Stderr, "bad pid file %q\n", b)
		return 1
	}
	// A stale pid file could name an unrelated process, which SIGHUP would
	// kill; only signal when roverd's socket answers.
	if err = pingDaemon(dirs); err != nil {
		fmt.Fprintln(os.Stderr, "roverd is not answering on its socket:", err)
		return 1
	}
	proc, err := os.FindProcess(pid)
	if err == nil {
		err = proc.Signal(syscall.SIGHUP)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot signal roverd (pid %d): %v\n", pid, err)
		return 1
	}
	fmt.Printf("reload requested (pid %d); roverd.log says whether it succeeded\n", pid)
	fmt.Println("TODO(M9): this is not yet protected by OS authentication")
	return 0
}

// pingDaemon connects to roverd's socket and leaves without a hello. It
// half-closes and waits for roverd to hang up, so roverd has read its peer
// credentials before the connection goes away (no log noise).
func pingDaemon(dirs paths.Dirs) error {
	sock, err := paths.SocketPath(dirs)
	if err != nil {
		return err
	}
	c, err := net.DialTimeout("unix", sock, 500*time.Millisecond)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return nil
	}
	if err := uc.CloseWrite(); err != nil {
		return err
	}
	_ = uc.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = io.Copy(io.Discard, uc)
	return nil
}
