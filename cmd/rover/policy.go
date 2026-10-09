package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
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
	"github.com/DreadpiratePickles/rover/internal/policy/yaml2cedar"
	policyfiles "github.com/DreadpiratePickles/rover/policy"
)

const policyUsage = `usage:
  rover policy init [--force] [--yaml]   write policy.cedar (or policy.yaml), config.yaml, the schema and templates
  rover policy compile <file.yaml>       print the Cedar a policy.yaml compiles to
  rover policy validate [--print-schema] [--policy FILE | FILE]
                                         load and type-check a policy (.cedar, or .yaml compiled first),
                                         then run ` + "`cedar validate`" + ` if installed
  rover policy test <audit.jsonl>        replay logged messages through the current policy
  rover policy apply                     ask roverd to reload config.yaml and the policy

roverd uses policy.cedar when it exists, else policy.yaml (compiled on load).`

// runPolicy dispatches `rover policy <sub>`.
func runPolicy(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, policyUsage)
		return 2
	}
	switch args[0] {
	case "init":
		return policyInit(args[1:])
	case "compile":
		return policyCompile(args[1:])
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

func starterFiles(useYAML bool) ([]initFile, error) {
	files := []initFile{{policyFile, policyfiles.Starter}}
	if useYAML {
		files = []initFile{{policyYAMLFile, policyfiles.StarterYAML}}
	}
	files = append(files,
		initFile{config.FileName, []byte(starterConfig)},
		initFile{schemaFile, policyfiles.Schema},
	)
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
// unless --force is given. With --yaml it writes policy.yaml instead of
// policy.cedar.
func policyInit(args []string) int {
	fset := flag.NewFlagSet("policy init", flag.ExitOnError)
	force := fset.Bool("force", false, "overwrite existing files")
	useYAML := fset.Bool("yaml", false, "write policy.yaml (compiled to Cedar on load) instead of policy.cedar")
	_ = fset.Parse(args)

	dirs, err := paths.Resolve()
	if err == nil {
		err = paths.Ensure(dirs)
	}
	files, ferr := starterFiles(*useYAML)
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
	if *useYAML {
		fmt.Println("next: edit policy.yaml, run `rover policy compile` to read the Cedar it becomes, `rover policy validate`, then `rover policy apply`.")
		fmt.Println("policy.yaml starts in observe mode: denials are logged as would_deny, not blocked.")
		if _, err := os.Lstat(filepath.Join(dirs.Config, policyFile)); err == nil {
			fmt.Println("note: policy.cedar exists and wins over policy.yaml; remove it to use the YAML.")
		}
		return 0
	}
	fmt.Println("next: edit policy.cedar (it permits nothing yet), run `rover policy validate`, then `rover policy apply`.")
	fmt.Println("config.yaml starts in observe mode: denials are logged as would_deny, not blocked.")
	return 0
}

// policyCompile prints the Cedar a policy.yaml compiles to. This is a
// human-facing command, so stdout is fine; errors go to stderr.
func policyCompile(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: rover policy compile <file.yaml>")
		return 2
	}
	src, err := readCapped(args[0], yaml2cedar.MaxSourceBytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	c, err := yaml2cedar.Compile(src, args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if _, err := os.Stdout.Write(c.Cedar); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
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

// policyValidate loads a policy the way roverd would and lists it. The file
// is --policy, or the one positional argument, or else the one roverd
// would pick (policy.cedar, else policy.yaml). A .yaml file is compiled
// first.
func policyValidate(args []string) int {
	dirs, err := paths.Resolve()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fset := flag.NewFlagSet("policy validate", flag.ExitOnError)
	file := fset.String("policy", "", "policy file to validate (.cedar or .yaml)")
	printSchema := fset.Bool("print-schema", false, "print the effective schema (generated from the config) and exit")
	_ = fset.Parse(args)
	if *file == "" && fset.NArg() == 1 {
		*file = fset.Arg(0)
	} else if fset.NArg() > 0 {
		fmt.Fprintln(os.Stderr, "usage: rover policy validate [--print-schema] [--policy FILE | FILE]")
		return 2
	}
	if *file == "" {
		if *file, _, err = pickPolicyFile(dirs.Config); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
	}
	// The same owner-only checks roverd applies, so validate and roverd agree.
	cfg, err := loadConfig(dirs.Config, *file)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	l, err := loadPolicy(*file, dirs.Config, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if *printSchema {
		_, _ = os.Stdout.Write(l.schema)
		return 0
	}
	if c := l.compiled; c != nil {
		implied := 0
		for _, r := range c.Rules {
			if r.Implied {
				implied++
			}
		}
		fmt.Printf("compiled %s: %d rules + %d implied list_tools permits -> Cedar (mode %s, roots: %s)\n",
			*file, len(c.Rules)-implied, implied, l.cfg.Mode, strings.Join(policy.RootNames(l.cfg.Roots), ", "))
	}
	infos := l.engine.Policies()
	for _, p := range infos {
		fmt.Printf("%s  %s\n", p.ID, p.Effect)
	}
	fmt.Printf("ok: %d policies (schema: %s, generated for roots: %s)\n",
		len(infos), l.schemaName, strings.Join(policy.RootNames(l.cfg.Roots), ", "))
	var compiled []byte
	if l.compiled != nil {
		compiled = l.compiled.Cedar
	}
	return cedarValidate(*file, compiled, l.schema)
}

// cedarTimeout bounds the official Cedar CLI run.
const cedarTimeout = 30 * time.Second

// cedarValidate runs the official `cedar validate` against the effective
// schema roverd uses (policy.SchemaFor, plan §5.1), when the cedar CLI is on
// PATH, and returns the exit code for validate. The schema is written to a
// private temporary directory because it is generated. For a policy.yaml,
// compiled holds the Cedar it compiled to, which is validated instead of the
// YAML file.
func cedarValidate(policyPath string, compiled, schema []byte) int {
	bin, err := exec.LookPath("cedar")
	if err != nil {
		fmt.Println("cedar CLI not installed; skipped")
		return 0
	}
	tmp, err := os.MkdirTemp("", "rover-cedar-")
	if err == nil {
		defer func() { _ = os.RemoveAll(tmp) }()
		err = writeNew(filepath.Join(tmp, schemaFile), schema)
	}
	if err == nil && compiled != nil {
		policyPath = filepath.Join(tmp, policyFile)
		err = writeNew(policyPath, compiled)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: cedar validate: temp file:", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), cedarTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "validate", "--schema", filepath.Join(tmp, schemaFile), "--policies", policyPath).CombinedOutput() //nolint:gosec // G204: the user's own cedar CLI, fixed arguments
	if len(out) > 0 {
		fmt.Print(string(out))
		if out[len(out)-1] != '\n' {
			fmt.Println()
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "cedar validate: failed (%s): %v\n", bin, err)
		return 1
	}
	fmt.Printf("cedar validate: ok (%s)\n", bin)
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
	file, _, err := pickPolicyFile(dirs.Config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	cfg, err := loadConfig(dirs.Config, file)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	l, err := loadPolicy(file, dirs.Config, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	eng, cfg := l.engine, l.cfg
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
		st.client, st.version = m.ClientInfo() // strict, like roverd
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
	fmt.Println("note: a running enforce daemon refuses to switch to observe; roverd.log then says")
	fmt.Println("  \"refused: switching enforce -> observe needs OS authentication (M9)\" (restart roverd to change it)")
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
