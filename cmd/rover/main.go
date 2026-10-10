// Command rover is the Rover MCP security gateway.
//
//	rover wrap [--name N] -- <server command> [args...]
//	rover daemon [--log-bodies]
//	rover log [--log FILE] [--verify]
//
// "wrap" starts the real MCP server as a child process and sits between it and
// the agent. To use it, change the agent's MCP config from
//
//	"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
//
// to
//
//	"command": "rover", "args": ["wrap", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
//
// Every message the wrapper sees is decided by roverd ("rover daemon"), the
// one process per user that owns the audit log. The wrapper starts roverd if
// it is not running, and refuses to start the server if roverd cannot be
// reached (fail closed).
//
// "daemon" runs roverd in the foreground; its diagnostics go to stderr.
// "log" prints the audit log as a timeline, or checks its hash chain.
//
// Exit codes: 0 success (or, for wrap, the server's own exit code); 1 a setup
// or session error; 2 a usage error; 3 wrap could not reach roverd and did
// not start the server.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/daemon"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/paths"
	"github.com/DreadpiratePickles/rover/internal/proxy"
	"github.com/DreadpiratePickles/rover/internal/state"
)

// Exit codes.
const (
	exitOK          = 0
	exitError       = 1
	exitUsage       = 2
	exitUnreachable = 3 // wrap: roverd not reachable, server never started
)

const usageText = `usage:
  rover wrap [--name N] -- <server command> [args...]
  rover daemon [--log-bodies]
  rover log [--log FILE] [--verify]`

// The files roverd keeps in its directories (see internal/paths).
const (
	pidFileName    = "roverd.pid"  // in Run: flock'ed by the running roverd
	lockFileName   = "roverd.lock" // in Run: serialises auto-start between wrappers
	daemonLogName  = "roverd.log"  // in State: an auto-started roverd's stderr
	stateDBName    = "rover.db"    // in State
	auditLogName   = "audit.jsonl" // in State
	envLogBodies   = "ROVER_LOG_BODIES"
	envNoAutostart = "ROVER_TEST_NO_AUTOSTART"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "wrap":
		os.Exit(wrap(os.Args[2:]))
	case "daemon":
		os.Exit(runDaemon(os.Args[2:]))
	case "log":
		os.Exit(showLog(os.Args[2:]))
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, usageText)
	os.Exit(exitUsage)
}

// errf prints one diagnostic line. Everything rover prints goes to stderr:
// in wrap, stdout belongs to the MCP protocol.
func errf(format string, a ...any) { fmt.Fprintf(os.Stderr, "[rover] "+format+"\n", a...) }

// defaultLogPath is state/audit.jsonl (see internal/paths). If the
// directories cannot be resolved it prints why and exits 1: falling back to
// some relative path would read or write a log nobody expects (fail closed).
func defaultLogPath() string {
	d, err := paths.Resolve()
	if err != nil {
		errf("cannot find rover's directories: %v", err)
		os.Exit(exitError)
	}
	return filepath.Join(d.State, auditLogName)
}

// ---- rover daemon ---------------------------------------------------------

// runDaemon is roverd. It runs in the foreground until SIGINT or SIGTERM; the
// wrapper's auto-start detaches it (new session, output to state/roverd.log).
func runDaemon(args []string) int {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	logBodies := fs.Bool("log-bodies", false, "write message bodies into the audit log (also: "+envLogBodies+"=1)")
	if err := fs.Parse(args); err != nil {
		return parseExit(err)
	}
	if fs.NArg() != 0 {
		usage()
	}
	// The environment variable exists for auto-started daemons, which get
	// no flags: the wrapper that starts roverd passes its environment on.
	bodies := *logBodies || os.Getenv(envLogBodies) == "1"

	fail := func(format string, a ...any) int {
		fmt.Fprintf(os.Stderr, "roverd: "+format+"\n", a...)
		return exitError
	}
	d, err := paths.Resolve()
	if err != nil {
		return fail("cannot find rover's directories: %v", err)
	}
	if err = d.Ensure(); err != nil {
		return fail("refusing to start: %v", err)
	}

	pid, err := daemon.AcquirePIDFile(filepath.Join(d.Run, pidFileName))
	if errors.Is(err, daemon.ErrAlreadyRunning) {
		return fail("roverd already running (%s is locked)", filepath.Join(d.Run, pidFileName))
	}
	if err != nil {
		return fail("pid file: %v", err)
	}
	defer func() { _ = pid.Release() }()

	db, err := state.Open(filepath.Join(d.State, stateDBName))
	if err != nil {
		return fail("state database: %v", err)
	}
	defer func() { _ = db.Close() }()

	logPath := filepath.Join(d.State, auditLogName)
	alog, err := audit.Open(logPath)
	if err != nil {
		return fail("cannot open the audit log: %v (check it with: rover log --verify)", err)
	}
	defer func() { _ = alog.Close() }()

	dm, err := daemon.New(daemon.Options{Dirs: d, Audit: alog, State: db, LogBodies: bodies})
	if err != nil {
		return fail("%v", err)
	}
	l, err := ipc.Listen(d.Socket)
	if err != nil {
		return fail("cannot listen on %s: %v", d.Socket, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(os.Stderr, "roverd: pid %d listening on %s; audit log %s (bodies: %v)\n", os.Getpid(), d.Socket, logPath, bodies)
	if err := dm.Serve(ctx, l); err != nil { // Serve closes l, which removes the socket
		return fail("%v", err)
	}
	fmt.Fprintln(os.Stderr, "roverd: stopped")
	return exitOK
}

// parseExit maps a flag parse error to an exit code: -h is a success, anything
// else a usage error (the flag package has already printed why).
func parseExit(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	return exitUsage
}

// ---- rover wrap -----------------------------------------------------------

func wrap(args []string) int {
	fs := flag.NewFlagSet("wrap", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, usageText) }
	name := fs.String("name", "", "server name for the audit log (default: the command's base name)")
	// --log and --no-bodies were A1's per-wrapper audit controls. They are
	// parsed only so we can say where they went instead of "flag provided
	// but not defined".
	_ = fs.String("log", "", "removed in M1")
	_ = fs.Bool("no-bodies", false, "removed in M1")
	if err := fs.Parse(args); err != nil {
		return parseExit(err)
	}
	removed := false
	fs.Visit(func(f *flag.Flag) { removed = removed || f.Name == "log" || f.Name == "no-bodies" })
	if removed {
		errf("--log and --no-bodies are gone: the daemon owns the audit log now; see `rover daemon --log-bodies`")
		return exitUsage
	}
	server := fs.Args()
	if len(server) == 0 {
		usage()
	}
	serverName := *name
	if serverName == "" {
		serverName = filepath.Base(server[0])
	}

	d, err := paths.Resolve()
	if err != nil {
		errf("cannot find rover's directories: %v", err)
		errf("roverd is not reachable; refusing to start %s (fail closed)", server[0])
		return exitUnreachable
	}
	client, err := connect(d)
	if err != nil {
		errf("%v", err)
		errf("roverd is not reachable; refusing to start %s (fail closed)", server[0])
		return exitUnreachable
	}
	defer func() { _ = client.Close() }() // says bye; roverd ends the session view

	sum := sha256.Sum256([]byte(strings.Join(server, "\x00")))
	welcome, err := client.Hello(ipc.Hello{
		WrapperPID:      os.Getpid(),
		ClientPID:       os.Getppid(), // the agent app: wrappers it starts share one session
		ServerName:      serverName,
		ServerCmdSHA256: hex.EncodeToString(sum[:]),
		Transport:       "stdio",
	}, 5*time.Second)
	if err != nil {
		errf("roverd did not accept the session: %v", err)
		errf("roverd is not reachable; refusing to start %s (fail closed)", server[0])
		return exitUnreachable
	}

	// G204: running a caller-chosen command is the whole point of "wrap". The
	// command comes from the user's own MCP client config, and exec.Command
	// never goes through a shell, so there is no injection surface here.
	cmd := exec.Command(server[0], server[1:]...) //nolint:gosec // G204: wrapping the user-configured server is intended, see above
	cmd.Stderr = os.Stderr
	childIn, err := cmd.StdinPipe()
	if err != nil {
		errf("%v", err)
		return exitError
	}
	childOut, err := cmd.StdoutPipe()
	if err != nil {
		errf("%v", err)
		return exitError
	}
	if err := cmd.Start(); err != nil {
		errf("cannot start server %q: %v", server[0], err)
		return exitError
	}
	errf("session %s: wrapping %q as %q via roverd", welcome.SessionID, server, serverName)

	// Pass Ctrl-C / termination through to the child so it can shut down cleanly.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for s := range sigs {
			_ = cmd.Process.Signal(s)
		}
	}()

	pipe := &proxy.Pipe{ToServer: childIn, ToClient: os.Stdout, Decider: jsonOnly{client}}
	inDone := make(chan error, 1)
	outDone := make(chan error, 1)
	go func() {
		err := pipe.Pump(os.Stdin, proxy.ClientToServer)
		_ = childIn.Close() // agent hung up (or we stopped) -> EOF on the server's stdin
		inDone <- describe(proxy.ClientToServer, err)
	}()
	go func() { outDone <- describe(proxy.ServerToClient, pipe.Pump(childOut, proxy.ServerToClient)) }()

	var pumpErr error
	select {
	case pumpErr = <-outDone: // server closed its stdout (exited), or the s2c pump stopped
	case pumpErr = <-inDone:
		if pumpErr != nil {
			_ = cmd.Process.Kill()
		}
		if e := <-outDone; pumpErr == nil {
			pumpErr = e
		}
	}
	if pumpErr != nil {
		errf("session %s stopped: %v", welcome.SessionID, pumpErr)
		_ = cmd.Process.Kill() // fail closed: nothing more passes without a decision
	}

	waitErr := cmd.Wait()
	if pumpErr != nil {
		return exitError
	}
	var exit *exec.ExitError
	if errors.As(waitErr, &exit) {
		if code := exit.ExitCode(); code > 0 {
			return code
		}
		return exitError // killed by a signal
	}
	if waitErr != nil {
		errf("server: %v", waitErr)
		return exitError
	}
	return exitOK
}

// errNotJSON: MCP's stdio transport carries only JSON-RPC messages, and
// roverd can only be asked about JSON. Anything else stops the session.
var errNotJSON = errors.New("not a JSON message")

// jsonOnly refuses non-JSON lines before they reach roverd, so the wrapper
// can say exactly why the session stopped.
type jsonOnly struct{ proxy.Decider }

func (j jsonOnly) Decide(dir proxy.Direction, raw []byte) (proxy.Verdict, error) {
	if !json.Valid(raw) {
		return proxy.Verdict{}, errNotJSON
	}
	return j.Decider.Decide(dir, raw)
}

// describe turns a pump error into a one-line reason for the user.
func describe(dir proxy.Direction, err error) error {
	if err == nil {
		return nil
	}
	who := "the agent"
	if dir == proxy.ServerToClient {
		who = "the server"
	}
	switch {
	case errors.Is(err, errNotJSON):
		return fmt.Errorf("%s sent a line that is not JSON; MCP stdio carries only JSON-RPC messages, so the session stops (fail closed)", who)
	case errors.Is(err, proxy.ErrMessageTooLarge):
		return fmt.Errorf("%s sent a message larger than %d bytes; the session stops", who, proxy.DefaultMaxMessage)
	case errors.Is(err, proxy.ErrStopped):
		return fmt.Errorf("lost roverd's decision on a message from %s: %w", who, err)
	default:
		return fmt.Errorf("relaying a message from %s: %w", who, err)
	}
}

// connect dials roverd. If nobody answers it starts roverd (unless
// ROVER_TEST_NO_AUTOSTART is set) and waits up to 3 s for it.
func connect(d paths.Dirs) (*ipc.Client, error) {
	c, err := ipc.Dial(d.Socket, time.Second)
	if err == nil {
		return c, nil
	}
	if os.Getenv(envNoAutostart) != "" {
		return nil, fmt.Errorf("cannot connect to roverd: %w (%s is set, so rover did not try to start it)", err, envNoAutostart)
	}
	if c, err = autostart(d); err != nil {
		return nil, fmt.Errorf("cannot start roverd: %w", err)
	}
	return c, nil
}

// spawnDaemon starts `<this binary> daemon` detached from us: in its own
// session (so the agent's Ctrl-C or our exit does not take it down), stdin
// from /dev/null, stdout and stderr appended to state/roverd.log. The
// environment is inherited, so ROVER_DIR and ROVER_LOG_BODIES carry over.
func spawnDaemon(d paths.Dirs) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	logf, err := os.OpenFile(filepath.Join(d.State, daemonLogName), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = logf.Close() }() // the child has its own copy
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		return err
	}
	defer func() { _ = devnull.Close() }()

	cmd := exec.Command(exe, "daemon") //nolint:gosec // G204: re-executes this very binary with a fixed argument
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, logf, logf
	detach(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	// Reap it if it exits while we are still running (for example "already
	// running"); otherwise it outlives us and init adopts it.
	go func() { _ = cmd.Wait() }()
	return nil
}

// dialRetry dials every 100 ms until it connects or timeout passes.
func dialRetry(sock string, timeout time.Duration) (*ipc.Client, error) {
	deadline := time.Now().Add(timeout)
	for {
		c, err := ipc.Dial(sock, 100*time.Millisecond)
		if err == nil {
			return c, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("no answer on %s after %v: %w", sock, timeout, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// ---- rover log ------------------------------------------------------------

// showLog prints the audit log as a readable timeline, or with --verify
// checks its hash chain.
func showLog(args []string) int {
	fs := flag.NewFlagSet("log", flag.ExitOnError)
	logPath := fs.String("log", "", "audit log file (JSONL); default: <state dir>/audit.jsonl")
	verify := fs.Bool("verify", false, "check the hash chain and report the first break")
	_ = fs.Parse(args)

	if *verify {
		return verifyLog(*logPath)
	}
	if *logPath == "" {
		*logPath = defaultLogPath()
	}
	f, err := os.Open(*logPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = f.Close() }() // read-only: a close error loses nothing

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 32<<20)
	for sc.Scan() {
		var e audit.Entry
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		srv := e.Server
		if srv == "" {
			srv = "server" // entries written before M1 have no server name
		}
		arrow := "agent -> " + srv
		if e.Dir == "s2c" {
			arrow = srv + " -> agent"
		}
		what := e.Method
		if e.ReplyTo != "" {
			what = "reply to " + e.ReplyTo
		}
		if e.Tool != "" {
			what += " [" + e.Tool + "]"
		}
		extra := ""
		if e.LatencyMS != nil {
			extra = fmt.Sprintf(" %.1fms", *e.LatencyMS)
		}
		if e.ToolError {
			extra += " TOOL-ERROR"
		}
		fmt.Printf("%s %s %-24s %-12s id=%s %s%s\n",
			e.Time.Local().Format("15:04:05.000"), e.Session, arrow, e.Kind, string(e.ID), what, extra)
	}
	return 0
}

// verifyLog checks the chain: of one file with --log, otherwise of every log
// in the state dir (rotated files included, oldest first). Exit code 1 on any
// break or error.
func verifyLog(logPath string) int {
	var (
		n    int
		err  error
		name = logPath
	)
	if logPath != "" {
		n, err = verifyFile(logPath)
	} else {
		d, rerr := paths.Resolve()
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "[rover] cannot find rover's directories: %v\n", rerr)
			return 1
		}
		name = d.State
		n, _, err = audit.VerifyFiles(d.State)
	}

	var ve *audit.VerifyError
	switch {
	case errors.As(err, &ve):
		file := ve.File
		if file == "" {
			file = name
		}
		fmt.Printf("BROKEN at %s:%d: %s\n", file, ve.Line, ve.Reason)
		return 1
	case err != nil:
		fmt.Fprintf(os.Stderr, "[rover] cannot verify %s: %v\n", name, err)
		return 1
	}
	fmt.Printf("ok: %d entries, chain intact\n", n)
	return 0
}

// verifyFile checks one log file. A single file cannot prove nothing came
// before its first entry; VerifyFiles (no --log) checks across files.
func verifyFile(path string) (int, error) {
	// The path is the user's own --log choice. Refuse a symlink so the file
	// we verify is the file they named, not whatever it points at. (The os
	// package's Root type would confine this further, but its methods carry
	// GO-2026-6604 on Windows, so we keep to plain calls; see audit.openInDir.)
	fi, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return 0, fmt.Errorf("%s is a symlink; refusing to verify it (name the real file)", path)
	}
	f, err := os.Open(path) //nolint:gosec // G304: the user's own --log path, checked above not to be a symlink
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }() // read-only
	n, _, err := audit.Verify(f)
	return n, err
}
