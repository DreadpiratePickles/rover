// Command rover is the Rover MCP security gateway.
//
//	rover wrap [--log FILE] [--no-bodies] -- <mcp server command> [args...]
//	rover log  [--log FILE]
//
// "wrap" starts the real MCP server as a child process and sits between it and
// the agent. To use it, change the agent's MCP config from
//
//	"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
//
// to
//
//	"command": "rover", "args": ["wrap", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/proxy"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "wrap":
		os.Exit(wrap(os.Args[2:]))
	case "log":
		os.Exit(showLog(os.Args[2:]))
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:\n  rover wrap [--log FILE] [--no-bodies] -- <server command> [args...]\n  rover log [--log FILE]")
	os.Exit(2)
}

func defaultLogPath() string {
	if p := os.Getenv("ROVER_LOG"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".rover", "audit.jsonl")
}

func wrap(args []string) int {
	fs := flag.NewFlagSet("wrap", flag.ExitOnError)
	logPath := fs.String("log", defaultLogPath(), "audit log file (JSONL)")
	noBodies := fs.Bool("no-bodies", false, "log metadata only, not message bodies")
	_ = fs.Parse(args)
	server := fs.Args()
	if len(server) == 0 {
		usage()
	}

	// Everything we print goes to stderr: stdout belongs to the protocol.
	errf := func(format string, a ...any) { fmt.Fprintf(os.Stderr, "[rover] "+format+"\n", a...) }

	log, err := audit.Open(*logPath)
	if err != nil {
		errf("cannot open audit log: %v", err)
		return 1 // fail closed: no audit log, no session
	}
	// The log file is unbuffered (each Write is one write(2) on an O_APPEND fd),
	// so there is nothing left to flush by the time we close it.
	defer func() { _ = log.Close() }()

	sess := proxy.NewSession(newSessionID(), log)
	sess.LogBodies = !*noBodies

	// G204: running a caller-chosen command is the whole point of "wrap". The
	// command comes from the user's own MCP client config, and exec.Command
	// never goes through a shell, so there is no injection surface here.
	cmd := exec.Command(server[0], server[1:]...) //nolint:gosec // G204: wrapping the user-configured server is intended, see above
	cmd.Stderr = os.Stderr
	childIn, err := cmd.StdinPipe()
	if err != nil {
		errf("%v", err)
		return 1
	}
	childOut, err := cmd.StdoutPipe()
	if err != nil {
		errf("%v", err)
		return 1
	}
	if err := cmd.Start(); err != nil {
		errf("cannot start server %q: %v", server[0], err)
		return 1
	}
	errf("session %s: wrapping %v, logging to %s", sess.ID, server, *logPath)

	// Pass Ctrl-C / termination through to the child so it can shut down cleanly.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for s := range sigs {
			_ = cmd.Process.Signal(s)
		}
	}()

	inDone := make(chan error, 1)
	outDone := make(chan error, 1)
	go func() {
		err := sess.Pump(os.Stdin, childIn, proxy.ClientToServer)
		_ = childIn.Close() // agent hung up -> tell the server (EOF on its stdin)
		inDone <- err
	}()
	go func() { outDone <- sess.Pump(childOut, os.Stdout, proxy.ServerToClient) }()

	var pumpErr error
	select {
	case pumpErr = <-outDone: // server closed its stdout (exited)
	case pumpErr = <-inDone:
		if pumpErr != nil {
			_ = cmd.Process.Kill()
		}
		if e := <-outDone; pumpErr == nil {
			pumpErr = e
		}
	}
	if pumpErr != nil {
		errf("session ended with error: %v", pumpErr)
		_ = cmd.Process.Kill()
	}

	waitErr := cmd.Wait()
	var exit *exec.ExitError
	if errors.As(waitErr, &exit) {
		return exit.ExitCode()
	}
	if pumpErr != nil {
		return 1
	}
	return 0
}

func newSessionID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// showLog prints the audit log as a readable timeline.
func showLog(args []string) int {
	fs := flag.NewFlagSet("log", flag.ExitOnError)
	logPath := fs.String("log", defaultLogPath(), "audit log file (JSONL)")
	_ = fs.Parse(args)

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
		arrow := "agent  -> server"
		if e.Dir == "s2c" {
			arrow = "server -> agent "
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
		fmt.Printf("%s %s %s %-12s id=%s %s%s\n",
			e.Time.Local().Format("15:04:05.000"), e.Session, arrow, e.Kind, string(e.ID), what, extra)
	}
	return 0
}
