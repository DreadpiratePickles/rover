package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/paths"
)

func defaultLogPath() string {
	if p := os.Getenv("ROVER_LOG"); p != "" {
		return p
	}
	dirs, err := paths.Resolve()
	if err != nil {
		return "audit.jsonl"
	}
	return filepath.Join(dirs.State, "audit.jsonl")
}

// showLog prints the audit log as a readable timeline, or checks its chain.
func showLog(args []string) int {
	fs := flag.NewFlagSet("log", flag.ExitOnError)
	logPath := fs.String("log", defaultLogPath(), "audit log file (JSONL)")
	verify := fs.Bool("verify", false, "check the hash chain and report the first break")
	_ = fs.Parse(args)

	f, err := os.Open(*logPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = f.Close() }()

	if *verify {
		res := audit.Verify(f)
		if res.Err != nil {
			fmt.Fprintf(os.Stderr, "%s: line %d: %v\n", *logPath, res.Line, res.Err)
			return 1
		}
		cont := ""
		if res.FirstPrev != "" {
			cont = fmt.Sprintf(", continues an earlier file (prev %.12s...)", res.FirstPrev)
		}
		fmt.Printf("%s: %d entries, chain intact%s\n", *logPath, res.Entries, cont)
		return 0
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), audit.MaxLine)
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
		action := e.Action
		if action == "" {
			action = "-"
		}
		fmt.Printf("%s %s %-10s %s %-12s %-7s id=%s %s%s\n",
			e.Time.Local().Format("15:04:05.000"), e.Session, e.Server, arrow, e.Kind, action, string(e.ID), what, extra)
	}
	return 0
}
