package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/config"
	"github.com/DreadpiratePickles/rover/internal/daemon"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
	"github.com/DreadpiratePickles/rover/internal/paths"
	"github.com/DreadpiratePickles/rover/internal/policy"
)

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
	f, err := os.Open(args[0]) //nolint:gosec // G703: reading the file the operator names on the command line is this command's job
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
