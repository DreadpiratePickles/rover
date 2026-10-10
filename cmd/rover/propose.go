package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/DreadpiratePickles/rover/internal/config"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/learn"
	"github.com/DreadpiratePickles/rover/internal/paths"
	"github.com/DreadpiratePickles/rover/internal/policy"
	"github.com/DreadpiratePickles/rover/internal/policy/propose"
	"github.com/DreadpiratePickles/rover/internal/policy/yaml2cedar"
	"github.com/DreadpiratePickles/rover/internal/state"
)

// policyPropose prints the policy learn mode proposes: the Cedar (and the
// YAML with --yaml), the calls it left out, the flagged ("suspicious")
// observations, and the roots config.yaml must declare before the proposal
// can be applied. --out writes the Cedar (or, with --yaml, the YAML) to a
// file instead of printing it; an existing file is kept unless --force.
func policyPropose(args []string) int {
	fset := flag.NewFlagSet("policy propose", flag.ExitOnError)
	out := fset.String("out", "", "write the proposal to FILE instead of printing it")
	withYAML := fset.Bool("yaml", false, "also print the policy.yaml equivalent (with --out: write the YAML)")
	force := fset.Bool("force", false, "with --out: overwrite FILE if it exists")
	_ = fset.Parse(args)
	if fset.NArg() != 0 {
		fmt.Fprintln(os.Stderr, policyUsage)
		return 2
	}
	if *out != "" && !*force {
		if _, err := os.Lstat(*out); err == nil {
			fmt.Fprintf(os.Stderr, "rover policy propose: %s exists; refusing to overwrite it (use --force)\n", *out)
			return 1
		}
	}
	p, note, err := buildProposal()
	if err != nil {
		fmt.Fprintln(os.Stderr, "rover policy propose:", err)
		return 1
	}
	if note != "" {
		fmt.Fprintln(os.Stderr, "note: "+note)
	}
	switch {
	case *out != "" && *withYAML && len(p.YAML) == 0:
		fmt.Fprintln(os.Stderr, "rover policy propose: "+p.YAMLNote)
		return 1
	case *out != "":
		data := p.Cedar
		if *withYAML {
			data = p.YAML
		}
		if err := writeNew(*out, data); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("wrote %s (%d rules)\n", *out, len(p.Rules))
	default:
		fmt.Print(string(p.Cedar))
		if *withYAML {
			printYAML(p)
		}
	}
	printProposalNotes(p)
	return 0
}

func printYAML(p propose.Proposal) {
	fmt.Println()
	if len(p.YAML) == 0 {
		fmt.Println("# " + p.YAMLNote)
		return
	}
	fmt.Println("# ---- policy.yaml equivalent ----")
	fmt.Print(string(p.YAML))
}

// printProposalNotes prints what was left out and the roots to add. Server
// and tool names come from the agent and the server: cell makes them safe
// for a terminal.
func printProposalNotes(p propose.Proposal) {
	if len(p.Notes) > 0 {
		fmt.Println("\nseen, not proposed:")
		for _, n := range p.Notes {
			fmt.Println("  " + cell(n))
		}
	}
	fmt.Println("\nsuspicious, not proposed:")
	if len(p.Suspicious) == 0 {
		fmt.Println("  (none)")
	}
	for _, o := range p.Suspicious {
		what := o.Tool
		if o.Action != learn.ActionCall {
			what = o.Action
		}
		fmt.Printf("  %s  %s  %s  flags: %s\n", o.TS.UTC().Format(time.RFC3339), cell(o.Server), cell(what), cell(strings.Join(o.Flagged, ", ")))
	}
	if len(p.NewRoots) > 0 {
		fmt.Println("\nroots to add to config.yaml:")
		for _, r := range p.NewRoots {
			q, _ := json.Marshal(r.Path)
			fmt.Printf("  %s: %s\n", r.Name, cell(string(q)))
		}
	}
}

// buildProposal loads the observations and the effective roots and labels
// and builds the proposal. note is roverd's note on a capped answer.
func buildProposal() (propose.Proposal, string, error) {
	dirs, err := paths.Resolve()
	if err == nil {
		err = paths.Ensure(dirs)
	}
	if err != nil {
		return propose.Proposal{}, "", err
	}
	cfg, err := effectiveConfig(dirs)
	if err != nil {
		return propose.Proposal{}, "", err
	}
	obs, note, err := loadObservations(dirs)
	if err != nil {
		return propose.Proposal{}, "", err
	}
	roots := map[string]string{}
	for _, r := range cfg.Roots {
		roots[r.Name] = r.Path
	}
	p, err := propose.Build(obs, roots, cfg.Labels, cfg.Normalizers)
	return p, note, err
}

// effectiveConfig is config.yaml with policy.yaml's roots and labels applied
// when policy.yaml is the policy roverd uses (as loadPolicy does). A
// policy.yaml that does not compile is ignored here: the proposal is about
// to replace it.
func effectiveConfig(dirs paths.Dirs) (config.Config, error) {
	file, _, perr := pickPolicyFile(dirs.Config)
	if perr != nil {
		file = ""
	}
	cfg, err := loadConfig(dirs.Config, file)
	if err != nil || file == "" || !isYAML(file) {
		return cfg, err
	}
	src, err := readCapped(file, yaml2cedar.MaxSourceBytes)
	if err != nil {
		return cfg, nil //nolint:nilerr // an unreadable policy.yaml only means config.yaml's roots apply
	}
	c, err := yaml2cedar.Compile(src, file)
	if err != nil {
		return cfg, nil //nolint:nilerr // see above
	}
	return cfg.WithPolicySettings(config.PolicySettings{Mode: c.Mode, RootOrder: c.RootOrder, Roots: c.Roots, Labels: c.Labels})
}

// loadObservations asks roverd (which holds the state database's lock)
// for the observations, or reads the database itself when no roverd runs.
func loadObservations(dirs paths.Dirs) ([]learn.Observation, string, error) {
	sock, err := paths.SocketPath(dirs)
	if err != nil {
		return nil, "", err
	}
	f, err := ipc.Admin(sock, ipc.Frame{Op: ipc.OpObservationsDump})
	if err == nil {
		var obs []learn.Observation
		if jerr := json.Unmarshal(f.Result, &obs); jerr != nil {
			return nil, "", fmt.Errorf("observations from roverd: %w", jerr)
		}
		return obs, f.Message, nil
	}
	if !errors.Is(err, ipc.ErrNoDaemon) {
		return nil, "", err
	}
	db, err := state.Open(filepath.Join(dirs.State, "state.db"))
	if errors.Is(err, state.ErrLocked) {
		return nil, "", errors.New("roverd holds the state database but did not answer on its socket; is it stuck?")
	}
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = db.Close() }()
	obs, err := propose.Load(db)
	return obs, "", err
}

// policyDiff prints the unified diff from the policy roverd would load
// (policy.cedar, else policy.yaml compiled) to the proposal, or to FILE (a
// .yaml FILE is compiled first). Exit status as diff(1): 0 same, 1
// different, 2 trouble.
func policyDiff(args []string) int {
	if len(args) > 1 {
		fmt.Fprintln(os.Stderr, policyUsage)
		return 2
	}
	dirs, err := paths.Resolve()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	var next []byte
	nextName := "proposal"
	if len(args) == 1 {
		nextName = args[0]
		next, err = cedarOf(args[0])
	} else {
		var p propose.Proposal
		p, _, err = buildProposal()
		next = p.Cedar
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "rover policy diff:", err)
		return 2
	}
	cur, curName := []byte(nil), "(no policy)"
	if file, _, perr := pickPolicyFile(dirs.Config); perr == nil {
		curName = file
		if cur, err = cedarOf(file); err != nil {
			fmt.Fprintln(os.Stderr, "rover policy diff:", err)
			return 2
		}
	}
	d := propose.UnifiedDiff(curName, nextName, cur, next)
	if d == "" {
		fmt.Println("no differences")
		return 0
	}
	fmt.Print(d)
	return 1
}

// cedarOf reads a policy file as Cedar, compiling a .yaml one.
func cedarOf(file string) ([]byte, error) {
	if !isYAML(file) {
		return readCapped(file, policy.MaxPolicyBytes)
	}
	src, err := readCapped(file, yaml2cedar.MaxSourceBytes)
	if err != nil {
		return nil, err
	}
	c, err := yaml2cedar.Compile(src, file)
	if err != nil {
		return nil, err
	}
	return c.Cedar, nil
}
