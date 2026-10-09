package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/DreadpiratePickles/rover/internal/detect"
)

// defaultCorpus is the corpus in a checkout of the repository.
const defaultCorpus = "testdata/corpus"

// runEval implements `rover eval [--corpus DIR]`: it runs detection tier 1
// over the evaluation corpus and prints, per kind, precision, recall and
// false-positive rate, then the attack cases it missed and the benign cases
// it flagged. It exits 1 if a gate fails (recall, false positives, corpus
// size or MIN_COUNTS), so CI can run it as a gate.
func runEval(args []string) int {
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	dir := fs.String("corpus", defaultCorpus, "corpus directory (one subdirectory per family, one JSON case per file)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: rover eval [--corpus DIR]")
		return 2
	}
	cases, err := detect.LoadCorpus(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rover eval:", err)
		return 1
	}
	r := detect.Evaluate(detect.NewRules(), cases)
	shrunk, err := detect.CheckMinCounts(*dir, cases)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rover eval:", err)
		return 1
	}
	printReport(os.Stdout, r)
	fails := append(r.Gates(), shrunk...)
	if len(fails) > 0 {
		for _, f := range fails {
			fmt.Printf("GATE FAILED: %s\n", f)
		}
		return 1
	}
	fmt.Printf("gates passed: recall >= %.2f, false-positive rate <= %.2f, corpus >= %d attack / %d benign, MIN_COUNTS\n",
		detect.GateRecall, detect.GateFPRate, detect.MinAttack, detect.MinBenign)
	return 0
}

func printReport(w io.Writer, r detect.Report) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "KIND\tATTACKS\tDETECTED\tRECALL\tBENIGN\tFALSE POS\tFP RATE\tPRECISION")
	row := func(name string, s detect.Stats) {
		_, _ = fmt.Fprintf(tw, "%s\t%d\t%d\t%.3f\t%d\t%d\t%.3f\t%.3f\n",
			name, s.Attacks, s.Detected, s.Recall(), s.Benign, s.FalsePos, s.FPRate(), s.Precision())
	}
	for _, k := range detect.Kinds {
		if s, ok := r.ByKind[k]; ok {
			row(string(k), *s)
		}
	}
	row("all", r.Total)
	_ = tw.Flush()
	families := make([]string, 0, len(r.ByFamily))
	for f := range r.ByFamily {
		families = append(families, f)
	}
	sort.Strings(families)
	var parts []string
	for _, f := range families {
		if s := r.ByFamily[f]; s.Attacks > 0 {
			parts = append(parts, fmt.Sprintf("%s %.3f (%d/%d)", f, s.Recall(), s.Detected, s.Attacks))
		}
	}
	_, _ = fmt.Fprintf(w, "\nrecall by family: %s\n", strings.Join(parts, ", "))
	_, _ = fmt.Fprintf(w, "missed attacks (%d):\n", len(r.Missed))
	for _, o := range r.Outcomes {
		if o.Case.Attack() && !o.Hit {
			_, _ = fmt.Fprintf(w, "  %s  expected %s, got %s\n", o.Case.ID, strings.Join(o.Case.Expect, ","), findingList(o.Findings))
		}
	}
	_, _ = fmt.Fprintf(w, "false positives (%d):\n", len(r.FalsePos))
	for _, o := range r.Outcomes {
		if !o.Case.Attack() && o.Hit {
			_, _ = fmt.Fprintf(w, "  %s  %s\n", o.Case.ID, findingList(o.Findings))
		}
	}
}

// findingList renders findings as "id:severity (note)" for the report.
func findingList(fs []detect.Finding) string {
	if len(fs) == 0 {
		return "nothing"
	}
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, fmt.Sprintf("%s:%s (%s)", f.ID, f.Severity, f.Note))
	}
	return strings.Join(out, "; ")
}
