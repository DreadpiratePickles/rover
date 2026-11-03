package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/DreadpiratePickles/rover/internal/detect"
	"github.com/DreadpiratePickles/rover/internal/dlp"
)

// defaultCorpus is the corpus in a checkout of the repository.
const defaultCorpus = "testdata/corpus"

// runEval implements `rover eval [--corpus DIR]`: it runs detection tier 1
// over the evaluation corpus and prints, per kind, precision, recall and
// false-positive rate, then the attack cases it missed and the benign cases
// it flagged; then the same for the secret detectors over DIR/dlp (M10).
// It exits 1 if a gate fails (recall, false positives, corpus size or
// MIN_COUNTS, for either), so CI can run it as a gate.
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
	fails = append(fails, evalDLP(os.Stdout, filepath.Join(*dir, "dlp"))...)
	if len(fails) > 0 {
		for _, f := range fails {
			fmt.Printf("GATE FAILED: %s\n", f)
		}
		return 1
	}
	fmt.Printf("gates passed: recall >= %.2f, false-positive rate <= %.2f, corpus >= %d attack / %d benign, MIN_COUNTS\n",
		detect.GateRecall, detect.GateFPRate, detect.MinAttack, detect.MinBenign)
	fmt.Printf("dlp gates passed: recall >= %.2f, false-positive rate <= %.2f, corpus >= %d secret / %d benign, dlp/MIN_COUNTS\n",
		dlp.GateRecall, dlp.GateFPRate, dlp.MinSecrets, dlp.MinBenign)
	return 0
}

// evalDLP runs the secret detectors over the DLP corpus (M10), prints its
// table in the same style, and returns its failed gates.
func evalDLP(w io.Writer, dir string) []string {
	cases, err := dlp.LoadCorpus(dir)
	if err != nil {
		return []string{"dlp corpus: " + err.Error()}
	}
	r := dlp.Evaluate(dlp.New(), cases)
	shrunk, err := dlp.CheckMinCounts(dir, cases)
	if err != nil {
		return []string{"dlp corpus: " + err.Error()}
	}
	_, _ = fmt.Fprintln(w, "\ndlp (secrets: found with an expected kind and gone after redaction)")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "KIND\tSECRETS\tDETECTED\tRECALL\tFALSE POS")
	for _, k := range dlp.Kinds {
		if st, ok := r.ByKind[k]; ok {
			_, _ = fmt.Fprintf(tw, "%s\t%d\t%d\t%.3f\t%d\n", k, st.Secrets, st.Detected, st.Recall(), st.FalsePos)
		}
	}
	t := r.Total
	_, _ = fmt.Fprintf(tw, "all\t%d\t%d\t%.3f\t%d of %d benign (FP rate %.3f, precision %.3f)\n",
		t.Secrets, t.Detected, t.Recall(), t.FalsePos, t.Benign, t.FPRate(), t.Precision())
	_ = tw.Flush()
	var missed, fps []string
	for _, o := range r.Outcomes {
		switch {
		case o.Case.Label == dlp.LabelSecrets && !o.Hit:
			missed = append(missed, fmt.Sprintf("  %s  expected %s, got %s", o.Case.ID, strings.Join(o.Case.Expect, ","), matchKinds(o.Matches)))
		case o.Case.Label == dlp.LabelBenign && o.Hit:
			fps = append(fps, fmt.Sprintf("  %s  %s", o.Case.ID, matchKinds(o.Matches)))
		}
	}
	_, _ = fmt.Fprintf(w, "missed secrets (%d):\n%s", len(missed), lines(missed))
	_, _ = fmt.Fprintf(w, "false positives (%d):\n%s", len(fps), lines(fps))
	return append(r.Gates(), shrunk...)
}

func matchKinds(ms []dlp.Match) string {
	if len(ms) == 0 {
		return "nothing"
	}
	return strings.Join(dlp.KindsOf(ms), ",")
}

func lines(ls []string) string {
	if len(ls) == 0 {
		return ""
	}
	return strings.Join(ls, "\n") + "\n"
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
