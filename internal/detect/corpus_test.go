package detect

import (
	"path/filepath"
	"sort"
	"testing"
)

// corpusDir is the evaluation corpus, from this package's directory.
var corpusDir = filepath.Join("..", "..", "testdata", "corpus")

// TestCorpusGates is the CI gate of plan §6 M5: recall on attack cases at
// least GateRecall, false positives on benign cases at most GateFPRate, and
// a corpus that never shrinks (MIN_COUNTS).
func TestCorpusGates(t *testing.T) {
	// Arrange
	cases, err := LoadCorpus(corpusDir)
	if err != nil {
		t.Fatal(err)
	}

	// Act
	r := Evaluate(NewRules(), cases)
	shrunk, err := CheckMinCounts(corpusDir, cases)
	if err != nil {
		t.Fatal(err)
	}

	// Assert
	kinds := make([]string, 0, len(r.ByKind))
	for k := range r.ByKind {
		kinds = append(kinds, string(k))
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		s := r.ByKind[Kind(k)]
		t.Logf("%-17s attacks %2d detected %2d recall %.3f | benign %2d fp %d fp-rate %.3f | precision %.3f",
			k, s.Attacks, s.Detected, s.Recall(), s.Benign, s.FalsePos, s.FPRate(), s.Precision())
	}
	t.Logf("overall: recall %.3f (%d/%d), fp-rate %.3f (%d/%d)", r.Total.Recall(), r.Total.Detected, r.Total.Attacks,
		r.Total.FPRate(), r.Total.FalsePos, r.Total.Benign)
	t.Logf("missed: %v", r.Missed)
	t.Logf("false positives: %v", r.FalsePos)
	for _, o := range r.Outcomes {
		if o.Case.Attack() && o.Hit {
			continue
		}
		if !o.Case.Attack() && !o.Hit {
			continue
		}
		for _, f := range o.Findings {
			t.Logf("  %s: %s %s %s", o.Case.ID, f.ID, f.Severity, f.Note)
		}
	}
	for _, f := range append(r.Gates(), shrunk...) {
		t.Error(f)
	}
}

// TestExpectedRulesFire lists, for information, every expected rule id that
// did not fire on its case (a case still counts as detected when one of its
// expected ids fires). It fails only if an expected id never fires anywhere
// in the corpus, which would mean the rule is dead.
func TestExpectedRulesFire(t *testing.T) {
	cases, err := LoadCorpus(corpusDir)
	if err != nil {
		t.Fatal(err)
	}
	fired := map[string]bool{}
	for _, o := range Evaluate(NewRules(), cases).Outcomes {
		got := map[string]bool{}
		for _, f := range o.Findings {
			got[f.ID] = true
			fired[f.ID] = true
		}
		for _, id := range o.Case.Expect {
			if !got[id] {
				t.Logf("%s: expected %s did not fire", o.Case.ID, id)
			}
		}
	}
	for _, id := range RuleIDs {
		if id != RuleOversizedResult && !fired[id] {
			t.Errorf("rule %s fires on no corpus case", id)
		}
	}
}
