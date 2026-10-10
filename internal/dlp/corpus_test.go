package dlp

import (
	"path/filepath"
	"testing"
)

// corpusDir is the DLP corpus, from this package's directory.
var corpusDir = filepath.Join("..", "..", "testdata", "corpus", "dlp")

// TestCorpusGates is the CI gate of plan §6 M10: recall (found with an
// expected kind AND gone after Redact) >= GateRecall, false positives on
// benign text <= GateFPRate, and a corpus that never shrinks.
func TestCorpusGates(t *testing.T) {
	// Arrange
	cases, err := LoadCorpus(corpusDir)
	if err != nil {
		t.Fatal(err)
	}

	// Act
	r := Evaluate(New(), cases)
	shrunk, err := CheckMinCounts(corpusDir, cases)
	if err != nil {
		t.Fatal(err)
	}

	// Assert
	for _, k := range Kinds {
		if s, ok := r.ByKind[k]; ok {
			t.Logf("%-18s secrets %2d found %2d | false pos %d", k, s.Secrets, s.Detected, s.FalsePos)
		}
	}
	t.Logf("overall: recall %.3f (%d/%d), fp-rate %.3f (%d/%d)", r.Total.Recall(), r.Total.Detected, r.Total.Secrets,
		r.Total.FPRate(), r.Total.FalsePos, r.Total.Benign)
	for _, o := range r.Outcomes {
		if o.Hit != (o.Case.Label == LabelSecrets) {
			t.Logf("  %s (%s): %+v", o.Case.ID, o.Case.Notes, o.Matches)
		}
	}
	for _, f := range append(r.Gates(), shrunk...) {
		t.Error(f)
	}
}

// TestEveryKindIsExercised fails if a kind is never expected by a case.
func TestEveryKindIsExercised(t *testing.T) {
	cases, err := LoadCorpus(corpusDir)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range cases {
		for _, k := range c.Expect {
			seen[k] = true
		}
	}
	for _, k := range Kinds {
		if !seen[k] {
			t.Errorf("no corpus case expects %s", k)
		}
	}
}
