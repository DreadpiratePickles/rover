package audit

import (
	"path/filepath"
	"testing"
	"time"
)

// M9: roverd compares approval records with the newest audit entry's time.
func TestLastTimeSurvivesReopen(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	l.SetRedactor(noRedact)
	if !l.LastTime().IsZero() {
		t.Fatal("empty log must have no last time")
	}
	at := time.Date(2026, 10, 9, 1, 2, 3, 4, time.UTC)
	if werr := l.Write(Entry{Time: at, Session: "s", Kind: "state"}); werr != nil {
		t.Fatal(werr)
	}
	_ = l.Close()
	l2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l2.Close() }()
	if !l2.LastTime().Equal(at) {
		t.Fatalf("last time %v, want %v", l2.LastTime(), at)
	}
}
