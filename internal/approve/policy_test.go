package approve

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/DreadpiratePickles/rover/internal/state"
)

func TestPolicyHashCoversEveryPartAndAbsence(t *testing.T) {
	base := []PolicyPart{{Name: "policy.cedar", Data: []byte("permit"), Present: true}, {Name: "config.yaml", Data: []byte("mode: enforce\n"), Present: true}}
	h := PolicyHash(base)
	edited := []PolicyPart{base[0], {Name: "config.yaml", Data: []byte("mode: observe\n"), Present: true}}
	deleted := []PolicyPart{base[0], {Name: "config.yaml", Present: false}}
	shifted := []PolicyPart{{Name: "policy.cedar", Data: []byte("permitmode: enforce\n"), Present: true}, {Name: "config.yaml", Present: true}}
	for name, parts := range map[string][]PolicyPart{"edited": edited, "deleted": deleted, "shifted": shifted} {
		if PolicyHash(parts) == h {
			t.Errorf("%s bundle has the same hash", name)
		}
	}
	if PolicyHash(base) != h || len(h) != 64 {
		t.Fatal("hash not stable")
	}
}

func TestApprovePolicyKeepsOnlyTheLatestCurrent(t *testing.T) {
	db, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, found, cerr := CurrentPolicy(db); found || cerr != nil {
		t.Fatalf("fresh db: found %v err %v", found, cerr)
	}
	now := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	a, b := PolicyHash([]PolicyPart{{Name: "a"}}), PolicyHash([]PolicyPart{{Name: "b"}})
	if perr := RecordPolicy(db, a, MethodInit, now); perr != nil {
		t.Fatal(perr)
	}
	if perr := RecordPolicy(db, b, "fake", now.Add(time.Second)); perr != nil {
		t.Fatal(perr)
	}
	cur, found, err := CurrentPolicy(db)
	if err != nil || !found || cur.Hash != b || cur.Method != "fake" {
		t.Fatalf("current %+v found %v err %v", cur, found, err)
	}
	if err := RecordPolicy(db, "short", "x", now); err == nil {
		t.Fatal("a malformed hash must be refused")
	}
}
