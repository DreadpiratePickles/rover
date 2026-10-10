package approve

import (
	"os"
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

func TestNonceIsOneTimeFreshAndPrivate(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	n := Nonce{Nonce: NewToken(), Hash: "h", Method: "fake", Created: now}
	if err := WriteNonce(dir, n); err != nil {
		t.Fatal(err)
	}
	got, err := ConsumeNonce(dir, now.Add(10*time.Second))
	if err != nil || got != n {
		t.Fatalf("got %+v err %v", got, err)
	}
	if _, err := ConsumeNonce(dir, now); err != ErrNoNonce {
		t.Fatalf("second use: %v", err)
	}
	// Stale.
	_ = WriteNonce(dir, n)
	if _, err := ConsumeNonce(dir, now.Add(NonceTTL+time.Second)); err == nil {
		t.Fatal("a stale nonce must be refused")
	}
	// World-readable.
	_ = WriteNonce(dir, n)
	if err := os.Chmod(filepath.Join(dir, NonceFile), 0o644); err != nil { //nolint:gosec // G302: the test makes it too open on purpose
		t.Fatal(err)
	}
	if _, err := ConsumeNonce(dir, now); err == nil {
		t.Fatal("a 0644 nonce must be refused")
	}
	if _, err := os.Lstat(filepath.Join(dir, NonceFile)); !os.IsNotExist(err) {
		t.Fatal("a refused nonce must be deleted too")
	}
	// A symlink is not followed.
	target := filepath.Join(dir, "target")
	_ = os.WriteFile(target, []byte("{}"), 0o600)
	_ = os.Symlink(target, filepath.Join(dir, NonceFile))
	if _, err := ConsumeNonce(dir, now); err == nil {
		t.Fatal("a symlinked nonce must be refused")
	}
}
