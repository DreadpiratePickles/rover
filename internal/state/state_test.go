package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func open(t *testing.T, path string) *DB {
	t.Helper()
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestOpenCreatesBucketsAndVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rover.db")
	db := open(t, path)
	v, err := db.SchemaVersion()
	if err != nil || v != SchemaVersion {
		t.Fatalf("SchemaVersion = %d, %v", v, err)
	}
	err = db.b.View(func(tx *bolt.Tx) error {
		for _, name := range allBuckets {
			if tx.Bucket(name) == nil {
				t.Errorf("bucket %s missing", name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("db mode %o, want 600", fi.Mode().Perm())
	}
	// Reopening keeps working.
	if err = open(t, path).Close(); err != nil {
		t.Fatal(err)
	}
}

func setVersion(t *testing.T, path, v string) {
	t.Helper()
	db := open(t, path)
	err := db.b.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(BucketMeta).Put(keySchemaVersion, []byte(v))
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
}

// Fail closed: an older rover must not touch state written by a newer one.
func TestNewerSchemaRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rover.db")
	setVersion(t, path, "2")
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("schema 2 accepted, err=%v", err)
	}
}

func TestBadSchemaRefused(t *testing.T) {
	for _, v := range []string{"0", "-1", "one", ""} {
		path := filepath.Join(t.TempDir(), "rover.db")
		setVersion(t, path, v)
		if _, err := Open(path); err == nil {
			t.Fatalf("schema %q accepted", v)
		}
	}
}

// Single owner: while one process holds the db, a second Open fails within
// the timeout instead of waiting forever.
func TestSecondOpenTimesOut(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rover.db")
	db := open(t, path)
	defer func() { _ = db.Close() }()

	start := time.Now()
	second, err := Open(path)
	elapsed := time.Since(start)
	if err == nil {
		_ = second.Close()
		t.Fatal("second Open succeeded while the first is open")
	}
	if !strings.Contains(err.Error(), "locked") {
		t.Fatalf("unexpected error: %v", err)
	}
	if elapsed < OpenTimeout/2 || elapsed > OpenTimeout+time.Second {
		t.Fatalf("second Open took %v, want about %v", elapsed, OpenTimeout)
	}
}

func TestLooseFileRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rover.db")
	if err := open(t, path).Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil { //nolint:gosec // G302: the test deliberately loosens the file
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("0644 db accepted")
	}
}

func TestSymlinkRefused(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.db")
	if err := open(t, target).Close(); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "rover.db")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link); err == nil {
		t.Fatal("symlinked db accepted")
	}
}
