package state

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestOpenCreatesBucketsAndVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	v, err := db.Version()
	if err != nil || v != SchemaVersion {
		t.Fatalf("version %d %v", v, err)
	}
	err = db.View(func(tx *bolt.Tx) error {
		for _, b := range allBuckets {
			if tx.Bucket(b) == nil {
				t.Errorf("bucket %s missing", b)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("perm %o, want 600", fi.Mode().Perm())
	}
}

func TestSecondOpenIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := Open(path); !errors.Is(err, ErrLocked) {
		t.Fatalf("want ErrLocked, got %v", err)
	}
}

func TestNewerSchemaIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], SchemaVersion+1)
	_ = db.Update(func(tx *bolt.Tx) error { return tx.Bucket(BucketMeta).Put(keySchema, buf[:]) })
	_ = db.Close()
	if _, err := Open(path); err == nil {
		t.Fatal("a file from a newer rover must not be opened")
	}
}
