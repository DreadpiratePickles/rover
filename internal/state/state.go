// Package state is roverd's on-disk database (plan §4.5), a single bbolt
// file in the state directory.
//
// bbolt is a small, pure-Go, single-writer key/value store with ACID
// transactions and an exclusive file lock: a second process cannot open the
// file while roverd has it, which also makes it a natural guard against two
// daemons running at once. Nothing in it is secret by design (pins, approval
// records, learn-mode observations), but it is created 0600 like everything
// else Rover writes.
//
// Every bucket exists from the first run so later milestones can rely on
// them, and the schema version in "meta" lets a newer roverd migrate an older
// file instead of guessing.
package state

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
	berrors "go.etcd.io/bbolt/errors"
)

// SchemaVersion is bumped whenever a bucket's layout changes. Migrate runs
// the steps between the file's version and this one.
const SchemaVersion = 1

// Bucket names.
var (
	BucketPins           = []byte("pins")            // server -> tool -> digest (M4)
	BucketObservations   = []byte("observations")    // learn mode (M6)
	BucketApprovedPolicy = []byte("approved_policy") // hash, approved_at, approver (M9)
	BucketApprovals      = []byte("approvals")       // pending and decided (M9)
	BucketGrants         = []byte("grants")          // rover-net (N4)
	BucketMeta           = []byte("meta")

	keySchema = []byte("schema_version")
)

var allBuckets = [][]byte{BucketPins, BucketObservations, BucketApprovedPolicy, BucketApprovals, BucketGrants, BucketMeta}

// ErrLocked is returned when another process holds the database.
var ErrLocked = errors.New("state database is locked by another process (is roverd already running?)")

// DB wraps the bbolt handle.
type DB struct {
	b *bolt.DB
}

// Open opens or creates the database at path, creates every bucket and
// migrates the schema. It gives up after one second if another process holds
// the lock.
func Open(path string) (*DB, error) {
	b, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if errors.Is(err, berrors.ErrTimeout) {
		return nil, ErrLocked
	}
	if err != nil {
		return nil, fmt.Errorf("open state: %w", err)
	}
	db := &DB{b: b}
	if err := db.migrate(); err != nil {
		_ = b.Close()
		return nil, err
	}
	return db, nil
}

// Close releases the file lock.
func (d *DB) Close() error { return d.b.Close() }

// Version returns the schema version stored in the file.
func (d *DB) Version() (uint32, error) {
	var v uint32
	err := d.b.View(func(tx *bolt.Tx) error {
		m := tx.Bucket(BucketMeta)
		if m == nil {
			return errors.New("meta bucket missing")
		}
		raw := m.Get(keySchema)
		if len(raw) != 4 {
			return fmt.Errorf("schema_version is %d bytes, want 4", len(raw))
		}
		v = binary.BigEndian.Uint32(raw)
		return nil
	})
	return v, err
}

// Update runs fn in a read-write transaction.
func (d *DB) Update(fn func(*bolt.Tx) error) error { return d.b.Update(fn) }

// View runs fn in a read-only transaction.
func (d *DB) View(fn func(*bolt.Tx) error) error { return d.b.View(fn) }

func (d *DB) migrate() error {
	return d.b.Update(func(tx *bolt.Tx) error {
		for _, name := range allBuckets {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return fmt.Errorf("bucket %s: %w", name, err)
			}
		}
		meta := tx.Bucket(BucketMeta)
		raw := meta.Get(keySchema)
		have := uint32(0)
		if len(raw) == 4 {
			have = binary.BigEndian.Uint32(raw)
		}
		switch {
		case have > SchemaVersion:
			return fmt.Errorf("state file is schema %d, this roverd understands up to %d: upgrade rover", have, SchemaVersion)
		case have == SchemaVersion:
			return nil
		}
		// Future migrations go here as `for v := have; v < SchemaVersion; v++`.
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], SchemaVersion)
		return meta.Put(keySchema, buf[:])
	})
}
