// Package state is roverd's small database: pins, learn-mode observations,
// the approved policy, approvals, network grants and metadata, in one bbolt
// file (state/rover.db).
//
// LESSON (M1):
//   - bbolt is an embedded key/value store: one file, no server, ACID
//     transactions. It takes an exclusive file lock (flock) on open, so only
//     one roverd can own the state at a time; a second Open waits at most
//     Timeout and then fails instead of corrupting anything.
//   - The file holds security state (which tool definitions were approved,
//     which calls a human allowed), so it is 0600 and we refuse a file that
//     is looser, or that is a symlink to somewhere else.
//   - A schema version in the "meta" bucket lets a future Rover migrate old
//     data. An OLDER binary that finds a NEWER schema refuses to open it:
//     guessing at a format you do not understand is how security state gets
//     silently misread (fail closed).
package state

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"time"

	bolt "go.etcd.io/bbolt"
	berrors "go.etcd.io/bbolt/errors"
)

// SchemaVersion is the schema this binary writes and understands.
const SchemaVersion = 1

// OpenTimeout is how long Open waits for another process's lock.
const OpenTimeout = time.Second

// Bucket names (plan §4.5).
var (
	BucketPins           = []byte("pins")            // server -> tool -> digest (M4)
	BucketObservations   = []byte("observations")    // learn mode (M6)
	BucketApprovedPolicy = []byte("approved_policy") // hash, approved_at, approver method
	BucketApprovals      = []byte("approvals")       // pending and decided (M9)
	BucketGrants         = []byte("grants")          // rover-net (N4)
	BucketMeta           = []byte("meta")            // schema_version
)

var allBuckets = [][]byte{BucketPins, BucketObservations, BucketApprovedPolicy, BucketApprovals, BucketGrants, BucketMeta}

var keySchemaVersion = []byte("schema_version")

// DB is the open state database.
type DB struct {
	b *bolt.DB
}

// Open opens (creating if needed) the database at path, creates the buckets
// and checks the schema version. The directory must already exist and be
// private (see paths.Ensure).
func Open(path string) (*DB, error) {
	// Refuse a symlink before bbolt follows it.
	if fi, err := os.Lstat(path); err == nil {
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("state db %s is not a regular file (symlink?); refusing to open it", path)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	b, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: OpenTimeout})
	if err != nil {
		if errors.Is(err, berrors.ErrTimeout) {
			return nil, fmt.Errorf("state db %s is locked by another process (is roverd already running?): %w", path, err)
		}
		return nil, fmt.Errorf("state db %s: %w", path, err)
	}
	db := &DB{b: b}
	if err := db.init(); err != nil {
		_ = b.Close()
		return nil, fmt.Errorf("state db %s: %w", path, err)
	}
	return db, nil
}

func (db *DB) init() error {
	// bbolt creates the file 0600, but an existing file keeps its mode.
	fi, err := os.Stat(db.b.Path())
	if err != nil {
		return err
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("mode is %04o; it must be 0600", perm)
	}
	return db.b.Update(func(tx *bolt.Tx) error {
		for _, name := range allBuckets {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		meta := tx.Bucket(BucketMeta)
		raw := meta.Get(keySchemaVersion)
		if raw == nil {
			return meta.Put(keySchemaVersion, []byte(strconv.Itoa(SchemaVersion)))
		}
		v, err := parseVersion(raw)
		if err != nil {
			return err
		}
		if v > SchemaVersion {
			return fmt.Errorf("schema version %d is newer than this rover understands (%d); upgrade rover", v, SchemaVersion)
		}
		// v < SchemaVersion would be migrated here; version 1 is the first.
		return nil
	})
}

func parseVersion(raw []byte) (int, error) {
	v, err := strconv.Atoi(string(raw))
	if err != nil || v < 1 {
		return 0, fmt.Errorf("invalid schema version %q", raw)
	}
	return v, nil
}

// SchemaVersion reads the stored schema version.
func (db *DB) SchemaVersion() (int, error) {
	var v int
	err := db.b.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket(BucketMeta)
		if meta == nil {
			return errors.New("meta bucket missing")
		}
		raw := meta.Get(keySchemaVersion)
		if raw == nil {
			return errors.New("schema version missing")
		}
		var err error
		v, err = parseVersion(raw)
		return err
	})
	return v, err
}

// Close releases the database and its lock.
func (db *DB) Close() error {
	return db.b.Close()
}
