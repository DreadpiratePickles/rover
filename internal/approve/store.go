package approve

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/DreadpiratePickles/rover/internal/state"
)

// Record is one approval as stored in the approvals bucket: pending while
// the human is asked, then decided with the method and time.
type Record struct {
	Request
	State     string    `json:"state"`
	Method    string    `json:"method,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	DecidedAt time.Time `json:"decided_at,omitzero"`
}

// Store keeps approval records.
type Store interface {
	Put(Record) error
	Get(id string) (Record, bool, error)
}

// persisted drops what must not reach the disk: the arguments. roverd
// redacts the secrets it recognises (M10), but a record does not need them
// and DLP cannot recognise every secret, so they stay in memory only.
func persisted(r Record) Record {
	r.Args = nil
	r.Elicitor = nil
	return r
}

// MemStore is a Store in memory (tests, and a daemon without a database).
type MemStore struct {
	mu sync.Mutex
	m  map[string]Record
}

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore { return &MemStore{m: map[string]Record{}} }

// Put implements Store.
func (s *MemStore) Put(r Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[r.ID] = persisted(r)
	return nil
}

// Get implements Store.
func (s *MemStore) Get(id string) (Record, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.m[id]
	return r, ok, nil
}

// BoltStore keeps records in state's approvals bucket, keyed by id.
type BoltStore struct{ db *state.DB }

// NewBoltStore returns a Store over db.
func NewBoltStore(db *state.DB) *BoltStore { return &BoltStore{db: db} }

// Put implements Store.
func (s *BoltStore) Put(r Record) error {
	b, err := json.Marshal(persisted(r))
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(state.BucketApprovals)
		if bk == nil {
			return errors.New("approvals bucket missing")
		}
		return bk.Put([]byte(r.ID), b)
	})
}

// Get implements Store.
func (s *BoltStore) Get(id string) (Record, bool, error) {
	var r Record
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(state.BucketApprovals)
		if bk == nil {
			return errors.New("approvals bucket missing")
		}
		raw := bk.Get([]byte(id))
		if raw == nil {
			return nil
		}
		found = true
		if err := json.Unmarshal(raw, &r); err != nil {
			return fmt.Errorf("approval %s: %w", id, err)
		}
		return nil
	})
	return r, found, err
}
