package pin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/DreadpiratePickles/rover/internal/dlp"
	"github.com/DreadpiratePickles/rover/internal/state"
	bolt "go.etcd.io/bbolt"
)

// Pin methods: how a digest came to be trusted.
const (
	MethodTOFU   = "tofu"   // first sight
	MethodCLI    = "cli"    // `rover pin approve` before M9, without OS authentication
	MethodOSAuth = "osauth" // M9: "osauth:<method>", after the OS dialog succeeded
)

// maxStoredCanonical caps the copy of a tool's canonical JSON kept for diffs.
// The digest always covers the whole definition and only digests are ever
// compared, so a change beyond the cap is still a change; only the copy
// (and so the diff) is cut.
const maxStoredCanonical = 1 << 20

// Pinned is everything Rover remembers about one (server, tool).
//
// Digest is the approved definition ("" if none was ever approved: a tool
// first seen after the server was pinned). Mismatch means the tool is
// blocked: the server sent something other than Digest (Latest, with its
// canonical JSON for the diff; Latest is "" when the definition could not be
// canonicalised, and Problem says why). Mismatch is stored, so a restart
// does not forgive a change; only Approve or Reset clears it.
type Pinned struct {
	Server          string    `json:"server"`
	Tool            string    `json:"tool"`
	Digest          Digest    `json:"digest,omitempty"`
	ApprovedAt      time.Time `json:"approved_at"`
	Method          string    `json:"method,omitempty"`
	Canonical       string    `json:"canonical,omitempty"`
	Mismatch        bool      `json:"mismatch,omitempty"`
	Latest          Digest    `json:"latest,omitempty"`
	LatestCanonical string    `json:"latest_canonical,omitempty"`
	Problem         string    `json:"problem,omitempty"`
}

// State is the one-word summary `rover pin list` prints.
func (p Pinned) State() string {
	switch {
	case !p.Mismatch:
		return "ok"
	case p.Digest == "":
		return "new"
	default:
		return "MISMATCH"
	}
}

// Store persists pins. List with server "" returns every server's pins,
// sorted by server then tool.
type Store interface {
	List(server string) ([]Pinned, error)
	Put(ps ...Pinned) error
	DeleteServer(server string) (int, error)
}

// key is "<server>\x00<tool>". Server names cannot contain NUL
// (ipc.ValidServerName), so the first NUL always ends the server.
func key(server, tool string) []byte {
	return []byte(server + "\x00" + tool)
}

func sortPins(ps []Pinned) {
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].Server != ps[j].Server {
			return ps[i].Server < ps[j].Server
		}
		return ps[i].Tool < ps[j].Tool
	})
}

// capCanonical is the copy of a tool's canonical JSON stored for display:
// capped, and with secrets redacted (M10), since a description can quote
// a key. Only this copy is redacted; the digest is over the original.
func capCanonical(c []byte) string {
	d := dlp.New()
	out, _, _, err := dlp.RedactJSON(d, c)
	if err != nil {
		out = dlp.Redact(c, d.Find(c))
	}
	// Redacted first, then cut: a secret straddling the cap is gone, not
	// stored half raw. The cut copy is for display only.
	return string(out[:min(len(out), maxStoredCanonical)])
}

// BoltStore keeps pins in state.BucketPins.
type BoltStore struct{ db *state.DB }

// NewBoltStore returns a Store over roverd's state database.
func NewBoltStore(db *state.DB) *BoltStore { return &BoltStore{db: db} }

// List implements Store. A record that does not decode is an error, never
// skipped: skipping it would forget a mismatch.
func (b *BoltStore) List(server string) ([]Pinned, error) {
	var out []Pinned
	err := b.db.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(state.BucketPins)
		if bk == nil {
			return errors.New("pins bucket missing")
		}
		prefix := []byte(nil)
		if server != "" {
			prefix = key(server, "")
		}
		c := bk.Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			var p Pinned
			if err := json.Unmarshal(v, &p); err != nil {
				return fmt.Errorf("pin %q: %w", k, err)
			}
			out = append(out, p)
		}
		return nil
	})
	sortPins(out)
	return out, err
}

// Put implements Store; all records are written in one transaction.
func (b *BoltStore) Put(ps ...Pinned) error {
	if len(ps) == 0 {
		return nil
	}
	return b.db.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(state.BucketPins)
		if bk == nil {
			return errors.New("pins bucket missing")
		}
		for _, p := range ps {
			v, err := json.Marshal(p)
			if err != nil {
				return err
			}
			if err := bk.Put(key(p.Server, p.Tool), v); err != nil {
				return err
			}
		}
		return nil
	})
}

// DeleteServer implements Store.
func (b *BoltStore) DeleteServer(server string) (int, error) {
	n := 0
	err := b.db.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(state.BucketPins)
		if bk == nil {
			return errors.New("pins bucket missing")
		}
		prefix := key(server, "")
		var keys [][]byte
		c := bk.Cursor()
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			keys = append(keys, append([]byte(nil), k...))
		}
		for _, k := range keys {
			if err := bk.Delete(k); err != nil {
				return err
			}
		}
		n = len(keys)
		return nil
	})
	return n, err
}

// MemStore is an in-memory Store, for tests and for a daemon run without a
// state database.
type MemStore struct {
	mu sync.Mutex
	m  map[string]Pinned
}

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore { return &MemStore{m: map[string]Pinned{}} }

// List implements Store.
func (s *MemStore) List(server string) ([]Pinned, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Pinned
	for _, p := range s.m {
		if server == "" || p.Server == server {
			out = append(out, p)
		}
	}
	sortPins(out)
	return out, nil
}

// Put implements Store.
func (s *MemStore) Put(ps ...Pinned) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range ps {
		s.m[string(key(p.Server, p.Tool))] = p
	}
	return nil
}

// DeleteServer implements Store.
func (s *MemStore) DeleteServer(server string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, p := range s.m {
		if p.Server == server {
			delete(s.m, k)
			n++
		}
	}
	return n, nil
}
