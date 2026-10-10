package approve

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/DreadpiratePickles/rover/internal/state"
)

// LESSON (M9): the policy is the gateway's brain, so changing it is an
// approval like any other. roverd only loads a policy whose hash a human
// approved: `rover policy apply` shows the OS dialog first and records the
// hash. Editing policy.cedar (or config.yaml, which holds the mode) and
// sending SIGHUP does nothing but log a refusal. There is no exception for
// the first policy: `rover policy init` asks for the dialog too. (An earlier
// version trusted the first policy on first use, and deleting state.db made
// any policy "the first" again.) Only the most recently approved hash is
// accepted, so
// an agent cannot roll back to an older, looser policy a human once
// approved either.

// PolicyApproval is one approved policy hash.
type PolicyApproval struct {
	Hash       string    `json:"hash"`
	ApprovedAt time.Time `json:"approved_at"`
	Method     string    `json:"method"`
}

var keyCurrent = []byte("current")

// PolicyPart is one file of the policy bundle: the policy file, config.yaml,
// the schema and the normalizers file. Present false means the file does
// not exist, which is part of the hash too (deleting config.yaml switches
// to observe mode, so it must not go unnoticed).
type PolicyPart struct {
	Name    string
	Data    []byte
	Present bool
}

// PolicyHash is the SHA-256 of the bundle: each part's name, presence,
// length and bytes, in the order given.
func PolicyHash(parts []PolicyPart) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p.Name))
		h.Write([]byte{0})
		if !p.Present {
			h.Write([]byte("absent\x00"))
			continue
		}
		h.Write([]byte(strconv.Itoa(len(p.Data))))
		h.Write([]byte{0})
		h.Write(p.Data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// CurrentPolicy returns the most recently approved policy, if any.
func CurrentPolicy(db *state.DB) (PolicyApproval, bool, error) {
	var a PolicyApproval
	var found bool
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(state.BucketApprovedPolicy)
		if b == nil {
			return errors.New("approved_policy bucket missing")
		}
		raw := b.Get(keyCurrent)
		if raw == nil {
			return nil
		}
		found = true
		return json.Unmarshal(raw, &a)
	})
	return a, found, err
}

// RecordPolicy records hash as the approved policy, keeping a history entry
// under "h/<approved_at>".
func RecordPolicy(db *state.DB, hash, method string, now time.Time) error {
	if len(hash) != sha256.Size*2 {
		return fmt.Errorf("approve policy: bad hash %q", hash)
	}
	a := PolicyApproval{Hash: hash, ApprovedAt: now.UTC(), Method: method}
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(state.BucketApprovedPolicy)
		if b == nil {
			return errors.New("approved_policy bucket missing")
		}
		if err := b.Put([]byte("h/"+a.ApprovedAt.Format(time.RFC3339Nano)), raw); err != nil {
			return err
		}
		return b.Put(keyCurrent, raw)
	})
}
