package approve

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// LESSON (M9): roverd holds the state database while it runs, so the CLI
// cannot record an approved policy itself. After the human passes the OS
// dialog, `rover policy apply` writes a one-time nonce file into run/ and
// sends SIGHUP; roverd reads it, deletes it, checks it is fresh and that
// the hash in it is the hash of the files on disk now, and only then
// records the hash and loads the policy (and accepts a switch from enforce
// to observe). Without a valid nonce, a reload loads only the policy that
// is already approved.
//
// Honest limit: the nonce proves "an authenticated CLI ran" only against
// an agent that cannot write files into run/. A same-user process that can
// write anywhere the user can could forge it (plan §3: a same-user process
// can always attack Rover; the defence is detection and the deny rules
// `rover install` adds). The lesson discusses moving the dialog into roverd.

// NonceFile is the nonce's name inside the run directory.
const NonceFile = "apply.nonce"

// NonceTTL is how long a nonce is accepted after the dialog.
const NonceTTL = 60 * time.Second

// maxNonceBytes bounds the file roverd reads.
const maxNonceBytes = 4 << 10

// Nonce is what an authenticated `rover policy apply` hands roverd.
type Nonce struct {
	Nonce   string    `json:"nonce"`
	Hash    string    `json:"hash"`
	Method  string    `json:"method"`
	Created time.Time `json:"created"`
}

// WriteNonce writes n into runDir, 0600, replacing any earlier nonce. The
// old file is removed first and the new one created with O_EXCL, so a
// symlink planted at the path is replaced, never followed.
func WriteNonce(runDir string, n Nonce) error {
	p := filepath.Join(runDir, NonceFile)
	b, err := json.Marshal(n)
	if err != nil {
		return err
	}
	if rerr := os.Remove(p); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
		return rerr
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: Rover's own run directory
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// ErrNoNonce means no nonce file exists.
var ErrNoNonce = errors.New("no apply nonce")

// ConsumeNonce reads and deletes the nonce in runDir. It is deleted
// whatever its content, so it can be used once at most. It must be a
// regular 0600 file and younger than NonceTTL at now.
func ConsumeNonce(runDir string, now time.Time) (Nonce, error) {
	p := filepath.Join(runDir, NonceFile)
	fi, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return Nonce{}, ErrNoNonce
	}
	if err != nil {
		return Nonce{}, err
	}
	defer func() { _ = os.Remove(p) }()
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		return Nonce{}, fmt.Errorf("apply nonce %s is not a regular 0600 file; ignored", p)
	}
	f, err := os.Open(p) //nolint:gosec // G304: Rover's own run directory, checked above
	if err != nil {
		return Nonce{}, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxNonceBytes+1))
	if err != nil {
		return Nonce{}, err
	}
	if len(b) > maxNonceBytes {
		return Nonce{}, errors.New("apply nonce too large; ignored")
	}
	var n Nonce
	if err := json.Unmarshal(b, &n); err != nil {
		return Nonce{}, fmt.Errorf("apply nonce: %w", err)
	}
	if age := now.Sub(n.Created); age < -5*time.Second || age > NonceTTL {
		return Nonce{}, fmt.Errorf("apply nonce is %s old, accepted for %s; run `rover policy apply` again", age.Round(time.Second), NonceTTL)
	}
	if len(n.Nonce) != 32 || n.Hash == "" || n.Method == "" {
		return Nonce{}, errors.New("apply nonce is incomplete; ignored")
	}
	return n, nil
}
