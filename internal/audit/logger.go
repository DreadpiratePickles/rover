// Package audit writes one JSON object per line (JSONL) for every message the
// gateway sees, as a tamper-evident hash chain.
//
// LESSON (A1):
//   - Audit logs are themselves sensitive: tool arguments contain file paths,
//     queries and sometimes secrets. The file is created 0600 (owner-only).
//     Module A5 adds redaction before anything is written.
//   - Logs are written BEFORE the message is forwarded ("log-then-forward").
//     If the gateway crashes mid-call, the record of what was attempted exists.
//   - If the log cannot be written, the caller stops the session: a security
//     control that silently keeps going without its audit trail "fails open".
//
// LESSON (M1): the hash chain.
//   - Every entry carries "prev" (the hash of the entry before it) and "hash"
//     (SHA-256 of the entry's own bytes, see chain.go). Change one byte of an
//     old entry and its hash no longer matches; delete or reorder an entry and
//     the next entry's "prev" no longer matches. `rover log --verify` walks the
//     chain and reports the first break.
//   - "Tamper-evident" is not "tamper-proof": someone who can write the file
//     can also recompute every hash after their edit. The chain catches
//     accidental damage and careless edits; anchoring the latest hash
//     somewhere the attacker cannot write is what makes it strong.
//   - The chain spans files: when audit.jsonl reaches MaxBytes it is renamed to
//     audit-<UTC time>.jsonl and the first entry of the new file links to the
//     last entry of the old one, so deleting a whole old file is detected too.
package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DefaultMaxBytes is the size at which Open'ed logs are rotated (plan §4.6).
const DefaultMaxBytes = 50 << 20

// Entry is one line of the audit log: one message seen in one direction.
//
// New fields go at the END so the field order in the JSON (and therefore the
// bytes that get hashed) stays stable for existing fields.
type Entry struct {
	Time      time.Time       `json:"ts"`
	Session   string          `json:"session"`
	Dir       string          `json:"dir"`  // "c2s" (client->server) or "s2c"
	Kind      string          `json:"kind"` // request | notification | result | error | invalid
	Method    string          `json:"method,omitempty"`
	ID        json.RawMessage `json:"id,omitempty"`
	Tool      string          `json:"tool,omitempty"`
	ReplyTo   string          `json:"reply_to,omitempty"` // for results/errors: the method they answer
	LatencyMS *float64        `json:"latency_ms,omitempty"`
	ToolError bool            `json:"tool_error,omitempty"` // result had isError=true
	Bytes     int             `json:"bytes"`
	Body      json.RawMessage `json:"body,omitempty"`
	Server    string          `json:"server,omitempty"` // MCP server name from the wrapper's hello
	Prev      string          `json:"prev"`             // hex SHA-256 of the previous entry; "" for the very first entry ever
	Hash      string          `json:"hash,omitempty"`   // hex SHA-256 of this entry; set by Write, see chain.go
}

// Logger appends Entries to the hash chain. It is safe for concurrent use.
//
// After any failed write the Logger refuses all further writes (the file may
// now end in a partial line, and appending after it would hide the damage).
type Logger struct {
	// MaxBytes: after a write that leaves the file larger than this, the file
	// is rotated. 0 disables rotation. Open sets DefaultMaxBytes; loggers from
	// New never rotate (there is no file to rename).
	MaxBytes int64
	// Now supplies entry times (when an Entry has none) and rotation names.
	// Tests inject a fixed clock.
	Now func() time.Time

	mu   sync.Mutex
	w    io.Writer
	f    *os.File // the open log file; nil for New
	dir  string   // the log's directory; "" for New
	name string   // the log's file name inside dir
	size int64
	last string // hash of the last entry written (the next entry's Prev)
	err  error  // sticky: once set, every Write fails
}

// Open appends to path, creating it (and its directory) owner-only. It reads
// the last entry to continue the chain from it (or, for an empty file, from
// the newest rotated file next to it). If that entry is damaged, Open fails:
// appending to a broken chain would hide the break.
func Open(path string) (*Logger, error) {
	dir, name := filepath.Dir(path), filepath.Base(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// Every later open, rename and stat joins dir with a plain file name:
	// the fixed log name, or a rotated name that parseRotated (or rotatedName)
	// produced, which cannot contain a path separator, so no path leaves dir.
	// openInDir refuses symlinks. The directory itself is created 0700 and
	// owner-checked by internal/paths before roverd opens the log.
	// (The os package's Root type is avoided on purpose: GO-2026-6604, see
	// openInDir.)
	l, err := openIn(dir, name)
	if err != nil {
		return nil, fmt.Errorf("audit log %s: %w", path, err)
	}
	return l, nil
}

func openIn(dir, name string) (*Logger, error) {
	f, err := openInDir(dir, name, os.O_CREATE|os.O_RDWR|os.O_APPEND)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err == nil {
		err = checkFile(fi)
	}
	var last string
	if err == nil {
		last, err = lastHashOf(f, fi.Size())
	}
	if err == nil && fi.Size() == 0 {
		last, err = lastRotatedHash(dir, name)
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Logger{
		MaxBytes: DefaultMaxBytes,
		Now:      time.Now,
		w:        f,
		f:        f,
		dir:      dir,
		name:     name,
		size:     fi.Size(),
		last:     last,
	}, nil
}

// checkFile refuses anything but a private regular file.
func checkFile(fi fs.FileInfo) error {
	if !fi.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("mode is %04o; it must be 0600", perm)
	}
	return nil
}

// openInDir opens the file called name in dir with flag (mode 0600 if it is
// created). name must be a plain file name: the fixed log name, or a rotated
// name that parseRotated accepted. A symlink is refused, not followed, so it
// cannot point the log (or rotation) at a file outside dir.
//
// LESSON: this used to use the os package's Root type, which confines opens
// to one directory in the kernel. Its Mkdir and MkdirAll can follow junctions
// out of the root on Windows (GO-2026-6604, fixed only in newer Go), and
// govulncheck's source mode does not filter by target OS, so CI failed on
// every OS. We use plain paths plus these checks instead. Lstat then
// open is not atomic, but the directory is private (0700, owner-checked), so
// only its owner could swap a file in between. O_NOFOLLOW would close that
// gap but does not exist on every GOOS.
func openInDir(dir, name string, flag int) (*os.File, error) {
	if name == "" || name == "." || name == ".." || name != filepath.Base(name) {
		return nil, fmt.Errorf("invalid audit log file name %q", name)
	}
	p := filepath.Join(dir, name)
	fi, err := os.Lstat(p)
	switch {
	case err == nil:
		if fi.Mode()&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("%s is a symlink; refusing to use it (audit logs must be regular files)", p)
		}
	case errors.Is(err, fs.ErrNotExist) && flag&os.O_CREATE != 0:
		// Not there yet: OpenFile creates it. (With O_EXCL, as rotate uses,
		// OpenFile also refuses a symlink that appears in between.)
	default:
		return nil, err
	}
	return os.OpenFile(p, flag, 0o600) //nolint:gosec // G304: name is checked above to be a plain file name, so p stays inside the private audit dir
}

// lastRotatedHash continues the chain from the newest rotated file, for when
// the current file is empty (e.g. roverd restarted right after a rotation).
func lastRotatedHash(dir, name string) (string, error) {
	names, err := rotatedFiles(dir, name)
	if err != nil || len(names) == 0 {
		return "", err
	}
	newest := names[len(names)-1]
	f, err := openInDir(dir, newest, os.O_RDONLY)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }() // read-only
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	if fi.Size() == 0 {
		return "", fmt.Errorf("rotated log %s is empty", newest)
	}
	h, err := lastHashOf(f, fi.Size())
	if err != nil {
		return "", fmt.Errorf("%s: %w", newest, err)
	}
	return h, nil
}

// New logs to any writer (used by tests). The chain is computed as usual;
// there is no rotation.
func New(w io.Writer) *Logger {
	return &Logger{Now: time.Now, w: w}
}

// LastHash is the hash of the last entry written (the next entry's Prev).
func (l *Logger) LastHash() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.last
}

// Write appends e to the chain. It sets e.Prev and e.Hash (and e.Time, if it
// is zero). Safe to call from both proxy directions at once.
func (l *Logger) Write(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return l.err
	}
	if e.Time.IsZero() {
		e.Time = l.Now().UTC()
	}
	e.Prev = l.last
	line, h, err := encodeLine(e)
	if err != nil {
		return err // nothing was written; the chain is intact
	}
	// One Write call per line: with O_APPEND that is one write(2), so
	// concurrent writers (there should be none) cannot interleave inside it.
	n, err := l.w.Write(line)
	l.size += int64(n)
	if err == nil && n != len(line) {
		err = io.ErrShortWrite
	}
	if err != nil {
		l.err = fmt.Errorf("audit: write failed; refusing further writes: %w", err)
		return l.err
	}
	l.last = h
	if l.f != nil && l.MaxBytes > 0 && l.size > l.MaxBytes {
		if err := l.rotate(); err != nil {
			l.err = fmt.Errorf("audit: rotation failed; refusing further writes: %w", err)
			return l.err
		}
	}
	return nil
}

// rotate renames the current file to <stem>-<UTC time>.jsonl and starts a new
// one. l.last is kept, so the new file's first entry links to the old file.
// Called with l.mu held.
func (l *Logger) rotate() error {
	// Make the old file durable before it is renamed and closed.
	if err := l.f.Sync(); err != nil {
		return err
	}
	if err := l.f.Close(); err != nil {
		return err
	}
	l.f, l.w = nil, failedWriter{}

	ts := l.Now().UTC().Format(rotateLayout)
	stem := strings.TrimSuffix(l.name, ".jsonl")
	renamed := false
	// Never overwrite an older rotated file: two rotations in the same second
	// get -1, -2, ... (VerifyFiles sorts these after the plain name).
	for n := 0; n < 1000 && !renamed; n++ {
		target := rotatedName(stem, ts, n)
		_, err := os.Lstat(filepath.Join(l.dir, target))
		if err == nil {
			continue
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		// roverd is the only writer (it holds the pid-file lock), so nothing
		// can create target between the Lstat and the Rename.
		if err := os.Rename(filepath.Join(l.dir, l.name), filepath.Join(l.dir, target)); err != nil {
			return err
		}
		renamed = true
	}
	if !renamed {
		return errors.New("too many rotated files with the same timestamp")
	}

	// O_EXCL: we just renamed the old file away; if something is there now,
	// it is not ours.
	f, err := openInDir(l.dir, l.name, os.O_CREATE|os.O_EXCL|os.O_RDWR|os.O_APPEND)
	if err != nil {
		return err
	}
	l.f, l.w, l.size = f, f, 0
	return nil
}

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, errors.New("audit log is closed") }

// Close closes the underlying file, if Open created one. Further writes fail.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	var err error
	if l.f != nil {
		err = l.f.Close()
		l.f = nil
	}
	if l.err == nil && l.name != "" { // a logger from New stays usable, as before
		l.err = errors.New("audit log is closed")
	}
	return err
}
