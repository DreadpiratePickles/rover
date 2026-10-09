// Package audit is Rover's tamper-evident record of every message that
// crossed the gateway.
//
// LESSON (A1, M1):
//   - Audit logs are themselves sensitive: tool arguments contain file paths,
//     queries and sometimes secrets. The file is created 0600 (owner-only)
//     and bodies are not logged unless the daemon is told to (M10 adds
//     redaction, after which bodies can be on by default).
//   - Logs are written BEFORE the message is forwarded ("log-then-forward").
//     If the gateway crashes mid-call, the record of what was attempted exists.
//   - If the log cannot be written, the daemon blocks the message: a security
//     control that keeps going without its audit trail "fails open".
//   - Each entry carries the hash of the previous one (a hash chain). Change,
//     drop or reorder any line and Verify reports the first line that no
//     longer fits. This does not stop an attacker who can rewrite the whole
//     file; it makes silent, surgical edits detectable (plan §4.6).
//
// Canonical form: an entry's hash is SHA-256 over the JSON encoding of the
// entry with its "hash" field empty, exactly as encoding/json produces it
// (struct field order, compact RawMessage, RFC 3339 UTC time). Verify
// re-encodes each parsed line and requires the bytes to match the file, so
// even a whitespace edit fails. The first entry of a file links to the last
// hash of the previous file after rotation; "" means "first file ever".
package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry is one line of the audit log: one message seen in one direction.
type Entry struct {
	Time      time.Time       `json:"ts"`
	Session   string          `json:"session"`
	Server    string          `json:"server,omitempty"` // MCP server name, as given to `rover wrap --name`
	Dir       string          `json:"dir"`              // "c2s" (client->server) or "s2c"
	Kind      string          `json:"kind"`             // request | notification | result | error | invalid
	Method    string          `json:"method,omitempty"`
	ID        json.RawMessage `json:"id,omitempty"`
	Tool      string          `json:"tool,omitempty"`
	ReplyTo   string          `json:"reply_to,omitempty"` // for results/errors: the method they answer
	LatencyMS *float64        `json:"latency_ms,omitempty"`
	ToolError bool            `json:"tool_error,omitempty"` // result had isError=true
	Action    string          `json:"action,omitempty"`     // forward | block | replace | hold (empty before M1)
	Reason    string          `json:"reason,omitempty"`
	Bytes     int             `json:"bytes"`
	Body      json.RawMessage `json:"body,omitempty"`
	Prev      string          `json:"prev"` // hash of the previous entry, "" for the very first
	Hash      string          `json:"hash,omitempty"`
}

// DefaultRotateBytes is the size at which the daemon starts a new log file.
const DefaultRotateBytes = 50 << 20

// Logger appends hash-chained entries. It is safe for concurrent use.
type Logger struct {
	mu   sync.Mutex
	w    io.Writer
	f    *os.File // nil when writing to an arbitrary writer
	path string
	last string // hash of the last entry written
	size int64
	// RotateBytes is the file size that triggers rotation; 0 disables it.
	RotateBytes int64
}

// Open appends to path, creating it (and its directory) owner-only, and
// resumes the hash chain from the last valid entry already in the file.
func Open(path string) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	last, err := lastHash(path)
	if err != nil {
		return nil, fmt.Errorf("resume chain: %w", err)
	}
	f, err := openAppend(path)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Logger{w: f, f: f, path: path, last: last, size: fi.Size(), RotateBytes: DefaultRotateBytes}, nil
}

func openAppend(path string) (*os.File, error) {
	// G304: path is Rover's own audit-log location under the state directory
	// (or --log), opened write-only with owner-only permissions.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // G304: Rover-owned audit-log path, see above
	if err != nil {
		return nil, err
	}
	return f, nil
}

// New logs to any writer (used by tests). Rotation is off.
func New(w io.Writer) *Logger {
	return &Logger{w: w}
}

// LastHash returns the hash of the most recent entry, "" if none.
func (l *Logger) LastHash() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.last
}

// Write links e to the chain and appends it as one line. Prev and Hash are
// set here; any values the caller put in them are overwritten.
func (l *Logger) Write(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.Prev = l.last
	line, hash, err := encode(e)
	if err != nil {
		return err
	}
	if l.f != nil && l.RotateBytes > 0 && l.size > 0 && l.size+int64(len(line)) > l.RotateBytes {
		if err := l.rotate(); err != nil {
			return fmt.Errorf("rotate audit log: %w", err)
		}
	}
	if _, err := l.w.Write(line); err != nil {
		return err
	}
	l.last = hash
	l.size += int64(len(line))
	return nil
}

// rotate renames the current file aside and starts a fresh one. The chain
// continues: the next entry's Prev is the last hash of the old file.
func (l *Logger) rotate() error {
	if err := l.f.Close(); err != nil {
		return err
	}
	aside := fmt.Sprintf("%s.%s", l.path, time.Now().UTC().Format("20060102T150405.000000000Z"))
	if err := os.Rename(l.path, aside); err != nil {
		return err
	}
	f, err := openAppend(l.path)
	if err != nil {
		return err
	}
	l.f, l.w, l.size = f, f, 0
	return nil
}

// Close closes the underlying file, if Open created one.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		return l.f.Close()
	}
	return nil
}

// encode returns the canonical line (with hash) and the hash itself.
func encode(e Entry) ([]byte, string, error) {
	e.Hash = ""
	unhashed, err := json.Marshal(e)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(unhashed)
	e.Hash = hex.EncodeToString(sum[:])
	line, err := json.Marshal(e)
	if err != nil {
		return nil, "", err
	}
	return append(line, '\n'), e.Hash, nil
}

// lastHash returns the hash of the final line of an existing log, "" if the
// file is missing or empty. A corrupt tail is an error: appending to a broken
// chain would hide the break behind new valid entries.
func lastHash(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: Rover-owned audit-log path
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	res := Verify(f)
	if res.Err != nil {
		return "", fmt.Errorf("line %d: %w", res.Line, res.Err)
	}
	return res.LastHash, nil
}

// Result is what Verify found.
type Result struct {
	Entries   int    // lines checked
	LastHash  string // hash of the final entry, "" if the log is empty
	FirstPrev string // Prev of the first entry; non-empty means it continues an earlier file
	Line      int    // 1-based line of the first problem, 0 if none
	Err       error  // nil when the chain is intact
}

// ErrChainBroken is wrapped by every verification failure.
var ErrChainBroken = errors.New("audit chain broken")

// MaxLine bounds a single audit line while verifying (bodies are capped by
// the proxy's 16 MiB message limit, plus metadata).
const MaxLine = 17 << 20

// Verify walks a log and reports the first line whose bytes, hash or link to
// the previous entry do not match.
func Verify(r io.Reader) Result {
	var res Result
	br := bufioReader(r)
	prev := ""
	for n := 1; ; n++ {
		line, err := readLine(br)
		if len(bytes.TrimSpace(line)) > 0 {
			var e Entry
			if uerr := json.Unmarshal(line, &e); uerr != nil {
				return fail(res, n, fmt.Errorf("%w: not valid JSON: %v", ErrChainBroken, uerr))
			}
			if n == 1 {
				res.FirstPrev = e.Prev
				prev = e.Prev
			}
			if e.Prev != prev {
				return fail(res, n, fmt.Errorf("%w: prev %q does not match previous hash %q", ErrChainBroken, e.Prev, prev))
			}
			claimed := e.Hash
			canon, hash, eerr := encode(e)
			if eerr != nil {
				return fail(res, n, fmt.Errorf("%w: %v", ErrChainBroken, eerr))
			}
			if hash != claimed {
				return fail(res, n, fmt.Errorf("%w: hash %q does not match contents (%q)", ErrChainBroken, claimed, hash))
			}
			if !bytes.Equal(bytes.TrimRight(canon, "\n"), bytes.TrimRight(line, "\r\n")) {
				return fail(res, n, fmt.Errorf("%w: line is not in canonical form (edited after writing)", ErrChainBroken))
			}
			prev = hash
			res.Entries++
			res.LastHash = hash
		}
		if errors.Is(err, io.EOF) {
			return res
		}
		if err != nil {
			return fail(res, n, fmt.Errorf("%w: %v", ErrChainBroken, err))
		}
	}
}

func fail(res Result, line int, err error) Result {
	res.Line, res.Err = line, err
	return res
}
