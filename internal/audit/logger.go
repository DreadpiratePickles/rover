// Package audit is Rover's tamper-evident record of every message that
// crossed the gateway.
//
// LESSON (A1, M1):
//   - Audit logs are themselves sensitive: tool arguments contain file paths,
//     queries and sometimes secrets. The file is created 0600 (owner-only),
//     and from M10 every entry passes through the Redactor roverd installs
//     (secrets become "[REDACTED:<kind>]") before it is hashed and written,
//     which is why bodies are now logged by default (`--no-bodies` to stop).
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
// with HTML escaping off (struct field order, compact RawMessage, RFC 3339
// UTC time). HTML escaping is off because it would turn every '<' in a body
// into six bytes, letting a hostile server inflate one 16 MiB message into a
// line no verifier would read. Verify re-encodes each parsed line and
// requires the bytes to match the file, so even a whitespace edit fails.
//
// What a hash chain cannot see: an attacker who removes lines from the END
// of the file, or deletes whole files, leaves a chain that still verifies.
// The daemon therefore also writes the newest hash to a small anchor file
// after every entry, and VerifyChain checks that the anchored hash appears
// in the chain. The first entry of the first file has prev ""; after
// rotation the next file's first entry links to the old file's last hash.
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
	"strings"
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
	Action    string          `json:"action,omitempty"`     // forward | block | replace | hold | would_deny (empty before M1)
	Reason    string          `json:"reason,omitempty"`
	RuleIDs   []string        `json:"rule_ids,omitempty"` // deciding policy ids (M2)
	Findings  []string        `json:"findings,omitempty"` // conversion/normalisation findings (M2)
	// Digest and PrevDigest are tool-pin digests (M4): the digest pinned,
	// seen or approved, and the one it replaces or differs from.
	Digest     string          `json:"digest,omitempty"`
	PrevDigest string          `json:"prev_digest,omitempty"`
	Bytes      int             `json:"bytes"`
	Body       json.RawMessage `json:"body,omitempty"`
	// BodyTruncated says Body is a JSON string holding only the start of
	// the body, cut to fit MaxLine (M10); BodySHA256 is the whole body's.
	BodyTruncated bool   `json:"body_truncated,omitempty"`
	BodySHA256    string `json:"body_sha256,omitempty"`
	Prev          string `json:"prev"` // hash of the previous entry, "" for the very first
	Hash          string `json:"hash,omitempty"`
}

// DefaultRotateBytes is the size at which the daemon starts a new log file.
const DefaultRotateBytes = 50 << 20

// Logger appends hash-chained entries. It is safe for concurrent use.
type Logger struct {
	mu   sync.Mutex
	w    io.Writer
	f    *os.File // nil when writing to an arbitrary writer
	path string
	last string    // hash of the last entry written
	at   time.Time // time of the last entry written
	size int64
	// RotateBytes is the file size that triggers rotation; 0 disables it.
	RotateBytes int64
	// AnchorPath, when set, receives the newest hash after every write
	// (written to a temp file and renamed, so it is never half-written).
	AnchorPath string
	// redact rewrites each entry before it is hashed (SetRedactor).
	redact func(Entry) Entry
}

// SetRedactor installs f, which rewrites every entry before it is hashed
// and written (M10: roverd removes secrets this way). Because Write calls
// it, no writer of the log (decisions, approvals, pins, tamper alerts) can
// forget to redact. nil removes it.
func (l *Logger) SetRedactor(f func(Entry) Entry) {
	l.mu.Lock()
	l.redact = f
	l.mu.Unlock()
}

// Open appends to path, creating it (and its directory) owner-only, and
// resumes the hash chain from the last valid entry already in the file.
func Open(path string) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	last, at, err := lastEntry(path)
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
	return &Logger{w: f, f: f, path: path, last: last, at: at, size: fi.Size(), RotateBytes: DefaultRotateBytes}, nil
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

// LastTime returns the time of the most recent entry, zero if none. roverd
// compares approval records with it (M9): an approval newer than the log
// was not written by roverd.
func (l *Logger) LastTime() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.at
}

// Write links e to the chain and appends it as one line. Prev and Hash are
// set here; any values the caller put in them are overwritten.
func (l *Logger) Write(e Entry) error {
	l.mu.Lock()
	redact := l.redact
	l.mu.Unlock()
	if redact == nil {
		return ErrNoRedactor // fail closed: never write an unredacted entry
	}
	e = fit(redact(e)) // outside the lock: a large body takes a while to scan
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
	if len(line) > MaxLine {
		return fmt.Errorf("audit entry of %d bytes exceeds %d", len(line), MaxLine)
	}
	if _, err := l.w.Write(line); err != nil {
		return err
	}
	l.last, l.at = hash, e.Time
	l.size += int64(len(line))
	if l.AnchorPath != "" {
		if err := writeAnchor(l.AnchorPath, hash); err != nil {
			return fmt.Errorf("write anchor: %w", err)
		}
	}
	return nil
}

func writeAnchor(path, hash string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(hash+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ReadAnchor returns the anchored hash, or "" when no anchor exists yet.
func ReadAnchor(path string) (string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: Rover-owned anchor path under the state directory
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(b)), nil
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
	unhashed, err := marshal(e)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(unhashed)
	e.Hash = hex.EncodeToString(sum[:])
	line, err := marshal(e)
	if err != nil {
		return nil, "", err
	}
	return append(line, '\n'), e.Hash, nil
}

// marshal is encoding/json without HTML escaping and without the trailing
// newline the Encoder adds.
func marshal(e Entry) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(e); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// lastEntry returns the hash and time of the final line of an existing
// log, "" if the file is missing or empty. A corrupt tail is an error:
// appending to a broken chain would hide the break behind new valid entries.
func lastEntry(path string) (string, time.Time, error) {
	f, err := os.Open(path) //nolint:gosec // G304: Rover-owned audit-log path
	if errors.Is(err, os.ErrNotExist) {
		return "", time.Time{}, nil
	}
	if err != nil {
		return "", time.Time{}, err
	}
	defer func() { _ = f.Close() }()
	res := Verify(f)
	if res.Err != nil {
		return "", time.Time{}, fmt.Errorf("line %d: %w", res.Line, res.Err)
	}
	return res.LastHash, res.LastTime, nil
}

// ErrNoRedactor refuses a Write before SetRedactor: an audit log that
// might hold secrets is worse than none (M10).
var ErrNoRedactor = errors.New("audit: no redactor installed")

const (
	// maxReason caps an entry's reason.
	maxReason = 64 << 10
	// fitHeadroom is kept free under MaxLine for the hash, prev and the
	// truncation fields.
	fitHeadroom = 4 << 10
)

// fit makes e encodable within MaxLine, so a size can never fail a write
// (an audit failure blocks everything): the reason is capped, and a body
// too large for the line is replaced by a JSON string holding its start,
// with body_truncated and the whole body's SHA-256.
func fit(e Entry) Entry {
	if len(e.Reason) > maxReason {
		e.Reason = strings.ToValidUTF8(e.Reason[:maxReason], "") + "...(truncated)"
	}
	if len(e.Body) == 0 {
		return e
	}
	line, _, err := encode(e)
	if err == nil && len(line) <= MaxLine-fitHeadroom {
		return e
	}
	sum := sha256.Sum256(e.Body)
	body := e.Body
	e.Body, e.BodyTruncated, e.BodySHA256 = json.RawMessage(`""`), true, hex.EncodeToString(sum[:])
	meta, _, _ := encode(e)
	budget := MaxLine - fitHeadroom - len(meta)
	n := min(len(body), budget)
	for n > 0 {
		s, _ := marshalString(string(body[:n]))
		if len(s) <= budget {
			e.Body = s
			break
		}
		n = n * budget / len(s) * 9 / 10
	}
	return e
}

// marshalString is s as a JSON string without HTML escaping.
func marshalString(s string) (json.RawMessage, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
