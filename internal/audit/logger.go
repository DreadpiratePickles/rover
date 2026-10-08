// Package audit writes one JSON object per line (JSONL) for every message the
// gateway sees.
//
// LESSON (A1):
//   - Audit logs are themselves sensitive: tool arguments contain file paths,
//     queries and sometimes secrets. The file is created 0600 (owner-only).
//     Module A5 adds redaction before anything is written.
//   - Logs are written BEFORE the message is forwarded ("log-then-forward").
//     If the gateway crashes mid-call, the record of what was attempted exists.
//   - If the log cannot be written, the caller stops the session: a security
//     control that silently keeps going without its audit trail "fails open".
//   - Module A9 turns this into a hash-chained, tamper-evident log.
package audit

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

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
}

type Logger struct {
	mu  sync.Mutex
	w   io.Writer
	c   io.Closer
	enc *json.Encoder
}

// Open appends to path, creating it (and its directory) owner-only.
func Open(path string) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	l := New(f)
	l.c = f
	return l, nil
}

// New logs to any writer (used by tests).
func New(w io.Writer) *Logger {
	return &Logger{w: w, enc: json.NewEncoder(w)}
}

// Write is safe to call from both proxy directions at once.
func (l *Logger) Write(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.enc.Encode(e)
}

func (l *Logger) Close() error {
	if l.c != nil {
		return l.c.Close()
	}
	return nil
}
