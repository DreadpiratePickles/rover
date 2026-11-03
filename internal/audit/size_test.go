package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func noRedact(e Entry) Entry { return e }

// newT and openT are New and Open with a redactor installed: Write
// refuses to run without one.
func newT(w io.Writer) *Logger {
	l := New(w)
	l.SetRedactor(noRedact)
	return l
}

func openT(path string) (*Logger, error) {
	l, err := Open(path)
	if l != nil {
		l.SetRedactor(noRedact)
	}
	return l, err
}

func TestWriteWithoutRedactorFailsClosed(t *testing.T) {
	var buf bytes.Buffer
	if err := New(&buf).Write(sample(1)); !errors.Is(err, ErrNoRedactor) || buf.Len() != 0 {
		t.Fatalf("err %v, wrote %d bytes", err, buf.Len())
	}
}

// Review H2: an entry whose body grew past MaxLine (redaction makes a body
// longer) must still be written, with the body cut, marked and hashed; a
// size problem must never turn roverd unhealthy.
func TestOversizedBodyIsTruncatedNotRefused(t *testing.T) {
	// Arrange
	var buf bytes.Buffer
	l := newT(&buf)
	body := json.RawMessage(`{"x":"` + strings.Repeat("pwd=[REDACTED:generic-credential] ", MaxLine/33) + `"}`)
	e := sample(1)
	e.Body, e.Reason = body, strings.Repeat("r", 4<<20)

	// Act
	err := l.Write(e)

	// Assert
	if err != nil {
		t.Fatal(err)
	}
	if buf.Len() > MaxLine {
		t.Fatalf("line of %d bytes > %d", buf.Len(), MaxLine)
	}
	var got Entry
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	if !got.BodyTruncated || got.BodySHA256 != hex.EncodeToString(sum[:]) || len(got.Reason) > maxReason+64 {
		t.Fatalf("truncated %v sha %s reason %d", got.BodyTruncated, got.BodySHA256, len(got.Reason))
	}
	if res := Verify(bytes.NewReader(buf.Bytes())); res.Err != nil {
		t.Fatal(res.Err)
	}
}
