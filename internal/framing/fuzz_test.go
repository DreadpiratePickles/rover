package framing

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"testing"
)

func FuzzReadLine(f *testing.F) {
	f.Add([]byte("a\nb\n"), 10)
	f.Add([]byte(""), 1)
	f.Add(bytes.Repeat([]byte("x"), 5000), 4096)
	f.Fuzz(func(t *testing.T, data []byte, limit int) {
		if limit < 1 || limit > 1<<20 {
			return
		}
		r := bufio.NewReaderSize(bytes.NewReader(data), 16)
		var total int
		for {
			line, err := ReadLine(r, limit)
			if len(line) > limit+1 {
				t.Fatalf("line of %d bytes exceeds limit %d", len(line), limit)
			}
			total += len(line)
			if errors.Is(err, ErrTooLarge) || errors.Is(err, io.EOF) {
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if total > len(data)+1 {
				t.Fatal("returned more bytes than the input holds")
			}
		}
	})
}
