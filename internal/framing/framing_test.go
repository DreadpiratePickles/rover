package framing

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestReadLineFramesFinalLineWithoutNewline(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("a\nb"))
	line, err := ReadLine(r, 10)
	if err != nil || string(line) != "a\n" {
		t.Fatalf("first: %q %v", line, err)
	}
	line, err = ReadLine(r, 10)
	if !errors.Is(err, io.EOF) || string(line) != "b\n" {
		t.Fatalf("last: %q %v", line, err)
	}
}

func TestReadLineEnforcesLimitAcrossBufferRefills(t *testing.T) {
	// A 2 KiB buffer and a 5 KiB line: the limit must count across refills.
	r := bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", 5000)+"\n"), 2048)
	if _, err := ReadLine(r, 4096); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
}

func TestReadLineAllowsLinesLargerThanBuffer(t *testing.T) {
	want := strings.Repeat("y", 100_000) + "\n"
	r := bufio.NewReaderSize(strings.NewReader(want), 4096)
	line, err := ReadLine(r, 1<<20)
	if err != nil || string(line) != want {
		t.Fatalf("got %d bytes, err %v", len(line), err)
	}
}
