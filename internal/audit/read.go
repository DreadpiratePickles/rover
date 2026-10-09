package audit

import (
	"bufio"
	"io"

	"github.com/DreadpiratePickles/rover/internal/framing"
)

func bufioReader(r io.Reader) *bufio.Reader {
	if br, ok := r.(*bufio.Reader); ok {
		return br
	}
	return bufio.NewReaderSize(r, 64<<10)
}

func readLine(br *bufio.Reader) ([]byte, error) {
	return framing.ReadLine(br, MaxLine)
}
