package audit

import (
	"encoding/json"
	"errors"
	"io"
	"os"
)

// Scan calls fn for every entry of the log at path, oldest first, across
// the rotated files (ChainFiles). It does not verify the chain (`rover log
// --verify` does); lines that do not parse are skipped. roverd uses it at
// start (M9) to find what its own history says about approved policies.
func Scan(path string, fn func(Entry)) error {
	files, err := ChainFiles(path)
	if err != nil {
		return err
	}
	for _, name := range files {
		if err := scanFile(name, fn); err != nil {
			return err
		}
	}
	return nil
}

func scanFile(name string, fn func(Entry)) error {
	f, err := os.Open(name) //nolint:gosec // G304: Rover's own audit-log files
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	br := bufioReader(f)
	for {
		line, err := readLine(br)
		var e Entry
		if len(line) > 0 && json.Unmarshal(line, &e) == nil {
			fn(e)
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
