package daemon

import (
	"bytes"
	"encoding/json"
	"testing"
)

// unescape must agree with encoding/json on every string it decodes.
func FuzzUnescape(f *testing.F) {
	for _, s := range []string{`"a\nb"`, `"é😀"`, `"\ud800x"`, `"\"\\\/\b\f\r\t"`, `"plain"`, `"\ud83dA"`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		var want string
		if json.Unmarshal(raw, &want) != nil {
			return
		}
		got, ok := textValue(bytes.TrimSpace(raw))
		if !ok {
			t.Fatalf("%q: not decoded", raw)
		}
		// encoding/json also replaces invalid UTF-8; compare only valid input.
		if json.Valid(raw) && string(got) != want && validUTF8(raw) {
			t.Fatalf("%q: got %q want %q", raw, got, want)
		}
	})
}

func validUTF8(b []byte) bool { return json.Valid(b) && string([]rune(string(b))) == string(b) }
