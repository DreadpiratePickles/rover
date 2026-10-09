package pin

import (
	"encoding/json"
	"testing"
)

// FuzzCanonical: Canonical never panics; when it succeeds its output is
// valid JSON, is a fixed point (canonicalising it again gives the same
// bytes), and keeps no member but the four pinned ones.
func FuzzCanonical(f *testing.F) {
	for _, s := range []string{
		echoTool,
		`{"name":"x","inputSchema":{"a":[1,2,{"b":null}],"c":-0.5e10}}`,
		`{"name":"x","description":"a","Description":"b"}`,
		`{"name":"\u003c","annotations":{"title":"\ud83d\ude00"}}`,
		`{}`, `[]`, `"s"`, `{"name":1}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		c, err := Canonical(in)
		if err != nil {
			return
		}
		if !json.Valid(c) {
			t.Fatalf("invalid canonical JSON %q from %q", c, in)
		}
		again, err := Canonical(c)
		if err != nil || string(again) != string(c) {
			t.Fatalf("not a fixed point: %q -> %q (%v)", c, again, err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(c, &m); err != nil {
			t.Fatal(err)
		}
		for k := range m {
			if !pinnedMembers[k] {
				t.Fatalf("kept member %q", k)
			}
		}
	})
}
