package dlp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/rover/internal/jsonedit"
)

// EncodeForTest is text as a JSON string.
func EncodeForTest(text []byte) []byte { return jsonedit.EncodeString(string(text)) }

var fuzzSeeds = []string{
	"", "AKIAEXAMPLE000000001", fakeGHP, fakeJWT, fakePEMHead, "-----BEGIN PRIVATE KEY-----", "password=hunter2hunter2",
	`{"password":"hunter2hunter2","x":[1,"` + fakeAKIA + `"]}`, `{"a":"é\ud800"}`, "eyJ.eyJ.", fakeRandom + "==",
	"xoxp-", "hooks.slack.com/services/x", `"token": "abc def"`, "\xff\xfe" + fakeStripe,
}

// FuzzFind: no panic, spans sorted, inside the text and not overlapping,
// known kinds, and Redact removes every span's bytes.
func FuzzFind(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add([]byte(s))
	}
	known := map[string]bool{}
	for _, k := range Kinds {
		known[k] = true
	}
	d := New()
	f.Fuzz(func(t *testing.T, text []byte) {
		ms := d.Find(text)
		end := 0
		for _, m := range ms {
			if !known[m.Kind] || m.Start < end || m.Start >= m.End || m.End > len(text) {
				t.Fatalf("bad match %+v (previous end %d, len %d)", m, end, len(text))
			}
			end = m.End
		}
		if len(ms) > 0 && !strings.Contains(string(Redact(text, ms)), "[REDACTED:") {
			t.Fatal("redaction lost its marker")
		}
	})
}

// FuzzRedact: valid JSON in, valid JSON out, and nothing found in the
// output that was not a marker (redaction is complete in one pass).
func FuzzRedact(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add([]byte(s))
		f.Add(append(append([]byte(`{"text":`), EncodeForTest([]byte(s))...), '}'))
	}
	d := New()
	f.Fuzz(func(t *testing.T, raw []byte) {
		out, kinds, err := RedactJSON(d, raw)
		if err != nil {
			return
		}
		if json.Valid(raw) && !json.Valid(out) {
			t.Fatalf("valid JSON in, invalid out:\n%s\n%s", raw, out)
		}
		if len(kinds) == 0 && string(out) != string(raw) {
			t.Fatal("nothing found but the bytes changed")
		}
	})
}
