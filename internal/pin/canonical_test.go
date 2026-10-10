package pin

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const echoTool = `{"name":"echo","description":"Returns the text you send it.","inputSchema":{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}}`

func TestCanonicalIsKeyOrderAndWhitespaceIndependent(t *testing.T) {
	// Arrange: the same tool, keys reordered at every level, re-indented.
	reordered := `{
	  "inputSchema": { "required": [ "text" ], "properties": { "text": {"type" : "string"} }, "type": "object" },
	  "description" : "Returns the text you send it.",
	  "name": "echo"
	}`

	// Act
	a, errA := DigestOf(json.RawMessage(echoTool))
	b, errB := DigestOf(json.RawMessage(reordered))
	c, _ := Canonical(json.RawMessage(reordered))

	// Assert
	if errA != nil || errB != nil || a != b {
		t.Fatalf("digests differ: %s (%v) vs %s (%v)", a, errA, b, errB)
	}
	want := `{"description":"Returns the text you send it.","inputSchema":{"properties":{"text":{"type":"string"}},"required":["text"],"type":"object"},"name":"echo"}`
	if string(c) != want {
		t.Fatalf("canonical\n got %s\nwant %s", c, want)
	}
}

func TestCanonicalDetectsOneCharacterChange(t *testing.T) {
	changed := strings.Replace(echoTool, "send it.", "send it!", 1)
	a, _ := DigestOf(json.RawMessage(echoTool))
	b, err := DigestOf(json.RawMessage(changed))
	if err != nil || a == b {
		t.Fatalf("a changed description must change the digest: %s %s %v", a, b, err)
	}
}

func TestCanonicalKeepsEverythingButMeta(t *testing.T) {
	// _meta is ignored; absent members stay absent (not null).
	c, err := Canonical(json.RawMessage(`{"_meta":{"x":1},"title":"T","name":"n","annotations":{"readOnlyHint":true}}`))
	if err != nil || string(c) != `{"annotations":{"readOnlyHint":true},"name":"n","title":"T"}` {
		t.Fatalf("got %s %v", c, err)
	}
}

func TestCanonicalEncodingDetails(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`{"name":"a<b>&c"}`, `{"name":"a<b>&c"}`},                                             // no HTML escaping
		{`{"name":"\u0041\/"}`, `{"name":"A/"}`},                                               // escapes normalised
		{`{"name":"x","inputSchema":{"max":1.50}}`, `{"inputSchema":{"max":1.50},"name":"x"}`}, // number text kept
		{`{"name":"x","inputSchema":{"e":[1e2, true, null]}}`, `{"inputSchema":{"e":[1e2,true,null]},"name":"x"}`},
		{`{"name":"😀","description":"\ud83d\ude00"}`, `{"description":"😀","name":"😀"}`}, // a valid surrogate pair is fine
	} {
		got, err := Canonical(json.RawMessage(tc.in))
		if err != nil || string(got) != tc.want {
			t.Errorf("%s: got %s %v, want %s", tc.in, got, err, tc.want)
		}
	}
}

func TestCanonicalRefusesAmbiguousTools(t *testing.T) {
	deep := `{"name":"x","inputSchema":` + strings.Repeat(`{"a":`, 70) + `1` + strings.Repeat(`}`, 70) + `}`
	for _, in := range []string{
		`{"name":"x","description":"a","description":"b"}`,             // duplicate key
		`{"name":"x","Description":"b","description":"a"}`,             // case collision
		`{"name":"x","inputSchema":{"type":"object","TYPE":"string"}}`, // deep collision
		`{"name":"x","inputSchema":{"enum":[{"a":1,"a":2}]}}`,          // inside an array
		`{"name":"x","description":"\ud800"}`,                          // lone surrogate
		"{\"name\":\"x\",\"description\":\"\xff\"}",                    // invalid UTF-8
		`{"name":"x","description":"�"}`,                               // literal replacement char
		`{"name":"x","description":"\ufffd"}`,                          // escaped replacement char
		deep,
		`["not an object"]`,
	} {
		_, err := Canonical(json.RawMessage(in))
		if !errors.Is(err, ErrUncanonicalisable) {
			t.Errorf("%.60s: want ErrUncanonicalisable, got %v", in, err)
		}
	}
}
