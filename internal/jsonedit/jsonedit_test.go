package jsonedit

import (
	"strings"
	"testing"
)

func TestStringsReportsKeysAndOffsets(t *testing.T) {
	raw := []byte(` {"a":"x","b":[1,"y",{"c":"zé"}],"d":{"e":"w"}} `)
	var got []string
	err := Strings(raw, func(key string, start, end int, s string) error {
		got = append(got, key+"="+s+"@"+string(raw[start:end]))
		return nil
	})
	want := `a=x@"x" b=y@"y" c=zé@"zé" e=w@"w"`
	if err != nil || strings.Join(got, " ") != want {
		t.Fatalf("%v\n got %s\nwant %s", err, strings.Join(got, " "), want)
	}
}

func TestApplyKeepsOtherBytesAndRefusesOverlap(t *testing.T) {
	raw := []byte(`{"a": "x" , "b":"y"}`)
	out, err := Apply(raw, []Edit{{Start: 16, End: 19, With: []byte(`"Y"`)}, {Start: 6, End: 9, With: EncodeString("<x>")}})
	if err != nil || string(out) != `{"a": "<x>" , "b":"Y"}` {
		t.Fatalf("%s %v", out, err)
	}
	if _, err := Apply(raw, []Edit{{Start: 1, End: 5}, {Start: 3, End: 6}}); err == nil {
		t.Fatal("overlap must be refused")
	}
}

func TestStringsRefusesDepthAndDuplicates(t *testing.T) {
	deep := strings.Repeat("[", MaxDepth+2) + strings.Repeat("]", MaxDepth+2)
	if err := Strings([]byte(deep), func(string, int, int, string) error { return nil }); err != ErrTooDeep {
		t.Fatalf("deep: %v", err)
	}
	if err := WalkStrings([]byte(`{"a":"1","A":"2"}`), nil, func(string) {}); err == nil {
		t.Fatal("case-colliding keys must be refused")
	}
}
