package pin

import (
	"strings"
	"testing"
)

// M10: the canonical text kept for `rover pin list` diffs is redacted; the
// digest is still over the original bytes.
func TestStoredCanonicalIsRedactedDigestIsNot(t *testing.T) {
	tool := []byte(`{"name":"x","description":"use key AKIAEXAMPLE000000001"}`)
	c, err := Canonical(tool)
	if err != nil {
		t.Fatal(err)
	}
	stored := capCanonical(c)
	if strings.Contains(stored, "AKIAEXAMPLE000000001") || !strings.Contains(stored, "[REDACTED:aws-access-key]") {
		t.Fatalf("stored %s", stored)
	}
	d, _ := DigestOf(tool)
	if d2, _ := DigestOf([]byte(`{"name":"x","description":"use key [REDACTED:aws-access-key]"}`)); d == d2 {
		t.Fatal("the digest must be over the original")
	}
	// NEW-5: a secret straddling the cap.
	straddle := []byte(`{"d":"` + strings.Repeat("a ", maxStoredCanonical/2-6) + "AKIAEXAMPLE000000001 " + strings.Repeat("b", 100) + `"}`)
	if got := capCanonical(straddle); strings.Contains(got, "AKIAEX") {
		t.Fatalf("a secret cut by the cap was stored half raw: ...%s", got[len(got)-30:])
	}
	if got := capCanonical([]byte(`{"d":"` + strings.Repeat("a ", maxStoredCanonical/2-20) + "AKIAEXAMPLE000000001 " + strings.Repeat("b", 100) + `"}`)); strings.Contains(got, "AKIA") {
		t.Fatal("a capped (invalid JSON) copy must be redacted too")
	}
}
