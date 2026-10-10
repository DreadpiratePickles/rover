package dlp

import (
	"encoding/json"
	"strings"
	"testing"
)

// Fake secrets: right shape, never valid anywhere.
const (
	fakeAKIA    = "AKIAEXAMPLE000000001"
	fakeAWSSec  = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	fakeGHP     = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	fakeSlack   = "xoxb-000000000000-EXAMPLEEXAMPLE"
	fakeHook    = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX" //nolint:gosec // G101: a fake fixture, valid nowhere
	fakeStripe  = "sk_live_EXAMPLE00000000000000000"                                              //nolint:gosec // G101: a fake fixture, valid nowhere
	fakeJWT     = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdC1vbmx5LXNpZ25hdHVyZQ"
	fakeRandom  = "Zx8Q2mN7pL4vR1tK9sW3yB6cF0hJ5gD8aE2uI7oP"
	fakePEMHead = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOQIBAAJBAOdjBW3XJkIGaOr2uXJCaVNC3NgegS4VAl5a7BTX80zQq99B4gxX\n-----END RSA PRIVATE KEY-----" //nolint:gosec // G101: a fake fixture, valid nowhere
)

func TestFindKinds(t *testing.T) {
	cases := []struct{ name, text, kind, secret string }{
		{"aws key", "id " + fakeAKIA + " ok", KindAWSAccessKey, fakeAKIA},
		{"aws secret near context", "aws_secret_access_key = " + fakeAWSSec, KindAWSSecret, fakeAWSSec},
		{"github", "use " + fakeGHP + ".", KindGitHubToken, fakeGHP},
		{"github pat", "github_pat_" + strings.Repeat("A1", 41), KindGitHubToken, "github_pat_" + strings.Repeat("A1", 41)},
		{"slack token", "SLACK=" + fakeSlack, KindSlackToken, fakeSlack},
		{"slack webhook", "post to " + fakeHook + " now", KindSlackWebhook, fakeHook},
		{"stripe", "key " + fakeStripe, KindStripe, fakeStripe},
		{"jwt", "Authorization: Bearer " + fakeJWT, KindJWT, fakeJWT},
		{"pem", "key:\n" + fakePEMHead + "\nend", KindPrivateKey, fakePEMHead},
		{"pem without end", "-----BEGIN PRIVATE KEY-----\nMIIBOQIBAAJBAOdjBW3XJkIGaOr2", KindPrivateKey, "MIIBOQIBAAJBAOdjBW3XJkIGaOr2"},
		{"generic", "password=hunter2hunter2", KindGeneric, "hunter2hunter2"},
		{"generic quoted", `api_key: "abcdefgh1234"`, KindGeneric, "abcdefgh1234"},
		{"high entropy", "value " + fakeRandom + " end", KindHighEntropy, fakeRandom},
	}
	d := New()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ms := d.Find([]byte(c.text))
			if len(ms) == 0 || ms[0].Kind != c.kind {
				t.Fatalf("want %s, got %+v", c.kind, ms)
			}
			red := string(Redact([]byte(c.text), ms))
			if strings.Contains(red, c.secret) || !strings.Contains(red, Marker(c.kind)) {
				t.Fatalf("redacted: %q", red)
			}
		})
	}
}

func TestBenignShapesAreNotFlagged(t *testing.T) {
	for _, text := range []string{
		"sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		"commit 3b46f4b1c9a0d2e8f7a6b5c4d3e2f1a0b9c8d7e6",
		"id 550e8400-e29b-41d4-a716-446655440000",
		"![x](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==)",
		"https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PLx0sYbCqOb8TBPRdmBHs5Iftvv9TPboYG",
		"const token = await getToken(user.id); if (token == \"\") return",
		"tokens_used: 123456789, max_tokens=4096",
		"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor.",
		"password: ${DB_PASSWORD}", "token = <your-token-here>", "secret: ********",
		"/usr/local/lib/python3.12/site-packages/requests/adapters.py",
	} {
		if ms := New().Find([]byte(text)); len(ms) > 0 {
			t.Errorf("%q: unexpected %+v", text, ms)
		}
	}
}

func TestRedactMergesOverlapsAndKeepsOtherBytes(t *testing.T) {
	text := []byte("a SECRETSECRET b")
	got := Redact(text, []Match{{Kind: KindHighEntropy, Start: 2, End: 10}, {Kind: KindGeneric, Start: 6, End: 14}, {Kind: KindJWT, Start: 99, End: 120}})
	if string(got) != "a [REDACTED:generic-credential] b" {
		t.Fatalf("%q", got)
	}
	if string(Redact(text, nil)) != string(text) {
		t.Fatal("no matches must keep the text")
	}
}

func TestRedactJSONSplicesOnlyChangedStrings(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0", "id":1,"result":{"content":[{"type":"text","text":"key ` + fakeAKIA + `é"}],` +
		`"structuredContent":{"password":"hunter2hunter2","n":  5, "x":"café"}}}`)
	out, kinds, err := RedactJSON(New(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(out) || strings.Contains(string(out), fakeAKIA) || strings.Contains(string(out), "hunter2") {
		t.Fatalf("%s", out)
	}
	for _, keep := range []string{`"jsonrpc":"2.0", "id":1`, `"n":  5, "x":"café"`} {
		if !strings.Contains(string(out), keep) {
			t.Errorf("bytes outside the redacted strings changed: %s", out)
		}
	}
	if strings.Join(kinds, ",") != KindAWSAccessKey+","+KindGeneric {
		t.Fatalf("kinds %v", kinds)
	}
	if same, _, _ := RedactJSON(New(), []byte(`{"a":"b"}`)); string(same) != `{"a":"b"}` {
		t.Fatal(string(same))
	}
	if _, _, err := RedactJSON(New(), []byte(`{"a":1,"a":2}`)); err == nil {
		t.Fatal("duplicate keys must be refused")
	}
}

func TestEntropyMaths(t *testing.T) {
	if h := Entropy([]byte("aaaa")); h != 0 {
		t.Fatal(h)
	}
	if h := Entropy([]byte("abcd")); h != 2 {
		t.Fatal(h)
	}
	t.Logf("aws example %.2f, random %.2f, sha256 %.2f", Entropy([]byte(fakeAWSSec)), Entropy([]byte(fakeRandom)),
		Entropy([]byte("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")))
}

func TestTextStartingInsideAKeyIsRedactedToItsEnd(t *testing.T) {
	text := "a2V5Ym9keQ==\nshort\n-----END RSA PRIVATE KEY-----\nafter"
	got := string(Redact([]byte(text), New().Find([]byte(text))))
	if got != "[REDACTED:private-key-pem]\nafter" {
		t.Fatalf("%q", got)
	}
}
