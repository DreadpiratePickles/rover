package dlp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
	"testing"
	"time"
)

// Review findings (verification of M10): each test was red before its fix.

// M3: 64 KB of "password=" made every occurrence read 512 bytes forward.
func TestGenericScanIsLinearOnCredentialWords(t *testing.T) {
	d := New()
	median := 2 * time.Millisecond
	bigLimit := 300 * time.Millisecond
	if raceBuild {
		median, bigLimit = 20*time.Millisecond, 3*time.Second
	}
	for _, unit := range []string{"password=", "pwd=a1234567 ", "token: \"", "AKIA", "bearer ", "basic "} {
		text := []byte(strings.Repeat(unit, resultSize/len(unit)+1)[:resultSize])
		ds := make([]time.Duration, 31)
		for i := range ds {
			start := time.Now()
			_ = d.Find(text)
			ds[i] = time.Since(start)
		}
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		overBudget(t, fmt.Sprintf("%q 64 KB median", unit), ds[15], median)
	}
	big := []byte(strings.Repeat("password=", (16<<20)/9))
	start := time.Now()
	_ = d.Find(big)
	overBudget(t, "16 MiB of password=", time.Since(start), bigLimit)
}

func TestHTTPAuthorizationHeaders(t *testing.T) {
	basic := base64.StdEncoding.EncodeToString([]byte("deploy:Sup3rS3cret"))
	for text, secret := range map[string]string{ //nolint:gosec // G101: fake fixtures, valid nowhere
		"Authorization: Bearer 9f8e7d6c5b4a3a2b1c0d9e8f7a6b5c4dzz11": "9f8e7d6c5b4a3a2b1c0d9e8f7a6b5c4dzz11",
		"-H 'authorization: basic " + basic + "'":                    basic,
	} {
		ms := New().Find([]byte(text))
		if len(ms) == 0 || ms[0].Kind != KindHTTPAuth || strings.Contains(string(Redact([]byte(text), ms)), secret) {
			t.Errorf("%q: %+v", text, ms)
		}
	}
	for _, benign := range []string{"basic usage of the bearer pattern", "Authorization: Bearer <token>", "Bearer ${TOKEN}"} {
		if ms := New().Find([]byte(benign)); len(ms) > 0 {
			t.Errorf("%q: %+v", benign, ms)
		}
	}
}

func TestBase64PEMIsAKeyOrPublic(t *testing.T) {
	cert := base64.StdEncoding.EncodeToString([]byte("-----BEGIN CERTIFICATE-----\nMIIC" + strings.Repeat("Ab3x", 60) + "\n-----END CERTIFICATE-----\n"))
	key := base64.StdEncoding.EncodeToString([]byte("-----BEGIN RSA PRIVATE KEY-----\nMIIE" + strings.Repeat("Ab3x", 60) + "\n-----END RSA PRIVATE KEY-----\n"))
	if ms := New().Find([]byte("certificate-authority-data: " + cert)); len(ms) > 0 {
		t.Errorf("a base64 certificate is public: %+v", ms)
	}
	if ms := New().Find([]byte("client-key-data: " + key)); len(ms) != 1 || ms[0].Kind != KindPrivateKey {
		t.Errorf("a base64 private key: %+v", ms)
	}
}

// The entropy threshold scales with the alphabet: 32 lowercase+digit
// characters (H about 4.26) were never flagged at a fixed 4.5.
func TestEntropyThresholdScalesWithAlphabet(t *testing.T) {
	for _, s := range []string{"k7x2m9q4w8e1r5t3y6u0i2o4p8a1s3d5", "h3k8s0d2f9g7j1l4z6x5c8v0b2n4m7q1w3e5"} {
		if ms := New().Find([]byte("key " + s)); len(ms) != 1 || ms[0].Kind != KindHighEntropy {
			t.Errorf("%s (H %.2f): %+v", s, Entropy([]byte(s)), ms)
		}
	}
	for _, s := range []string{"node_modules/left-pad/lib/index-v2", "2024_spring_launch_event_announcement"} {
		if ms := New().Find([]byte(s)); len(ms) > 0 {
			t.Errorf("%s: %+v", s, ms)
		}
	}
}

// H1: member names are strings too.
func TestRedactJSONRedactsMemberNamesKeepingThemUnique(t *testing.T) {
	raw := []byte(`{"a":{"` + fakeAKIA + `":"owner","AKIAEXAMPLE000000002":"x","[REDACTED:aws-access-key]#2":1},"n":1}`)
	out, kinds, n, err := RedactJSON(New(), raw)
	if err != nil || n != 2 || strings.Join(kinds, ",") != KindAWSAccessKey {
		t.Fatalf("%s %v %d %v", out, kinds, n, err)
	}
	var v struct{ A map[string]any }
	if !json.Valid(out) || json.Unmarshal(out, &v) != nil || len(v.A) != 3 || strings.Contains(string(out), "000000001") {
		t.Fatalf("%s", out)
	}
	if got, err := FindJSON(New(), []byte(`{"`+fakeGHP+`":1}`)); err != nil || len(got) != 1 {
		t.Fatalf("FindJSON must see names: %v %v", got, err)
	}
}

// Random tokens of every alphabet and length are found (the fixed 4.5
// threshold missed most 32-character lowercase+digit tokens).
func TestRandomTokensOfEveryAlphabetAreFound(t *testing.T) {
	rng := rand.New(rand.NewPCG(10, 10)) //nolint:gosec // G404: a seeded, reproducible test input, not a secret
	for _, a := range []string{"abcdefghijklmnopqrstuvwxyz0123456789", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"} {
		for _, n := range []int{32, 40, 64, 128} {
			found := 0
			for range 500 {
				b := make([]byte, n)
				for i := range b {
					b[i] = a[rng.IntN(len(a))]
				}
				if len(New().Find(append([]byte("k "), b...))) > 0 {
					found++
				}
			}
			if found < 480 {
				t.Errorf("alphabet %d, %d bytes: %d/500 found", len(a), n, found)
			}
		}
	}
}
