// Package dlp finds secrets in text so roverd can keep them away from the
// model and out of its own files (plan §6 M10).
//
// LESSON (M10): data-loss prevention here has two jobs.
//   - Results coming back from a server may carry credentials (a config
//     file, an .env, a CI log). The model does not need them to do its job,
//     and anything the model sees can be repeated, summarised or sent on by
//     a later tool call, so roverd replaces them with "[REDACTED:<kind>]"
//     before the agent receives the line.
//   - Arguments going out through an egress tool (send an e-mail, post to a
//     URL) must not carry a credential at all: that is exfiltration, so the
//     call is blocked.
//
// Two kinds of detector work together. Format detectors know a vendor's
// token shape (AKIA + 16, ghp_ + 36, "-----BEGIN ... PRIVATE KEY-----"),
// so they are precise. The entropy detector knows nothing about vendors: it
// flags a long run of token characters whose Shannon entropy is high, which
// is how a randomly generated secret looks, and it is what catches the
// formats nobody listed. Its false positives (hashes, ids, images) are kept
// down by shape exclusions, see entropy.go.
//
// Everything is hand-written over the bytes, no regexp: one pass for the
// entropy runs plus a few memchr-style searches for fixed prefixes, so a
// 64 KB result costs well under the 2 ms budget and the time is linear in
// the input whatever it contains.
package dlp

import "sort"

// Kinds of secret, in priority order: when two matches overlap, the merged
// span keeps the earlier (more specific) kind.
const (
	KindPrivateKey   = "private-key-pem"
	KindAWSAccessKey = "aws-access-key"
	KindGitHubToken  = "github-token"
	KindSlackWebhook = "slack-webhook"
	KindSlackToken   = "slack-token"
	KindStripe       = "stripe"
	KindJWT          = "jwt"
	KindAWSSecret    = "aws-secret"
	KindGeneric      = "generic-credential"
	KindHighEntropy  = "high-entropy"
	redactedPrefix   = "[REDACTED:"
	redactedSuffix   = "]"
)

// Kinds lists every kind, most specific first.
var Kinds = []string{
	KindPrivateKey, KindAWSAccessKey, KindGitHubToken, KindSlackWebhook, KindSlackToken,
	KindStripe, KindJWT, KindAWSSecret, KindGeneric, KindHighEntropy,
}

var priority = func() map[string]int {
	m := make(map[string]int, len(Kinds))
	for i, k := range Kinds {
		m[k] = i
	}
	return m
}()

// Match is one secret: its kind and its byte span [Start, End) in the
// text. Entropy is the span's Shannon entropy in bits per byte, when the
// detector computed it (entropy and aws-secret), else 0.
type Match struct {
	Kind       string
	Start, End int
	Entropy    float64
}

// Detector finds secrets. Find returns matches sorted by Start that do not
// overlap (overlapping candidates are merged, keeping the most specific
// kind). It is safe for concurrent use.
type Detector interface {
	Find(text []byte) []Match
}

// New returns the detector with every built-in kind.
func New() Detector { return detector{} }

type detector struct{}

// Find implements Detector.
func (detector) Find(text []byte) []Match {
	if len(text) < minSecret {
		return nil
	}
	lower := lowerASCII(text)
	var ms []Match
	ms = findPrefixed(text, ms)
	ms, public := findPEM(text, ms)
	ms = findJWT(text, ms)
	ms = findGeneric(text, lower, ms)
	ms = findRuns(text, lower, public, ms)
	return resolve(ms)
}

// minSecret is the shortest text any detector can match (an AWS access
// key id is 20 bytes; a generic credential's value 8 plus "pwd=").
const minSecret = 12

// resolve sorts matches and merges overlapping ones.
func resolve(ms []Match) []Match {
	if len(ms) < 2 {
		return ms
	}
	sort.Slice(ms, func(i, j int) bool {
		if ms[i].Start != ms[j].Start {
			return ms[i].Start < ms[j].Start
		}
		return priority[ms[i].Kind] < priority[ms[j].Kind]
	})
	out := ms[:1]
	for _, m := range ms[1:] {
		cur := &out[len(out)-1]
		if m.Start >= cur.End {
			out = append(out, m)
			continue
		}
		cur.End = max(cur.End, m.End)
		cur.Entropy = max(cur.Entropy, m.Entropy)
		if priority[m.Kind] < priority[cur.Kind] {
			cur.Kind = m.Kind
		}
	}
	return out
}

// KindsOf returns the sorted, distinct kinds of ms.
func KindsOf(ms []Match) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range ms {
		if !seen[m.Kind] {
			seen[m.Kind] = true
			out = append(out, m.Kind)
		}
	}
	sort.Strings(out)
	return out
}

// lowerASCII is text with A-Z lowered; every other byte (and so every
// offset) is unchanged.
func lowerASCII(text []byte) []byte {
	out := make([]byte, len(text))
	for i, c := range text {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

func isDigit(c byte) bool { return '0' <= c && c <= '9' }
func isUpper(c byte) bool { return 'A' <= c && c <= 'Z' }
func isLower(c byte) bool { return 'a' <= c && c <= 'z' }
func isAlnum(c byte) bool { return isDigit(c) || isUpper(c) || isLower(c) }
