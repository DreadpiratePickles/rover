package learn

import (
	"math"
	"regexp"
	"strings"

	"github.com/cedar-policy/cedar-go/types"
)

// literalNames are the argument names whose value a shape may keep: names
// that usually hold one of a few fixed words. "state" and "scope" are not
// among them: OAuth uses both for opaque values. Any other argument keeps its
// JSON type only, because a short string can be a key or a password
// (independent verification of M6 found both stored).
var literalNames = map[string]bool{
	"branch": true, "ref": true, "mode": true, "method": true, "format": true, "level": true,
	"sort": true, "direction": true, "order": true, "visibility": true, "status": true,
	"type": true, "kind": true, "lang": true, "language": true, "encoding": true,
}

// literalValue is a value worth keeping: a plain word of at most 32 bytes.
var literalValue = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,31}$`)

// secretPrefixes are the token prefixes M10's redaction knows.
var secretPrefixes = regexp.MustCompile(`^(?:sk_live_|sk_test_|rk_live_|ghp_|gho_|ghs_|ghu_|github_pat_|xox[abpr]-|AKIA|ASIA)`)

// From minSecretLen characters on, a value looks like a secret when its
// Shannon entropy is above maxEntropy bits per character or it mixes
// digits and letters ("hunter2xyz"). Shorter values and plain words
// ("main", "ascending") are kept.
const (
	maxEntropy   = 3.5
	minSecretLen = 8
)

// literalShape keeps the JSON type, and the value only when the argument
// name is enum-like and the value is a plain word that is not secret-shaped.
func literalShape(name string, v types.Value) Arg {
	a := Arg{Type: jsonType(v)}
	if s, ok := v.(types.String); ok && literalNames[name] && keepable(string(s)) {
		a.Value = string(s)
	}
	return a
}

func keepable(s string) bool {
	return literalValue.MatchString(s) && !secretShaped(s)
}

// secretShaped reports a value that looks like a credential.
func secretShaped(s string) bool {
	if secretPrefixes.MatchString(s) || strings.ContainsAny(s, "=:") {
		return true
	}
	if len(s) < minSecretLen {
		return false
	}
	return entropy(s) > maxEntropy || (strings.ContainsAny(s, "0123456789") && strings.IndexFunc(s, isLetter) >= 0)
}

// entropy is the Shannon entropy of s in bits per character.
func entropy(s string) float64 {
	counts := map[rune]int{}
	n := 0
	for _, r := range s {
		counts[r]++
		n++
	}
	h := 0.0
	for _, c := range counts {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}

func isLetter(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }
