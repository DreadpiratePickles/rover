package dlp

import (
	"bytes"
	"encoding/base64"
	"math"
)

// The entropy detector. A run is a maximal sequence of token bytes
// [A-Za-z0-9+/_-], plus up to two '=' of base64 padding at its end. For a
// run of n bytes in which byte value b occurs c_b times, the Shannon
// entropy is H = -Σ (c_b/n) log2(c_b/n) bits per byte. English words and
// identifiers reuse a few letters (H about 3 to 4); a random string comes
// close to what its alphabet and length allow (see threshold.go: 4.27 for
// 32 lowercase+digit bytes, 4.56 for 32 base64 bytes). A run of
// minRun..maxRun bytes whose H reaches the threshold for its alphabet and
// length, holding a digit and a letter and at most one separator (/ + _ -)
// in maxSepShare bytes, is flagged, unless its shape says it is something
// else:
//   - hex only (with dashes): SHA-256 digests, git commit ids and UUIDs are
//     high-entropy by design and are what an audit log is full of, so hex
//     is never flagged by entropy alone (format detectors still apply);
//   - base64 of a known binary (PNG, JPEG, GIF, WebP, PDF, zip) or after
//     "base64," in a data: URI: images, not secrets;
//   - inside a URL (the white-space-delimited word holds "://"): path
//     segments and video or playlist ids look random; a credential in a
//     query string is still caught as generic (token=...);
//   - published integrity hashes and public keys: SRI ("sha512-..."), go.sum
//     ("h1:..."), SSH public keys ("AAAAC3NzaC1lZDI1NTE5..."), and the body
//     of a public PEM block (CERTIFICATE, PUBLIC KEY, PGP PUBLIC KEY BLOCK);
//   - the local part of an address (followed by '@'): Message-IDs;
//   - base64 of a whole PEM file ("LS0tLS1CRUdJTi...", kubeconfig *-data):
//     decoded, a private key is flagged as one at any length, anything
//     else (a certificate) is public.
//
// aws-secret is the 40-byte [A-Za-z0-9+/] run of an AWS secret access key,
// with H >= awsEntropy, when "aws" or "secret" appears in the 64 bytes
// before it: the context is what separates it from any other 40 bytes.
const (
	minRun      = 32
	maxRun      = 512
	maxSepShare = 8 // a run with more than 1/8 separators (/ + _ -) is a path or slug
	awsEntropy  = 4.3
	awsLen      = 40
	awsContext  = 64
)

// publicPrefixes start runs that are base64 of public data: binaries
// (PNG, JPEG, GIF, WebP, PDF, zip), SRI hashes and SSH public keys.
var publicPrefixes = [][]byte{
	[]byte("iVBORw0KGgo"), []byte("/9j/"), []byte("R0lGOD"), []byte("UklGR"), []byte("JVBERi0"), []byte("UEsDB"),
	[]byte("sha256-"), []byte("sha384-"), []byte("sha512-"),
	[]byte("AAAAB3NzaC1"), []byte("AAAAC3NzaC1"), []byte("AAAAE2VjZHNh"),
}

// publicBefore end the text before a run of public data.
var publicBefore = [][]byte{[]byte("base64,"), []byte("h1:")}

func runByte(c byte) bool { return isAlnum(c) || c == '+' || c == '/' || c == '_' || c == '-' }

// findRuns is the one pass over the text: it walks every run once, and
// remembers whether the current white-space-delimited word is a URL.
// public are the spans of public PEM blocks (sorted), skipped.
func findRuns(text, lower []byte, public []span, ms []Match) []Match {
	inURL := false
	for i := 0; i < len(text); {
		if c := text[i]; !runByte(c) {
			switch {
			case isSpace(c) || c == '"' || c == '(' || c == '<':
				inURL = false // a new word starts
			case c == ':' && bytes.HasPrefix(text[i:], []byte("://")):
				inURL = true
			}
			i++
			continue
		}
		start := i
		for i < len(text) && runByte(text[i]) {
			i++
		}
		for pad := 0; pad < 2 && i < len(text) && text[i] == '='; pad++ {
			i++
		}
		if bytes.HasPrefix(text[start:i], base64PEM) {
			// base64 of a whole PEM file (kubeconfig *-data): a private
			// key is a key at any length; a certificate is public.
			if base64PEMPrivate(text[start:i]) {
				ms = append(ms, Match{Kind: KindPrivateKey, Start: start, End: i})
			}
			continue
		}
		for len(public) > 0 && public[0].end <= start {
			public = public[1:]
		}
		inPublic := len(public) > 0 && public[0].start <= start
		if n := i - start; (n >= minRun && n <= maxRun || n == awsLen) && !inURL && !inPublic {
			if m, ok := classifyRun(text, lower, start, i); ok {
				ms = append(ms, m)
			}
		}
	}
	return ms
}

// classifyRun decides whether text[start:end] is an aws-secret, a
// high-entropy secret, or neither.
func classifyRun(text, lower []byte, start, end int) (Match, bool) {
	run := text[start:end]
	digit, lower1, upper1, hexOnly, awsShape := false, false, false, true, len(run) == awsLen
	seps := 0
	for _, c := range run {
		switch {
		case isDigit(c):
			digit = true
		case isUpper(c) || isLower(c):
			lower1, upper1 = lower1 || isLower(c), upper1 || isUpper(c)
			if (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
				hexOnly = false
			}
		case c == '-':
			seps++
		case c != '=':
			hexOnly = false
			seps++
		}
		if c == '_' || c == '-' {
			awsShape = false
		}
	}
	if !digit || (!lower1 && !upper1) || hexOnly || publicData(text, start, end) {
		return Match{}, false
	}
	h := entropy(run)
	if awsShape && h >= awsEntropy {
		ctx := lower[max(0, start-awsContext):start]
		if bytes.Contains(ctx, []byte("aws")) || bytes.Contains(ctx, []byte("secret")) {
			return Match{Kind: KindAWSSecret, Start: start, End: end, Entropy: h}, true
		}
	}
	// A path or slug has a separator every few bytes; random base64 has
	// one in 32 (+/ or -_ of 64 symbols).
	if len(run) >= minRun && seps*maxSepShare <= len(run) && h >= threshold(alphabet(lower1, upper1, seps > 0), len(run)) {
		return Match{Kind: KindHighEntropy, Start: start, End: end, Entropy: h}, true
	}
	return Match{}, false
}

// publicData: the run is base64 of public data (publicPrefixes,
// publicBefore) or the local part of an address.
func publicData(text []byte, start, end int) bool {
	if end < len(text) && text[end] == '@' {
		return true
	}
	for _, p := range publicBefore {
		if bytes.HasSuffix(text[:start], p) {
			return true
		}
	}
	for _, p := range publicPrefixes {
		if bytes.HasPrefix(text[start:], p) {
			return true
		}
	}
	return false
}

// entropy is the Shannon entropy of b in bits per byte.
func entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	n := float64(len(b))
	h := 0.0
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

// Entropy is the Shannon entropy of b in bits per byte (exported for the
// lesson's examples and tests).
func Entropy(b []byte) float64 { return entropy(b) }

// base64PEM is base64 of "-----BEGIN".
var base64PEM = []byte("LS0tLS1CRUdJTi")

// base64PEMPrivate decodes the start of a base64 PEM file and reports a
// private key ("-----BEGIN ... PRIVATE KEY-----" on its first line).
func base64PEMPrivate(run []byte) bool {
	head := run[:min(len(run), 96)] // 72 decoded bytes: the whole BEGIN line
	head = head[:len(head)/4*4]
	dec, err := base64.StdEncoding.DecodeString(string(head))
	if err != nil {
		return false
	}
	if nl := bytes.IndexByte(dec, '\n'); nl >= 0 {
		dec = dec[:nl]
	}
	return bytes.Contains(dec, []byte("PRIVATE KEY"))
}
