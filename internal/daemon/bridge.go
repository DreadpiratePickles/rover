package daemon

import "strings"

// TLSFindingPrefix starts the audit finding that names the TLS key exchange
// of a `rover bridge` connection (M11), e.g. "tls:X25519MLKEM768". It is
// information, not a detection: replay and learn mode ignore it.
const TLSFindingPrefix = "tls:"

// DetectionFindings drops the informational tls: findings from fs.
func DetectionFindings(fs []string) []string {
	var out []string
	for _, f := range fs {
		if !strings.HasPrefix(f, TLSFindingPrefix) {
			out = append(out, f)
		}
	}
	return out
}
