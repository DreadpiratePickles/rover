package daemon

import (
	"github.com/DreadpiratePickles/rover/internal/detect"
	"github.com/DreadpiratePickles/rover/internal/dlp"
)

// redactJoints scans the joint of each pair of adjacent text blocks (the
// last joinWindow bytes of one and the first of the next, joined) and
// redacts what it finds in both blocks. A secret split in two blocks is
// whole only in the joint; one that begins in a block after a cut (the
// context "password=" in the other) is recognisable only there too.
func (s *Server) redactJoints(res []byte, member string, kind detect.Kind) ([]byte, []string, int, error) {
	texts, err := blockTexts(res, member, kind)
	if err != nil {
		return nil, nil, 0, err
	}
	found := make([][]dlp.Match, len(texts))
	var kinds []string
	for i := 0; i+1 < len(texts); i++ {
		a, b := texts[i], texts[i+1]
		if a == nil || b == nil {
			continue
		}
		tail, head := a.text[max(0, len(a.text)-joinWindow):], b.text[:min(len(b.text), joinWindow)]
		cut, off := len(tail), len(a.text)-len(tail)
		for _, m := range s.jointMatches(tail, head) {
			if m.Start < cut {
				found[i] = append(found[i], dlp.Match{Kind: m.Kind, Start: off + m.Start, End: off + min(m.End, cut)})
			}
			if m.End > cut {
				found[i+1] = append(found[i+1], dlp.Match{Kind: m.Kind, Start: max(m.Start, cut) - cut, End: m.End - cut})
			}
			kinds = append(kinds, m.Kind)
		}
	}
	var edits []edit
	for i, ms := range found {
		if len(ms) > 0 {
			edits = append(edits, edit{start: texts[i].start, end: texts[i].end, with: mustJSON(string(dlp.Redact([]byte(texts[i].text), ms)))})
		}
	}
	if len(edits) == 0 {
		return res, nil, 0, nil
	}
	out, err := applyEdits(res, edits)
	return out, kinds, len(kinds), err
}

// jointMatches finds secrets in tail+head, as offsets in the two joined:
// the union of a scan with a NUL between the two sides (NUL is never part
// of a token, and never in JSON text: each side's own secrets, with the
// other side's context) and a scan of the plain join. A plain-join match
// that crosses the joint is kept only when the bytes on both sides of the
// joint are non-white-space, so the token really continues across it (a
// key split in two blocks, after "GITHUB_TOKEN=" or not); a secret that
// ends at a line break does not run on into the next block ("[default]").
func (s *Server) jointMatches(tail, head string) []dlp.Match {
	cut := len(tail)
	var out []dlp.Match
	for _, m := range s.dlp.Find([]byte(tail + "\x00" + head)) {
		switch {
		case m.End <= cut:
		case m.Start > cut:
			m.Start, m.End = m.Start-1, m.End-1
		default:
			continue // cannot cross a NUL
		}
		out = append(out, m)
	}
	continues := cut > 0 && len(head) > 0 && !isWhite(tail[cut-1]) && !isWhite(head[0])
	for _, m := range s.dlp.Find([]byte(tail + head)) {
		if m.Start >= cut || m.End <= cut || continues {
			out = append(out, m)
		}
	}
	return out
}

func isWhite(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}
