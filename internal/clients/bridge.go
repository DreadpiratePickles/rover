package clients

import (
	"bytes"
	"fmt"
	"path/filepath"

	"github.com/DreadpiratePickles/rover/internal/ipc"
)

// LESSON (M11): a remote server in a client config is a URL the client
// talks to directly, so Rover never saw that traffic. `rover install` now
// turns it into a local stdio server, `rover bridge --name <key> --url
// <url>`, which speaks Streamable HTTP to the remote and sends every
// message through roverd like `rover wrap`. Two rules from M7 still hold:
// only the few bytes that must change are spliced in, and uninstall is the
// exact inverse. The url is moved into args as its original bytes, and an
// original "type" value is kept in args too ("--remote-type"), so nothing
// is lost.
//
// An entry with its own "headers" is left alone: those are usually an
// Authorization token in a plaintext file, and Rover never forwards a
// client's headers (the confused-deputy rule). The user moves the token
// into the keychain and removes the headers, then reruns install.

// bridgeArgsFlags are the fixed flags of a converted entry.
const (
	flagRemoteType = "--remote-type"
	flagURL        = "--url"
)

// IsBridgeForm reports whether command and args are `rover bridge --name N
// [--remote-type T] --url U` exactly as bridgeEdits writes it.
func IsBridgeForm(command string, args []string) bool {
	base := filepath.Base(command)
	if base != "rover" && base != "rover.exe" {
		return false
	}
	switch len(args) {
	case 5:
		return args[0] == "bridge" && args[1] == "--name" && args[3] == flagURL
	case 7:
		return args[0] == "bridge" && args[1] == "--name" && args[3] == flagRemoteType && args[5] == flagURL
	}
	return false
}

// bridgeable says whether a remote entry can be converted, and if not why.
func bridgeable(src []byte, s Server) (string, bool) {
	switch {
	case s.HasHeaders:
		return s.Label() + " is a remote server with its own headers (often a token in this file); Rover never forwards a client's headers: " +
			"store the token with `rover bridge login --name " + ipc.SanitizeServerName(s.Key) + " --token -`, remove \"headers\", then rerun install", false
	case s.RemoteType == "ws":
		return s.Label() + " is a remote server over WebSocket, which `rover bridge` does not speak; left alone", false
	case s.urlF == nil || s.URL == "":
		return s.Label() + " is a remote server without a url string; left alone", false
	}
	if _, ok := keyStart(src, s.urlF.Start, "url"); !ok {
		return s.Label() + " is a remote server whose \"url\" key is written unusually; left alone", false
	}
	return "", true
}

// bridgeEdits converts a remote entry into a `rover bridge` stdio entry:
// the "url" key becomes "command", its value becomes the rover path plus an
// "args" member (the url's own bytes are the last arg), and a "type" value
// becomes "stdio".
func bridgeEdits(orig, src []byte, s Server, roverPath string) []edit {
	k, _ := keyStart(src, s.urlF.Start, "url")
	var b bytes.Buffer
	b.Write(jsonString(roverPath))
	b.WriteString(`, "args": ["bridge", "--name", `)
	b.Write(jsonString(ipc.SanitizeServerName(s.Key)))
	if s.typF != nil {
		b.WriteString(`, "` + flagRemoteType + `", `)
		b.Write(orig[s.typF.Start:s.typF.End])
	}
	b.WriteString(`, "` + flagURL + `", `)
	b.Write(orig[s.urlF.Start:s.urlF.End])
	b.WriteByte(']')
	// The key is renamed in place, so the bytes between key and value
	// (": " or ":" or anything) stay exactly as the user wrote them.
	es := []edit{{start: k, end: k + len(`"url"`), text: []byte(`"command"`)}, {start: s.urlF.Start, end: s.urlF.End, text: b.Bytes()}}
	if s.typF != nil {
		es = append(es, edit{start: s.typF.Start, end: s.typF.End, text: []byte(`"stdio"`)})
	}
	return es
}

// unbridgeEdits is the exact inverse of bridgeEdits.
func unbridgeEdits(orig, src []byte, s Server) ([]edit, error) {
	if !s.Bridged || s.cmd == nil || s.args == nil {
		return nil, fmt.Errorf("%s is not bridged", s.Label())
	}
	k, ok := keyStart(src, s.cmd.Start, "command")
	if !ok || string(orig[s.cmd.End:s.args.Start]) != `, "args": ` {
		return nil, fmt.Errorf("%s: the bridge entry was edited by hand; restore it from the backup or edit it yourself", s.Label())
	}
	url := s.argElems[len(s.argElems)-1]
	es := []edit{{start: k, end: k + len(`"command"`), text: []byte(`"url"`)}, {start: s.cmd.Start, end: s.args.End, text: bytes.Clone(orig[url.Start:url.End])}}
	if len(s.argElems) == 7 {
		if s.typF == nil {
			return nil, fmt.Errorf("%s: the bridge entry lost its \"type\"; restore it from the backup", s.Label())
		}
		t := s.argElems[4]
		es = append(es, edit{start: s.typF.Start, end: s.typF.End, text: bytes.Clone(orig[t.Start:t.End])})
	}
	return es, nil
}

// keyStart finds where the member whose value starts at valueStart begins:
// back over spaces, the colon and spaces, to a key written exactly as
// "<key>" (an escaped spelling is refused).
func keyStart(src []byte, valueStart int, key string) (int, bool) {
	i := valueStart - 1
	for i >= 0 && isSpace(src[i]) {
		i--
	}
	if i < 0 || src[i] != ':' {
		return 0, false
	}
	i--
	for i >= 0 && isSpace(src[i]) {
		i--
	}
	lit := `"` + key + `"`
	start := i + 1 - len(lit)
	if start < 0 || string(src[start:i+1]) != lit {
		return 0, false
	}
	return start, true
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }
