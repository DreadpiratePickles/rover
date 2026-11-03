package bridge

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
)

// LESSON (M11, the confused deputy): every header on a request to the remote
// server is built here, by Rover, from a fixed list. Nothing the agent sends
// (a "headers" member in its config, an "Authorization" string inside a
// message, an environment variable) is copied into an HTTP header. The only
// values taken from a message are the ones the MCP spec says to mirror
// (method, tool name or URI, protocol version), and those go through
// headerValue, which base64-encodes anything that is not plain visible
// ASCII, so a crafted tool name cannot smuggle "\r\nAuthorization: ..."
// into the request.

// Header names (case-insensitive on the wire).
const (
	hdrSession     = "Mcp-Session-Id"
	hdrProtocol    = "MCP-Protocol-Version"
	hdrMethod      = "Mcp-Method"
	hdrName        = "Mcp-Name"
	hdrLastEventID = "Last-Event-ID"
)

// metaProtocolKey is where 2026-07-28 messages carry their protocol version.
const metaProtocolKey = "io.modelcontextprotocol/protocolVersion"

// headerSafe reports whether s can be sent as a plain header value: visible
// ASCII and spaces, no edge whitespace, and not shaped like the sentinel.
func headerSafe(s string) bool {
	if s == "" || s != strings.TrimSpace(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return !strings.HasPrefix(s, "=?base64?") || !strings.HasSuffix(s, "?=")
}

// headerValue encodes s per the 2026-07-28 Value Encoding rule.
func headerValue(s string) string {
	if headerSafe(s) {
		return s
	}
	return "=?base64?" + base64.StdEncoding.EncodeToString([]byte(s)) + "?="
}

// setMCPHeaders adds the mirrored MCP headers for m. negotiated is the
// protocol version the server returned from initialize ("" if none yet).
func setMCPHeaders(h http.Header, m jsonrpc.Message, negotiated string) {
	if v := bodyProtocolVersion(m); v != "" {
		h.Set(hdrProtocol, v)
	} else if negotiated != "" && m.Method != "initialize" {
		h.Set(hdrProtocol, negotiated)
	}
	if m.Kind != jsonrpc.KindRequest && m.Kind != jsonrpc.KindNotification {
		return
	}
	if m.Method != "" {
		h.Set(hdrMethod, headerValue(m.Method))
	}
	var key string
	switch m.Method {
	case "tools/call", "prompts/get":
		key = "name"
	case "resources/read":
		key = "uri"
	default:
		return
	}
	var p map[string]json.RawMessage
	if json.Unmarshal(m.Params, &p) != nil {
		return
	}
	var v string
	if json.Unmarshal(p[key], &v) == nil && v != "" {
		h.Set(hdrName, headerValue(v))
	}
}

// bodyProtocolVersion reads params._meta["io.modelcontextprotocol/protocolVersion"].
func bodyProtocolVersion(m jsonrpc.Message) string {
	var p struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if len(m.Params) == 0 || json.Unmarshal(m.Params, &p) != nil {
		return ""
	}
	var v string
	if json.Unmarshal(p.Meta[metaProtocolKey], &v) != nil || !headerSafe(v) || len(v) > 64 {
		return ""
	}
	return v
}

// resultProtocolVersion reads result.protocolVersion of an initialize reply.
func resultProtocolVersion(result json.RawMessage) string {
	var r struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if json.Unmarshal(result, &r) != nil || !headerSafe(r.ProtocolVersion) || len(r.ProtocolVersion) > 64 {
		return ""
	}
	return r.ProtocolVersion
}
