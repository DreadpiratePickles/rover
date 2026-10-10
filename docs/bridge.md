# `rover bridge`: facts checked before building (M11)

Checked on 2026-10-09 against the official MCP specification. The latest
revision on modelcontextprotocol.io that day is **2026-07-28**; the previous
one is **2025-11-25**. Remote servers in the wild speak either, so the bridge
handles both (it forwards the client's bytes and does not pick a version).

## Streamable HTTP

Sources:
- https://modelcontextprotocol.io/specification/latest/basic/transports (overview, 2026-07-28)
- https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http
- https://modelcontextprotocol.io/specification/2025-11-25/basic/transports

Both revisions:
- Every client message is its own HTTP POST to one MCP endpoint. The client
  MUST send `Accept` listing both `application/json` and `text/event-stream`.
- A notification (or, in 2025-11-25, a response) that the server accepts is
  answered `202 Accepted` with no body; refusal is an HTTP error status.
- A request is answered with `Content-Type: application/json` (one JSON
  object) or `text/event-stream` (SSE); the client MUST support both.
- `MCP-Protocol-Version: <version>` on requests. In 2025-11-25 it is the
  version negotiated in `initialize` (absent header: server assumes
  2025-03-26). In 2026-07-28 it MUST equal the body's
  `_meta["io.modelcontextprotocol/protocolVersion"]`, else 400.
- Servers MUST validate `Origin` (DNS rebinding); local servers SHOULD bind
  to 127.0.0.1.

2025-11-25 only (all removed in 2026-07-28):
- `MCP-Session-Id` may be set on the response carrying `InitializeResult`;
  the client MUST then send it on every later request. 404 for a request
  with a session id means the session ended: the client MUST start over with
  a new `initialize`.
- `DELETE` with the session id ends the session; 405 means the server does
  not allow it.
- `GET` with `Accept: text/event-stream` opens a stream for server-initiated
  requests and notifications; 405 means the server offers none.
- SSE events may carry `id:`; to resume after a drop the client sends `GET`
  with `Last-Event-ID`. A `retry:` field MUST be respected before reconnecting.
- Servers may send JSON-RPC requests on SSE streams (elicitation, sampling).

2026-07-28 only:
- No sessions, no GET stream, no `Last-Event-ID` resumption ("Resumable SSE
  streams via Last-Event-ID are not supported"); a server answering an older
  client SHOULD return 405 to GET and DELETE and ignore `Mcp-Session-Id`.
- Required mirrored headers: `Mcp-Method` (all requests) and `Mcp-Name`
  (`params.name` or `params.uri` of `tools/call`, `resources/read`,
  `prompts/get`); values outside visible ASCII, with edge spaces or that look
  like the sentinel are sent as `=?base64?...?=`. Mismatch is 400 with
  JSON-RPC error -32020 (HeaderMismatch).
- `x-mcp-header` tool parameters MUST be mirrored as `Mcp-Param-<Name>`.
- Cancellation is closing the request's SSE stream.

What the bridge does: POST with both Accept types; JSON or SSE; `id:` and
`retry:` tracked, one GET with `Last-Event-ID` (retry capped) if a POST
stream drops before its response; `Mcp-Session-Id` captured and replayed;
404 with a session clears it and fails that request; GET listener started
after `initialize` (405 stops it); DELETE on exit; `MCP-Protocol-Version`
from the body's `_meta` when present, else the version the server returned
in `initialize`; `Mcp-Method` and `Mcp-Name` derived from the body with the
base64 sentinel. Deviation: `Mcp-Param-*` (x-mcp-header) is **not**
mirrored in M11; a 2026-07-28 server that uses it answers -32020 and the
client sees that error (tracked for M12+).

## Authorization

Sources:
- https://modelcontextprotocol.io/specification/latest/basic/authorization (2026-07-28)
- https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery
- https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration
- https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations

- OAuth 2.1 (draft-ietf-oauth-v2-1-13) authorization code flow; the client
  is an OAuth client in its own right.
- Discovery: on 401 read `resource_metadata` from `WWW-Authenticate`
  (RFC 9728 §5.1); without it try
  `/.well-known/oauth-protected-resource/<path>` then
  `/.well-known/oauth-protected-resource`. The document MUST list at least
  one `authorization_servers`; the choice is the client's (Rover: the first).
- AS metadata (RFC 8414): for an issuer with a path try
  `/.well-known/oauth-authorization-server/<path>`,
  `/.well-known/openid-configuration/<path>`, `<issuer>/.well-known/openid-configuration`;
  without a path the first two. The document's `issuer` MUST equal the
  issuer used to build the URL, else it MUST NOT be used.
- PKCE: S256; if `code_challenge_methods_supported` is absent the client
  MUST refuse to proceed.
- Registration priority: pre-registered client, then Client ID Metadata
  Documents (`client_id_metadata_document_supported`), then RFC 7591
  dynamic registration (`registration_endpoint`, now marked deprecated),
  then ask the user. Native clients SHOULD register with
  `application_type: "native"`. Credentials are bound to the issuer.
- `resource` (RFC 8707) MUST be in both the authorization and the token
  request and be the canonical server URI (no fragment, no trailing slash).
- RFC 9207: if the AS advertises `authorization_response_iss_parameter_supported`
  the redirect MUST carry `iss` equal to the recorded issuer; a present
  `iss` is always compared.
- Tokens go only in `Authorization: Bearer`, never in the query string; the
  client MUST NOT send the server tokens other than ones from its AS.
- `state` SHOULD be used and checked; redirect URIs MUST be localhost or HTTPS.
- Confused deputy / token passthrough: a server MUST NOT pass through the
  token it received; proxies with static client ids need per-client consent.

What the bridge does: discovery from the 401 (well-known fallback), RFC 8414
with issuer check, PKCE S256 refused unless advertised, RFC 7591 when
`registration_endpoint` exists (`client_name: Rover`,
`application_type: native`, `token_endpoint_auth_method: none`, loopback
redirect), else a `client_id` from config.yaml; `state` and the PKCE
verifier bound per login; `iss` checked per RFC 9207; `resource` = the
canonical bridge URL in both requests. Not implemented: Client ID Metadata
Documents (Rover has no HTTPS home for one yet) and step-up on 403
`insufficient_scope` (the error reaches the client; rerun `rover bridge login`).

Audience (documented rule): if the access token is a JWT (three base64url
parts with a JSON payload) its `aud` (string or array) MUST contain the
resource; if the token is opaque and the token response echoes `resource`
or `aud`, it MUST equal the resource; an opaque token with no echo is
accepted (the server must check it; nothing more is knowable client-side).

Confused deputy rule in Rover: the bridge builds every remote request's
headers itself. Nothing from the client's messages, its environment or its
MCP config `headers` becomes an HTTP header, except the derived
`Mcp-Method`/`Mcp-Name`/`MCP-Protocol-Version` (sentinel-encoded, so no
header injection). Redirects are refused (not followed), so a 3xx cannot
carry Rover's own token to another host either.

## go-keyring on headless Linux

Sources: https://github.com/zalando/go-keyring (README, v0.2.8 source:
keyring_unix.go, secret_service/secret_service.go) and
github.com/godbus/dbus/v5 v5.2.2 conn.go / conn_other.go.

- Linux uses the Secret Service D-Bus API (`org.freedesktop.secrets`, e.g.
  gnome-keyring) and the default "login" collection. The README says
  nothing about headless use.
- `dbus.SessionBus()` takes `DBUS_SESSION_BUS_ADDRESS`, else
  `/run/user/<uid>/bus`, else **autolaunches `dbus-launch`**; on a headless
  box that either fails or starts a bus with no secret service, and the
  call fails with `ServiceUnknown`.
- macOS shells out to `/usr/bin/security`; `Set` passes the secret on the
  tool's stdin (`security -i`), not argv; service+account+secret over about
  3000 bytes is `ErrSetDataTooBig`.

Fallback (plan §8): Rover probes first, without autolaunch
(`SessionBusPrivateNoAutoStartup`, then `NameHasOwner` /
`ListActivatableNames` for `org.freedesktop.secrets`), and any failure is
`ErrNoKeychain`: "no keychain available; Rover will not store tokens in a
file". There is no file fallback. Not run in a Linux container here (no
container runtime on the build Mac); verified by source reading and
`GOOS=linux go vet`.
