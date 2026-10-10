# M11 · Remote servers through `rover bridge`

**Goal:** until now Rover only saw MCP servers that run on your machine and
talk over stdin/stdout. More and more servers are remote: a URL your agent
talks to over HTTPS, often with a login. That traffic went around Rover.
M11 adds `rover bridge`: to the agent it looks like any local stdio server,
and on the other side it speaks MCP's **Streamable HTTP** transport to the
remote. Every message still goes through roverd, so policy, pinning,
detection and DLP apply unchanged. Rover logs in to the remote **itself**
(OAuth 2.1), keeps the tokens in the **OS keychain** only, and never passes
on a credential that came from the agent's side. Lesson focus: OAuth 2.1,
PKCE, the confused deputy, token audience, TLS 1.3 handshakes, and hybrid
post-quantum key exchange.

## (a) What was built

- `rover bridge --name N --url URL [--pq-required]` (cmd/rover/bridge.go):
  the same two pumps as `rover wrap` (internal/proxy), with an HTTP client
  where the child process used to be. It connects to roverd first; no
  daemon, no remote traffic. The hello says `transport: "http"`.
- `internal/bridge`: the Streamable HTTP client. Each message is one POST
  with `Accept: application/json, text/event-stream`; the answer is one
  JSON object or an SSE stream (`data:` lines; `id:` remembered so a
  dropped stream is resumed with `Last-Event-ID`). `Mcp-Session-Id` is
  captured from the `initialize` reply and sent on every later request;
  `DELETE` ends the session when the client hangs up; a `GET` stream
  carries server-initiated messages when the server offers one (405 means
  it does not). Every remote message is capped at 16 MiB, like stdio.
  docs/bridge.md records what the spec (2026-07-28 and 2025-11-25) says.
- `internal/bridge/oauth`: discovery from the server's `401` (RFC 9728),
  the authorization server's metadata (RFC 8414), dynamic registration
  (RFC 7591) as "Rover", authorization code + **PKCE S256** + `state` +
  `resource` (RFC 8707), a one-shot redirect page on `127.0.0.1:<random>`,
  token exchange, refresh, and the **audience check**.
- `internal/keychain`: the OS keychain (`github.com/zalando/go-keyring`) or
  a clear refusal: "no keychain available; Rover will not store tokens in a
  file". There is no file fallback.
- `rover bridge login --name N` (browser) or `--token -` (a static bearer
  from stdin). `rover doctor --remote` handshakes each configured bridge
  and prints the key exchange group. `rover install` turns remote entries
  in client configs into `rover bridge` entries (byte-exact, reversible).
- config.yaml `bridges: {name: {url, pq_required, ca_file, auth}}`. It is
  covered by `rover policy apply`, so it beats the client config: a bridge
  whose `--url` differs is refused, and `pq_required` there cannot be
  switched off by a flag.
- roverd records the negotiated group on every bridged audit entry as the
  finding `tls:X25519MLKEM768` (or `tls:X25519`, ...).

## (b) Design decisions and the attacks they prevent

### 1. OAuth 2.1 in one page

OAuth lets you give a program **limited, revocable** access to a service
without giving it your password. Four parties: you (the resource owner),
the **client** (Rover), the **authorization server** (AS, where you log in)
and the **resource server** (the remote MCP server). The client sends your
browser to the AS; you log in there, not in Rover; the AS sends the browser
back to the client with a short-lived **authorization code**; the client
swaps the code for an **access token** (and maybe a **refresh token**) at
the AS's token endpoint; it then sends `Authorization: Bearer <token>` to
the resource server. OAuth 2.1 is OAuth 2.0 with the dangerous parts
removed: no implicit flow (tokens in URLs), no password grant, PKCE always.

How does Rover find the AS? It sends a request without a token; the server
answers `401` with `WWW-Authenticate: Bearer resource_metadata="..."`.
That document (RFC 9728) lists the AS; the AS's own metadata (RFC 8414)
lists its endpoints. Rover checks that the metadata's `issuer` equals the
URL it asked, refuses an AS that does not advertise PKCE S256, and refuses
plain http anywhere except 127.0.0.1.

### 2. PKCE: why a stolen code is useless

The code comes back through the browser, so other things can see it: a
malicious app registered for the same redirect, browser history, a proxy
log. PKCE (RFC 7636) binds the code to the process that asked for it. Rover
makes a random **verifier** (32 bytes), sends only its SHA-256 (the
**challenge**) with the authorization request, and sends the verifier itself
only with the token request. The AS checks `SHA256(verifier) == challenge`.
Whoever steals the code does not have the verifier, and cannot compute it
from the challenge. `state` (another random value) does the same for the
redirect: the loopback page takes exactly one code, only with Rover's
state, then stops accepting; a guess gets 400, a replay 410.

### 3. The confused deputy

A deputy acts with someone else's authority. It is "confused" when an
attacker tricks it into using that authority for the attacker. The MCP
version: an agent (or its config) holds a bearer token for service A. If
the bridge forwarded the client's `Authorization` header, a hostile remote
B could simply ask for it, and Rover would hand A's token to B. Rover's
rule: **every header on a remote request is built by Rover from a fixed
list.** The client's config `headers` are not used (install leaves such an
entry alone and tells you to move the token into the keychain), nothing
from the environment is read, and the only values copied from a message
are the method, tool name and protocol version the spec says to mirror;
those are base64-encoded if they contain anything but plain ASCII, so a
tool named `"echo\r\nAuthorization: ..."` cannot inject a header.
Redirects are refused, not followed, so a `307` cannot carry Rover's own
token to another host either.

### 4. Token audience

An access token says who it is for (`aud`, "audience"). Rover asks for a
token for exactly this server (`resource=https://host/mcp`, RFC 8707) and
then checks what it got: if the token is a JWT, its `aud` must contain that
resource; if it is opaque and the AS echoed a `resource` or `aud`, that
must match; an opaque token without an echo is accepted (Rover cannot see
inside it; the server must check it, which the spec requires). A token for
another audience is refused and never stored. Why it matters: a token
valid for "everything at this AS" is a skeleton key. If a remote you
connect to is malicious, a narrowly-scoped token is all it can steal, and
it only works on that remote.

### 5. Tokens only in the keychain

`rover bridge login` stores one JSON record per bridge in the keychain
(service `rover`, account = the bridge name): access and refresh token,
expiry, client id, issuer, token endpoint, resource. Nothing goes to
ROVER_DIR, the audit log or stderr (the tests grep for the token). On
macOS go-keyring hands the secret to `/usr/bin/security` on its stdin, not
its argv. On Linux it needs a Secret Service on the D-Bus session bus;
Rover checks for one first without auto-launching a bus, and without one
it refuses. `--token -` reads stdin for the same reason argv is avoided:
every process on the machine can read argv with `ps`.

### 6. TLS 1.3 handshakes

TLS 1.3 needs one round trip. The client's `ClientHello` lists the cipher
suites and **key exchange groups** it supports and already includes a
**key_share** (a public key) for its favourite group. The server picks a
group, answers with its own key_share in `ServerHello`, and from that point
everything, including the server's certificate, is encrypted. Both sides
combine the two shares into the same secret without ever sending it. If
the server likes none of the offered shares it asks for another one
(HelloRetryRequest); if it supports none of the groups the handshake fails.
Rover requires TLS 1.3 (`MinVersion`), verifies the certificate, and logs
the group of every new connection.

### 7. Hybrid post-quantum key exchange

X25519 is a classical elliptic-curve exchange. A large quantum computer
could break it, and an attacker can record your traffic **now** and decrypt
it **later** ("harvest now, decrypt later"). ML-KEM-768 (FIPS 203) is a
post-quantum key encapsulation. **X25519MLKEM768** runs both and mixes the
two secrets, so an attacker must break both. Go 1.24+ offers it first by
default. `pq_required: true` (or `--pq-required`) sets `CurvePreferences`
to that group alone: a server or a middlebox that cannot do it makes the
handshake fail **before any MCP byte is sent**. That is fail closed: a
silent fallback to X25519 is exactly what a downgrade attacker wants.

## (c) Exercise it by hand

The lab uses the testauth build (fake approval dialog), the fake remote and
a throwaway ROVER_DIR. Login writes one item (service `rover`, account
`fake`) into your real login keychain; the last step deletes it.

```bash
umask 077
make build && go build -tags testauth -o /tmp/rover-ta ./cmd/rover
export ROVER_DIR=$(mktemp -d /tmp/rover-m11-XXXX)
./bin/fake-remote -as-http -sse -ca "$ROVER_DIR/ca.pem" &   # prints the remote URL
URL=https://127.0.0.1:54907/mcp                              # paste yours
/tmp/rover-ta policy init
printf '%s\n' \
  '@id("fake-list") permit (principal, action == Action::"list_tools", resource == Server::"fake");' \
  '@id("fake-echo") permit (principal, action == Action::"call_tool", resource == Tool::"fake/echo");' \
  > "$ROVER_DIR/config/policy.cedar"
sed -i '' 's/^mode: observe$/mode: enforce/' "$ROVER_DIR/config/config.yaml"
printf 'bridges:\n  fake:\n    url: %s\n    pq_required: true\n    ca_file: %s/ca.pem\n' "$URL" "$ROVER_DIR" >> "$ROVER_DIR/config/config.yaml"
/tmp/rover-ta --test-auth=allow policy apply
/tmp/rover-ta bridge login --name fake       # your browser opens; the fake AS approves at once
/tmp/rover-ta --test-auth=allow daemon &
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"manual","version":"0"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello over the bridge"}}}' \
  '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"delete_file","arguments":{"path":"/etc/hosts"}}}' \
  > /tmp/m11-in.jsonl
(cat /tmp/m11-in.jsonl; sleep 2) | /tmp/rover-ta bridge --name fake --url "$URL"
#   id 3: the echo; id 4: "Blocked by Rover policy ..." (isError)
#   stderr: "tls: 127.0.0.1 negotiated X25519MLKEM768"
grep -o '"findings":\["tls:[^"]*"\]' "$ROVER_DIR/state/audit.jsonl" | sort | uniq -c
/tmp/rover-ta doctor --remote | grep remote  # PASS remote fake: ... negotiated X25519MLKEM768
grep -rl access_token "$ROVER_DIR"           # nothing: the token is only in the keychain
security delete-generic-password -s rover -a fake; kill %1 %2
```

### Lab: see the key_share group in Wireshark (macOS)

1. Install Wireshark (`brew install --cask wireshark`) and open it. Allow
   it to capture when asked (it installs "ChmodBPF").
2. Capture on **Loopback: lo0** (for the fake remote), or on your Wi-Fi
   interface (en0) for a public MCP server you trust.
3. Display filter: `tls.handshake.type == 1` (ClientHello) or
   `tls.handshake.type == 2` (ServerHello). For the fake remote add
   `&& tcp.port == 54907` (your port).
4. Run `/tmp/rover-ta doctor --remote` (it only handshakes) or the bridge.
5. Open the ClientHello: Transport Layer Security > Handshake Protocol >
   Extension: supported_groups lists what Rover offers; Extension:
   key_share shows the shares actually sent. Look for
   `X25519MLKEM768 (0x11ec)`: its key_exchange is 1216 bytes (an ML-KEM-768
   encapsulation key plus 32 bytes of X25519), against 32 for X25519.
6. Open the ServerHello: Extension: key_share > Key Share Entry: Group is
   the group the server chose (1120 bytes back for the hybrid).
7. Now bridge to a server that only does X25519 without `pq_required`: the
   ServerHello shows `x25519 (0x001d)` and doctor prints WARN. With
   `pq_required: true` the ClientHello offers only 0x11ec, an alert
   follows, and no HTTP request is ever sent.

## (d) Three attacks to try against it

### Attack 1: the remote demands the client's bearer (expect: never sent)

Put a token in the client config entry's `headers` and in the environment
(`export AUTHORIZATION="Bearer stolen"`), and put
`"_meta":{"authorization":"Bearer stolen"}` in a `tools/call`. Let the fake
remote record every header it receives (`Remote.Headers()` in
internal/bridge/bridgetest). Expect: `rover install` leaves the entry with
`headers` alone and says why; the remote only ever sees Rover's own
`Authorization` (or none). TestNoClientCredentialsForwarded is this attack.

### Attack 2: a token for a different audience (expect: refused, not stored)

Set `Audience: "https://other.example"` on the fake AS (bridgetest.AS) and
log in. Expect: "the authorization server issued a token for a different
audience; refusing it", and no keychain item. TestAudienceMismatchRejected
is this attack. Then think about an opaque token with no echo: it is
accepted. Why is that the right call, and who must check it?

### Attack 3: a downgrade to classical TLS (expect: fail closed)

Serve the fake remote with `tls.Config{CurvePreferences:
[]tls.CurveID{tls.X25519}}` and bridge to it with `--pq-required`.
Expect: "pq_required: the server did not agree to X25519MLKEM768; nothing
was sent", the client gets a JSON-RPC error, and the server's handler never
runs (TestPQRequiredFailsClosed). Without `--pq-required` it works and the
audit log says `tls:X25519`. Then remove `--pq-required` from the client
config while config.yaml says `pq_required: true`: it stays on.

## (e) Five explain-back questions

1. PKCE sends the challenge in the browser redirect and the verifier only
   to the token endpoint. Why does stealing the code from the browser not
   help an attacker, and why must the method be S256, not "plain"?
2. What is a confused deputy? Describe how a bridge that forwarded the
   client's `Authorization` header would become one, and the places Rover
   makes sure it does not.
3. Rover asks for `resource=<server URL>` and then checks the token's
   `aud`. What does each half protect against on its own?
4. In a TLS 1.3 handshake, what is in a key_share, who sends one, and why
   does a hybrid X25519MLKEM768 share defeat "record now, decrypt later"?
5. Why does `pq_required` fail the handshake instead of falling back to
   X25519 with a warning, and why is the setting in config.yaml stronger
   than the `--pq-required` flag in the client's config?
