# M2 · Cedar policy engine

**Goal:** give roverd something to decide with. Until now `decide` said
"forward" to everything. After M2 it asks a policy, and the answer can be
block. Lesson focus: decision point versus enforcement point, default deny,
attribute-based access control (ABAC), why normalisation happens before the
policy, and parser differentials again.

## (a) What was built

### Two halves: who decides, who enforces

The gateway has two jobs that are easy to blur. One job is to **decide**
whether a message is allowed. The other is to **enforce** the decision by
actually forwarding, replacing or dropping bytes.

- The **decision point** is roverd. `internal/policy` holds the logic. It never
  touches a socket. You hand it one message and some facts, and it hands back
  an `Outcome`: forward or block, a reason, and the ids of the rules that
  decided.
- The **enforcement point** is the wrapper. `rover wrap` receives the verdict
  and obeys it. It has no policy and no opinion.

Keeping them apart pays off twice. The decision can be tested with plain
function calls, thousands of times, with no processes. And the enforcement
code stays small enough to read in one sitting, which matters because it is
the code an attacker would most like to confuse.

### Cedar in one paragraph

Cedar is a policy language from AWS. A request has four parts: a **principal**
(who is asking), an **action** (what they want to do), a **resource** (what it
is done to) and a **context** (facts about this particular request). A policy
is either a `permit` or a `forbid`, with a scope on the principal, action and
resource, and optional `when` / `unless` conditions over the context. Three
rules decide everything. If no `permit` matches, the answer is **deny**
(default deny). If any `forbid` matches, the answer is deny even when a permit
also matches (**forbid wins**). Otherwise the answer is allow. There is no
ordering of rules and no "first match", so adding a rule can never quietly
change the meaning of the rules above it.

### The entity model Rover uses

The schema is `policy/schema.cedarschema`. Rover reads every policy against it
when it loads.

| Cedar thing | In Rover |
| --- | --- |
| Principal: `Client` | The agent app, named by `clientInfo.name` from `initialize` (for example `claude-code`). |
| Resource: `Server` | One wrapped MCP server, named by `rover wrap --name`. |
| Resource: `Tool in [Server]` | One tool. Its id is `server/tool`, for example `Tool::"echo/read_file"`. Because the tool is `in` its server, `resource in Server::"echo"` matches every tool of that server. Attributes: `name` and `labels`. |
| Resource: `Resource in [Server]` | An MCP resource, for `resources/read`. |
| Action `call_tool` | A `tools/call` from the agent. |
| Action `list_tools` | A `tools/list` from the agent. |
| Action `read_resource` | A `resources/read` from the agent. |
| Action `server_sampling` | A `sampling/createMessage` request from the **server** to the client. |
| Action `server_elicitation` | An `elicitation/create` request from the **server** to the client. |

The **context** is where "attribute-based" comes from. Every request carries
`session` (has this session touched private data, seen untrusted content, and
how many calls), `device`, `time`, `detection`, and, for `call_tool` only, two
records built from the call itself: `args` (the converted arguments) and
`norm` (the normalised arguments). `device` and `detection` are all zero until
later milestones fill them in.

### A tools/call from bytes to verdict

```
 agent line (bytes)
      |
      v
 rover wrap  ----- decide frame ----->  roverd
 (enforcement)                          |
      ^                                 | 1. parse the JSON-RPC envelope
      |                                 | 2. policed method? (five of them)
      |                                 | 3. convert.Args: whole message ->
      |                                 |      Cedar Record, with limits and
      |                                 |      duplicate-key check
      |                                 | 4. normalize.Apply: path/url/...
      |                                 |      -> context.norm
      |                                 | 5. build entities + context
      |                                 |      (session flags, labels, time)
      |                                 | 6. cedar.Authorize
      |                                 | 7. forbid errored? count as fired
      |                                 | 8. observe mode? would_deny
      |                                 | 9. write audit entry
      |                                 v
      |                           Outcome{forward | block, reason, rules, response}
      |                                 |
      +<------- verdict ---------------+
      |
  forward: send the ORIGINAL bytes on
  block:   write the response (isError result) back to the agent
```

In words:

1. roverd parses the line with `jsonrpc.Parse`. Only five message kinds are
   judged: `tools/call`, `tools/list`, `resources/read` from the agent, and
   `sampling/createMessage`, `elicitation/create` from the server. Everything
   else (`initialize`, `ping`, notifications, results) is forwarded unjudged
   in M2. `policy.Policed` is the function that says which.
2. `convert.Args` turns the **whole message** into a Cedar Record. It enforces
   limits (depth 16 for the arguments, 4096 keys, 1 MiB per string) and refuses
   duplicate keys at any depth. Numbers that are not plain integers become
   strings with a finding. `null` keys are dropped.
3. `normalize.Apply` looks up which arguments of this tool need a normaliser
   (from `normalizers.yaml`), and produces `context.norm.<arg>`: for a path,
   the cleaned, symlink-resolved path and one `under_<root>` boolean per root
   in `config.yaml`.
4. roverd builds the Cedar request: the Client and Server entities, the Tool
   entity with its labels from `config.yaml`, and the context.
5. `cedar.Authorize` evaluates every policy and returns allow or deny plus the
   ids of the policies that decided.
6. The result is turned into an `Outcome`. A block carries a ready-made
   response for the requester (next section). In observe mode a deny becomes a
   forward marked `would_deny`.
7. roverd writes the audit entry (action, reason, rule ids, findings) and only
   then answers the wrapper, as in M1.

### What the agent sees

- **A blocked `tools/call`** gets a normal JSON-RPC **result** with
  `isError: true` and text such as `Blocked by Rover policy (rule
  hide-read-file): forbid hide-read-file. Do not retry this call; tell the user
  what you were trying to do.`
- **A blocked `tools/list` or `resources/read`** gets a JSON-RPC **error**
  `-32001`, message `blocked by rover: <reason>`.
- **A blocked server-to-client request** (sampling, elicitation) gets the same
  `-32001` error, sent back to the server, and is never forwarded to the
  client.
- **`tools/list` hiding.** A tool named by a hide rule is removed from the
  server's `tools/list` reply before the agent sees it. Every other tool stays
  listed.

### Observe versus enforce

`config.yaml` has `mode: observe` (the default, plan D6: learn, then enforce)
or `mode: enforce`. In observe mode a deny is **forwarded** and recorded as
`would_deny`, so you can run a new policy against real traffic and read
`rover log` before anything is blocked. Malformed or hostile arguments are
blocked even in observe mode: they are not "unpermitted", they are broken.

### The `rover policy` commands

| Command | What it does |
| --- | --- |
| `rover policy init [--force]` | Writes `policy.cedar` (the starter), `config.yaml`, `schema.cedarschema` and `templates/*.cedar` into the config directory. Refuses to overwrite anything unless `--force`. |
| `rover policy validate [--policy FILE]` | Loads a policy exactly as roverd would (parse, type-check against the schema in strict mode) and lists each policy id with its effect. Also loads `config.yaml`. Exit 1 on any error. |
| `rover policy test <audit.jsonl>` | Replays logged messages through the **current** policy in enforce mode and prints the decision and deciding rules for each. Needs a log written with `rover daemon --log-bodies`; entries without a body are counted as skipped. |
| `rover policy apply` | Asks the running roverd to reload `config.yaml` and `policy.cedar`. A bad file is rejected and the previous policy stays in force. |

`rover policy init` writes five templates: `filesystem-project-only`,
`github-readonly`, `fetch-allowlist`, `deny-sampling` and `trifecta-guard`.
They are examples to read and copy from, not active until you paste them into
`policy.cedar`.

## (b) Design decisions and the attacks they prevent

### 1. Default deny: "no permit" is a block

**Attack prevented:** the unknown tool. A server adds a tool tomorrow, or a
prompt-injected agent calls a tool nobody thought about. With an
allow-by-default gateway every such tool is allowed until someone notices. With
default deny, a tool is blocked until a human writes a `permit` that names it.
The starter policy shows the stance: it contains only two `forbid` rules and
permits nothing, so a fresh install blocks every `tools/call`.

Two related guards. If **no policy loads at all** (missing file, syntax error,
bad permissions on the file), roverd blocks every policed message with reason
`no_policy` and logs `NO POLICY LOADED`. Messages that are not policed
(`initialize`, `ping`) still flow, so the server can start. And `Load` is
all-or-nothing: one bad policy fails the whole load, so there is never a
half-loaded set.

Proof: `TestStarterDeniesServerRequestsAndToolCalls`
(`internal/policy/decide_test.go`) asserts that the starter blocks a
`tools/call` with reason `no permit matched` and no rule ids.
`TestNoPolicyBlocksToolCalls` (`cmd/rover/policy_test.go`) and
`TestNoPolicyBlocksPolicedMessagesOnly` (`internal/daemon/policy_test.go`)
cover the no-policy case through the real daemon and in isolation.
`TestLoadRejectsBadPolicies` (`internal/policy/templates_test.go`) lists the
policies that must fail to load.

### 2. Forbid beats permit

**Attack prevented:** the broad permit that swallows a safety rule. You write
`permit (principal, action == Action::"call_tool", resource in
Server::"filesystem")` to get work done, and later add a rule to protect one
dangerous tool. If the order of rules mattered, the broad permit written first
could win. In Cedar order never matters: any matching `forbid` decides. A
safety rule you add today cannot be undone by a permit that already exists.

Proof: `TestPermitLetsEchoThroughButReadFileIsBlockedWithRuleID`
(`internal/policy/decide_test.go`) loads a permit for the whole `echo` server
and a forbid for `echo/read_file`. Echo goes through, `read_file` is blocked,
and the response names the forbid. `TestLabelsAndSessionReachThePolicy` does
the same with the trifecta forbid on top of a permit.

### 3. Normalise before the policy sees the path

**Attack prevented:** path traversal that fools a string match. Cedar compares
strings. It never touches the filesystem, so `like "/home/me/projects/*"`
happily matches `/home/me/projects/../.ssh/id_rsa`. The text starts with the
right prefix. The file the server opens is somewhere else. This is a parser
differential in a new coat: the policy engine and the filesystem disagree about
what a path means.

The fix is to ask the filesystem's question in Go, **before** Cedar runs. For
each path argument `internal/policy/normalize` cleans the path, makes it
absolute against the first root, follows symlinks one component at a time (even
when the tail does not exist yet, so `write_file` to a new file works), and
checks containment with `filepath.Rel`, so `projects2` is not inside
`projects`. It hands the policy a plain fact: `context.norm.path.under_projects`.
The policy then decides on what the server will really open.

When the normaliser cannot be sure, it fails closed. A NUL byte, a
percent-encoded `.`, `/`, `\` or NUL, a symlink loop or an unreadable path is
a hard reject: reason `norm_reject`, blocked even in observe mode. A
look-alike separator is kept as a literal character (so it is just an odd
file name, never a traversal) and a finding `path_lookalike_separator` is
recorded.

The plan §5.3 acceptance matrix. Each row is a path that must not end up
inside `projects`. "What it does" is what the running system did in the lab
(part (c)); "Test" is the case name in `TestPathEscapeMatrix`
(`internal/policy/normalize/normalize_test.go`).

| Attack path | What it does | Test case |
| --- | --- | --- |
| `../outside/secret` | Resolved against the root, lands outside. `under_projects` is false, no permit matches: `no permit matched`. | `dot-dot relative` |
| `%2e%2e/outside/secret` | Never URL-decoded here, but a server that decodes would see `..`, so it is rejected outright: `norm_reject`. | `percent-encoded dotdot` |
| `<root>/escape/secret` where `escape` is a symlink to `outside` | The symlink is followed. The real path is outside. `under_projects` false: `no permit matched`. | `symlink escape` |
| `<root>/../.ssh` | `..` is cleaned away. The path is `.ssh` next to the root, outside it: `no permit matched`. | `root dot-dot ssh` |
| `projects` + U+2215 + `app` (a division slash that looks like `/`) | Kept as a literal character, so it is one strange file name outside the root. Finding `path_lookalike_separator`. `no permit matched`. | `U+2215 lookalike` |
| `<root>/app/notes.txt` followed by a NUL byte | A NUL ends a C string, so a server could open a different file than the one the policy saw. Rejected: `norm_reject`. | `trailing NUL` |

The same test also covers upper-case `%2E%2E`, a dangling symlink and U+FF0F.
Two tests show the matrix reaching the real decision, not just the normaliser:
`TestNormalisedPathDecidesProjectAccess` (an escape and a relative `../` are
blocked, a path inside the root is forwarded with the rule id) and
`TestNormaliserRejectBlocks` (a NUL is blocked in observe mode). Siblings with
a shared prefix are covered by `TestPathSiblingWithSharedPrefixIsNotUnder`,
and an array with one escaping path by `TestPathSetOneEscapeIsNotAllUnder`.
`FuzzPath` throws random paths at the normaliser.

### 4. Conversion limits and duplicate keys (parser differentials, again)

**Attack prevented 1: two values for one key.** JSON does not say which of two
identical keys wins. Some parsers keep the first, some the last. If Rover read
`{"path":"app/notes.txt","path":"../outside/secret"}` as the harmless first
value while the MCP server read the second, the policy would approve a call
that does something else. Rover refuses the call (`args_duplicate_keys`)
instead of picking a winner. This is the A1 lesson, now applied to arguments.
Rover applies the check to the **whole message**, not just `arguments`: a
duplicate `"name"` in `params` would let the policy judge `echo` while the
server runs `read_file`.

**Attack prevented 2: truncation.** Limits (depth 16, 4096 keys, 1 MiB per
string) are a **deny**, not a cut. If Rover trimmed an oversized document to
fit, the policy would judge a smaller document than the one forwarded, and an
attacker could hide the dangerous part past the cut. Exceeding a limit is
`args_too_complex`. Invalid UTF-8 is `args_invalid_json`, because
`encoding/json` would silently replace bad bytes with U+FFFD and make two
different byte strings look identical.

The converter walks the stream with `json.Decoder` tokens, so these checks
happen while parsing and never on a fully built structure.

Both are blocked **even in observe mode**: they are not "something the policy
did not permit", they are evidence the message is hostile or broken.

Proof: `TestArgsDeniesBadInput` and `TestArgsLimitBoundaries`
(`internal/policy/convert/convert_test.go`) check each rule at its boundary.
`TestConversionFailuresBlockEvenInObserveMode` and
`TestDuplicateToolNameInEnvelopeBlocks` (`internal/policy/decide_test.go`)
check observe mode and the envelope (since the review, a duplicate in
`params` is caught even earlier, as `invalid_jsonrpc`). `TestDepthSixteenArgumentsAreAllowed`
pins the exact limit. `FuzzArgs` fuzzes the converter and `FuzzDecide` the
whole decision.

### 5. A blocked tools/call is a result; a blocked sampling request is an error

**Attack prevented:** the retry loop. If a blocked call came back as a
JSON-RPC error, many clients show the model a generic failure, and the model
tries again, or tries a cleverer route. A result with `isError: true` is part
of the tool conversation. The model reads "Blocked by Rover policy (rule X):
reason. Do not retry this call; tell the user what you were trying to do", and
the useful thing for it to do is to tell the human. The block text speaks to
the model on purpose.

A server-to-client request is different. The one reading the reply is a server,
not a model, and the message must not reach the client at all. So Rover sends
JSON-RPC error `-32001` back to the server and forwards nothing. The starter
policy forbids sampling (a server driving your model with prompts you never
see) and elicitation (a server asking you for information in a dialog that
looks like the client's).

The id is copied into the reply as the original bytes. Re-encoding it would
change `"req-<2>"` into escaped form and the client would not match the reply
to its request.

Proof: `TestPermitLetsEchoThroughButReadFileIsBlockedWithRuleID` asserts the
exact response bytes, including the `<` in the id. `TestStarterDeniesServerRequestsAndToolCalls`
checks that sampling and elicitation get `-32001` with `blocked by rover:
forbid starter-deny-sampling`. `TestListToolsAndResourcesReadBlockWithJSONRPCError`
covers `tools/list` and `resources/read`.

### 6. Hiding is cosmetic; blocking is the control

**Attack prevented:** the tool you cannot see but can name. Removing a tool
from `tools/list` stops the model being tempted by it. It does not stop a model
(or an injected prompt) that already knows the name from calling it. So a hide
rule is a `forbid` first, and the hiding is a courtesy on top.

The shape is strict. `@rover_hide("true")` is accepted only on an
unconditional `forbid` for one concrete tool, for every principal, with no
`when` or `unless`:

```
@id("hide-read-file") @rover_hide("true")
forbid (principal, action == Action::"call_tool", resource == Tool::"echo/read_file");
```

A conditional forbid cannot hide, because `tools/list` has no call context to
test the condition against. Such a tool stays listed and is judged at call
time. A misspelt `@rover_hdie` is a load error, not a silent no-op.

Filtering happens on the server's reply. roverd rebuilds the `tools/list`
result from the original bytes of every kept tool and every other member, so
only the hidden entries change. The reply comes from the server, so it is
parsed strictly: a duplicate key, a tool without a name or trailing data makes
roverd **replace the whole reply with an error** rather than forward something
that may still list the hidden tool. A second, uncorrelated result with no
matching request is filtered too, so a server cannot send an unfiltered copy.

Proof: `TestHiddenToolIsAlsoBlockedWhenCalled`
(`internal/policy/hide_test.go`) shows the same rule hides and blocks.
`TestFilterToolsListDropsHiddenToolAndKeepsOtherBytes` checks the byte
preservation. `TestFilterToolsListRejectsAmbiguousResults` and
`TestUnfilterableToolsListIsReplacedWithError` /
`TestUncorrelatedResultIsFilteredToo` (`internal/daemon/policy_test.go`) cover
the strict parse. `TestHiddenToolIsBlockedAndFilteredFromList` runs it through
the daemon. `TestPolicyEndToEnd` (`cmd/rover/policy_test.go`) runs it through
the real wrapper and daemon binaries.

### 7. Observe mode and its exceptions

**Attack prevented (by design, not by code): the all-or-nothing rollout.** A
gateway that blocks from the first minute gets switched off by the first
annoyed user. Observe mode lets you collect `would_deny` entries, run `rover
policy test` against them, fix the policy, and only then switch to `enforce`.
That is plan D6.

But observe mode must not be a back door. Three things still block there:

- Conversion failures: `args_duplicate_keys`, `args_too_complex`,
  `args_not_object`, `args_invalid_json`.
- Normaliser rejects: `norm_reject`.
- Anything on the decision path that goes wrong (a bad direction, a bad tool
  name, an internal error).

Pin violations and high-severity detections will join this list when M4 and M5
exist (plan D6 says they are never observe-only).

Any `mode` value other than `observe` is treated as `enforce`, and an unknown
value in `config.yaml` is a load error. A typo must not switch enforcement off.

Proof: `TestObserveModeForwardsDenyAsWouldDeny` and
`TestConversionFailuresBlockEvenInObserveMode` (`internal/policy/decide_test.go`),
`TestObserveModeAuditsWouldDeny` (`internal/daemon/policy_test.go`),
`TestInvalidConfigsAreRefused` (`internal/config/config_test.go`).

### 8. A closed-record schema, and "an erroring forbid counts as fired"

This is a limitation, and you should understand it before you rely on the
templates.

Cedar has no "open" record type. `context.args` cannot be "whatever the tool
sent". So `schema.cedarschema` lists the argument names a policy may use:
`path`, `url`, `owner`, `repo` under `args`, and a fixed set of normalised
arguments (`path`, `source`, `destination`, `repo_path`, `paths`, `files`,
`url`) under `norm`. A policy that mentions `context.args.query` fails
validation at load. That is the safe direction: a typo cannot silently become
"never matches".

The fields are declared **required**, so a policy can write
`context.norm.path.under_projects` without a `has` guard. The price: when a
call does not send that argument, reading it is an **evaluation error**. Cedar
then skips that policy. What happens next depends on the effect:

- An erroring `permit` simply does not apply. Default deny covers it.
- An erroring `forbid` might have fired if the data had been there. Rover
  counts it **as fired** (`outcome` in `internal/policy/decide.go`). The call
  is blocked, and the block reason names the rule id (`forbid <id>`, with
`(evaluation error)` added when the erroring forbid was the only reason).

Honest consequence: a forbid like `when { context.norm.url.host == "evil.example" }`
blocks **every** call that has no `url` argument, even `echo`. It over-blocks.
It never under-blocks, which is the right way to be wrong, but it is a real
usability cost. Until a fix, guard optional arguments yourself:
`context.norm has url && context.norm.url.host == "evil.example"`.

The fix is planned for M3 (the YAML to Cedar compiler), which will generate the
schema and the rules together. Until then, `config.yaml` itself says: "a new
root name also needs a matching under_<name> attribute in schema.cedarschema".
The shipped schema knows one root name, `projects`.

Proof: `TestErroringForbidCountsAsFired` (`internal/policy/decide_test.go`)
and `TestBuiltRequestsMatchTheSchema` (`internal/policy/request_test.go`).

### 9. TODO(M9): `rover policy apply` is not protected, and an agent with a shell can use that

Say it plainly, as plan §0.6 and the threat model ask. Today, reloading policy
works like this: `rover policy apply` reads `run/roverd.pid`, checks roverd
answers on its socket, and sends it SIGHUP. roverd reloads `config.yaml` and
`policy.cedar`. A reload that fails keeps the old policy.

There is **no authentication** on that path, and none that could work yet. A
manipulated agent with a shell tool runs as you. It can edit `policy.cedar`
(the file is `0600`, owned by you, and so is the agent), run `rover policy
apply` or just `kill -HUP $(cat $ROVER_DIR/run/roverd.pid)`, and the policy it
wrote is live. It can also flip `mode` from `enforce` to `observe` the same
way, or rather it could: since the independent review, a running roverd
refuses a reload from enforce to observe (see "What the independent review
changed" below), though it can still rewrite the policy itself. The permission
checks in `loadAll` stop *other* users, not *you*. This is
the "manipulated agent attacking Rover through its shell tool" row of the
threat model: partially in scope, and M2 does not close it.

What M9 changes (plan M9 and D9): `rover policy apply` and switching `mode`
from enforce to observe require an OS authentication dialog (Touch ID or
password on macOS, polkit on Linux) that nothing the agent can reach can
answer, and roverd refuses to load a policy file whose hash is not in
`approved_policy`. Editing `policy.cedar` then does nothing until a human
approves it. M2 leaves a visible `TODO(M9)` in `cmd/rover/policy.go` and
`cmd/rover/daemon.go`, and `rover policy apply` prints
`TODO(M9): this is not yet protected by OS authentication` every time, so
nobody can forget.

Proof that the weakness is real is Attack 3 in part (d). Proof that the happy
path works: `TestApplyReloadsAndKeepsPreviousOnError` and
`TestReloadSwapsPolicy`.

### 10. Session flags from labels: the seed of the M8 trifecta rule

**Attack prevented (later): data theft by prompt injection.** The dangerous
pattern needs three things in one session: access to private data, exposure to
untrusted content, and a way to send data out. Any one is fine. All three
together is the "lethal trifecta".

M2 plants the seed. `config.yaml` can label tools:

```
labels:
  filesystem:
    read_file: [reads_private]
  fetch:
    fetch: [reads_untrusted, egress]
```

Each **forwarded** `tools/call` of a labelled tool updates the session's flags
(`NextFlags` in `internal/daemon/session.go`): `reads_private` sets
`touched_private`, `reads_untrusted` sets `saw_untrusted`. A blocked call sets
nothing, because a blocked read never touched data. The flags are session-wide,
shared across servers under one agent (M1), and arrive in the context as
`context.session`. The `trifecta-guard` template then forbids any tool labelled
`egress` once both flags are true. M8 builds the full rule on top; M2 only
shows that the plumbing works.

Proof: `TestLabelsAndSessionReachThePolicy` (`internal/policy/decide_test.go`)
and `TestReadsPrivateToolSetsTouchedPrivateForTheNextDecision`
(`internal/daemon/policy_test.go`).

### What the independent review changed

After M2 was written, a separate reviewer attacked it. Four findings changed
the code; each now has a test that failed before the fix and passes after.

**C1: keys that differ only in case (a parser differential, a third time).**
Go's `encoding/json` matches JSON keys to struct fields *ignoring case*, and if
two keys match the same field the **last** one wins. Rover's message
classifier (`jsonrpc.Parse`) and the tools/list filter used it. Cedar, the
argument converter and most MCP servers match keys **exactly**. Two lines from
the review show what that meant:

```
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","Name":"read_file","arguments":{}}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","Method":"ping","params":{"name":"read_file","arguments":{}}}
```

In the first, the policy was asked about `echo` and permitted it, but a server
that decodes with `encoding/json` reads the last match, `Name`, and runs
`read_file`. In the second, Rover's classifier read the last match, `Method`,
saw a harmless `ping`, and never asked the policy at all, while the server read
`method` and ran `tools/call`. The same trick on a server reply
(`"result"` plus `"Result"`) slipped a hidden tool past the tools/list filter.

The fix is a strict object reader, `jsonrpc.Object`. It keeps every key
exactly as written and refuses an object with a duplicate key, or with two keys
that are equal ignoring case (`name`/`Name`, and even `k` and the Kelvin sign
`K`). `Parse` uses it for the envelope and for `params`, accepts only the six
member names JSON-RPC defines, and marks anything else `invalid` with a reason.
roverd blocks an invalid line in both directions, in every mode, with or
without a policy, with reason `invalid_jsonrpc: ...`. If the line still has a
usable `id` and `method`, the sender gets JSON-RPC error `-32600 Invalid
Request` instead of waiting forever; anything else is dropped. The tools/list
filter and the splice that rebuilds the reply use the same reader, and the
argument converter now treats case-colliding keys as duplicates too. The lesson
is the one from A1 and decision 4, sharpened: refusing duplicates is not
enough when the parsers disagree about what counts as "the same key".

Proof: `TestParseRejectsKeyDifferentials` and `TestObjectRejectsAmbiguousOrBadInput`
(`internal/jsonrpc/strict_test.go`), `FuzzParse` (now also checks that a valid
line re-parses to the same kind, method, id and tool),
`TestKeyDifferentialsAreBlockedAsInvalid` (`internal/daemon/invalid_test.go`,
through the real socket, in enforce, observe and no-policy modes),
`TestUnfilterableToolsListIsReplacedWithError`,
`TestFilterToolsListRejectsAmbiguousResults`, `TestInvalidLinesBlockInEveryMode`
and the new rows of `TestArgsDeniesBadInput`.

**H1: `~` in a path.** A relative path is joined onto the first root, so
`~/.ssh/id_rsa` became `<projects>/~/.ssh/id_rsa`, which is "under projects".
But many servers expand a leading `~` to your home directory, and `~bob` to
Bob's. `~/projects/../.ssh` is then simply `~/.ssh`. Rover cannot know what a
server does with `~`, so a path starting with `~` is now refused outright
(`norm_reject`, with `path_tilde` in the error). Proof: the two new rows of
`TestPathEscapeMatrix`, `TestPathTildeIsRejected` and
`TestTildePathIsDeniedUnderProjectsPermit`.

**H2: a known bug in a dependency.** `golang.org/x/text` v0.30.0, which the
path normaliser uses for Unicode normalisation (NFC), has GO-2026-5970: some
invalid input makes it loop forever. An attacker controls the paths, so that
is a denial of service against roverd. It is upgraded to v0.41.0, the newest
release that still builds with Go 1.25. Proof: `make vuln` (govulncheck)
reported the call path from `normPath` before and is clean after.

**M2: deleting config.yaml switched enforcement off.** With no `config.yaml`,
Rover uses observe mode (D6, learn first). So `rm config.yaml && rover policy
apply` quietly turned an enforcing roverd into one that only logs. Now a
*reload* may never move from enforce to observe: roverd keeps the previous
policy and mode and logs `refused: switching enforce -> observe needs OS
authentication (M9)`, and `rover policy apply` prints that rule because it
cannot see roverd's answer. Starting roverd with no `config.yaml` still means
observe. Proof: `TestReloadRefusesEnforceToObserve` and
`TestReloadAllowsObserveToEnforce` (`internal/daemon/policy_test.go`).

Smaller fixes from the same review: `rover policy validate` now runs the
official `cedar validate` when the Cedar CLI is installed and says
`cedar CLI not installed; skipped` otherwise (`TestPolicyValidateRunsCedarCLI`
and friends); it refuses the same too-open files roverd refuses, including the
normalizers file `config.yaml` names
(`TestPolicyValidateAndDaemonCheckFilePermissions`); and server names may only
use `A-Za-z0-9_.-`, so a name like `evil/echo` cannot blur the
`<server>/<tool>` id (`TestServerNames`, `TestWrapRejectsBadServerName`).

### A note on speed

A policy check sits in the path of every message. `TestDecideLatency`
(`internal/policy/bench_test.go`) loads 200 policies and fails if the 99th
percentile of `Decide` is 5 ms or more. `BenchmarkDecide200` reports it.

## (c) Exercise it by hand

Everything below was run on macOS in a throwaway directory. Timestamps, session
ids and pids will differ from yours.

### Build and write the starter files

```bash
cd /path/to/rover            # your checkout of the m2 branch
make build
export ROVER_DIR=/tmp/rover-lab-m2
./bin/rover policy init
```

Expected:

```
wrote /tmp/rover-lab-m2/config/policy.cedar
wrote /tmp/rover-lab-m2/config/config.yaml
wrote /tmp/rover-lab-m2/config/schema.cedarschema
wrote /tmp/rover-lab-m2/config/templates/deny-sampling.cedar
wrote /tmp/rover-lab-m2/config/templates/fetch-allowlist.cedar
wrote /tmp/rover-lab-m2/config/templates/filesystem-project-only.cedar
wrote /tmp/rover-lab-m2/config/templates/github-readonly.cedar
wrote /tmp/rover-lab-m2/config/templates/trifecta-guard.cedar
next: edit policy.cedar (it permits nothing yet), run `rover policy validate`, then `rover policy apply`.
config.yaml starts in observe mode: denials are logged as would_deny, not blocked.
```

Look at what it wrote, and at the permissions:

```bash
ls -l "$ROVER_DIR/config" "$ROVER_DIR/config/templates"
cat "$ROVER_DIR/config/policy.cedar"
./bin/rover policy validate
```

Every file is `-rw-------`. The validate output is:

```
starter-deny-sampling  forbid
starter-deny-elicitation  forbid
ok: 2 policies (schema: /tmp/rover-lab-m2/config/schema.cedarschema)
```

Run `./bin/rover policy init` a second time. It refuses and lists every file
(`refusing to overwrite existing files (use --force)`).

### Switch to enforce and write a small policy

```bash
sed -i '' 's/^mode: observe/mode: enforce/' "$ROVER_DIR/config/config.yaml"
grep '^mode' "$ROVER_DIR/config/config.yaml"      # mode: enforce

cat > "$ROVER_DIR/config/policy.cedar" <<'EOF'
@id("starter-deny-sampling")
forbid (principal, action == Action::"server_sampling", resource);

@id("starter-deny-elicitation")
forbid (principal, action == Action::"server_elicitation", resource);

@id("echo-list")
permit (principal, action == Action::"list_tools", resource == Server::"echo");

@id("echo-call")
permit (principal, action == Action::"call_tool", resource == Tool::"echo/echo");

@id("hide-read-file") @rover_hide("true")
forbid (principal, action == Action::"call_tool", resource == Tool::"echo/read_file");
EOF

./bin/rover policy validate
```

Expected: five lines of `id  effect`, then `ok: 5 policies (schema: ...)`.

### Terminal 1: run the daemon by hand

```bash
export ROVER_DIR=/tmp/rover-lab-m2
./bin/rover daemon --log-bodies
```

`--log-bodies` records full message bodies so that `rover policy test` can
replay them. Bodies can hold secrets until M10 adds redaction; this is a lab
directory. You should see:

```
... roverd policy loaded (mode enforce)
... roverd listening on /tmp/rover-lab-m2/run/roverd.sock (pid NNN, bodies=true)
```

### Terminal 2: wrap the echo server and paste lines

```bash
export ROVER_DIR=/tmp/rover-lab-m2
./bin/rover wrap --name echo -- ./bin/echo-server
```

Paste these lines one at a time. The first is `initialize`:

```
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/hosts"}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi rover"}}}
```

What you get back:

- For `tools/list` (id 2): only `echo`. The echo server really has two tools;
  `read_file` was removed from the reply.

  ```
  {"jsonrpc":"2.0","id":2,"result":{"tools":[{"description":"Returns the text you send it.","inputSchema":{"properties":{"text":{"type":"string"}},"required":["text"],"type":"object"},"name":"echo"}]}}
  ```

- For `read_file` (id 3), at once, from Rover, and the server never sees it.
  On stderr you also get `[rover] blocked request tools/call: forbid hide-read-file`.

  ```
  {"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"Blocked by Rover policy (rule hide-read-file): forbid hide-read-file. Do not retry this call; tell the user what you were trying to do."}],"isError":true}}
  ```

- For `echo` (id 4): `{"jsonrpc":"2.0","id":4,"result":{"content":[{"text":"hi rover","type":"text"}]}}`

Press Ctrl-D to end the session.

### Read the log

```bash
./bin/rover log
./bin/rover log --verify
```

`rover log` shows, among eight lines:

```
... echo  agent  -> server request  forward  id=2 tools/list rules=echo-list
... echo  agent  -> server request  block    id=3 tools/call [read_file] rules=hide-read-file (forbid hide-read-file)
... echo  agent  -> server request  forward  id=4 tools/call [echo] rules=echo-call
... echo  server -> agent  result   replace  id=2 reply to tools/list ... (hidden: read_file)
```

The `replace` line is the filtered `tools/list` reply. `--verify` prints
`.../audit.jsonl: 8 entries in 1 file(s), chain intact, anchor matches`.

### Replay the log through the policy

```bash
./bin/rover policy test "$ROVER_DIR/state/audit.jsonl"
```

```
replaying /tmp/rover-lab-m2/state/audit.jsonl in enforce mode (config.yaml says enforce)
2026-10-09 17:29:41  echo         tools/list                   forward rules=echo-list (logged: forward)
2026-10-09 17:29:41  echo         tools/call read_file         block   rules=hide-read-file (logged: block)
2026-10-09 17:29:41  echo         tools/call echo              forward rules=echo-call (logged: forward)
3 replayed: 2 forward, 1 block; 5 not policed; 0 skipped (no body)
```

The last column, `(logged: ...)`, is what actually happened at the time.
When you change the policy and re-run `policy test`, a difference between the
decision and the logged action is exactly what your edit would change. If the
daemon ran without `--log-bodies`, entries have no body and are counted as
`skipped (no body)`; the command tells you to use `--log-bodies`.

### Apply a change

Add a comment line to `policy.cedar`, then:

```bash
./bin/rover policy apply
```

```
reload requested (pid NNN); roverd.log says whether it succeeded
note: a running enforce daemon refuses to switch to observe; roverd.log then says
  "refused: switching enforce -> observe needs OS authentication (M9)" (restart roverd to change it)
TODO(M9): this is not yet protected by OS authentication
```

Terminal 1 prints `policy reloaded (mode enforce)`. Now break the file
(`echo 'permit (oops' >> "$ROVER_DIR/config/policy.cedar"`) and apply again:
terminal 1 prints `policy reload FAILED, keeping the previous policy: ...`.
The old policy is still in force, and a wrapped echo still works. Remove the
bad line before going on, and run `./bin/rover policy validate` to be sure.

### Observe mode

```bash
sed -i '' 's/^mode: enforce/mode: observe/' "$ROVER_DIR/config/config.yaml"
./bin/rover policy apply
```

Terminal 1 refuses: `policy reload refused: switching enforce -> observe needs
OS authentication (M9); keeping the previous policy and mode`. A reload may
tighten the mode, never loosen it (see "What the independent review changed").
You are the human here, so restart roverd instead: Ctrl-C in terminal 1, then
`./bin/rover daemon` again. It prints `policy loaded (mode observe)`. Start a new wrapper in terminal 2
and send `initialize` and the `read_file` line again:

```bash
./bin/rover wrap --name echo -- ./bin/echo-server
```

This time `read_file` is **forwarded**: the echo server reads `/etc/hosts` and
you get its contents back. That is observe mode doing what it says, and why you
only use it with a policy you are still learning. Look at the log:

```bash
./bin/rover log | tail -4
grep would_deny "$ROVER_DIR/state/audit.jsonl" | jq '{action, reason, rule_ids, tool}'
```

```
... agent  -> server request  would_deny id=3 tools/call [read_file] rules=hide-read-file (would_deny)
```

```
{"action":"would_deny","reason":"would_deny","rule_ids":["hide-read-file"],"tool":"read_file"}
```

Note that `tools/list` is **still** filtered in observe mode: the hidden tool
stays out of the list even though a direct call would be forwarded. Switch
back to enforce before the next exercise.

### Exercise: a root, a normaliser and a filesystem-style permit

The echo server's `read_file` has a `path` argument. The built-in normaliser
mappings are for the official `filesystem` server, not for `echo`, so you also
tell Rover to treat `echo`'s `read_file` path as a path.

```bash
cd "$ROVER_DIR"
mkdir -p projects/app outside
echo "project note" > projects/app/notes.txt
echo "TOP SECRET"   > outside/secret
ln -s "$ROVER_DIR/outside" projects/escape

cat > config/config.yaml <<EOF
mode: enforce
roots:
  projects: $ROVER_DIR/projects
normalizers: normalizers.yaml
EOF

cat > config/normalizers.yaml <<'EOF'
servers:
  echo:
    read_file: {path: path}
EOF

cat > config/policy.cedar <<'EOF'
@id("echo-list")
permit (principal, action == Action::"list_tools", resource == Server::"echo");

@id("echo-call")
permit (principal, action == Action::"call_tool", resource == Tool::"echo/echo");

@id("read-projects-only")
permit (principal, action == Action::"call_tool", resource == Tool::"echo/read_file")
when { context.norm.path.under_projects };
EOF

./bin/rover policy validate && ./bin/rover policy apply
```

The root name `projects` becomes the attribute `under_projects`, which the
schema already declares. A root with another name would need a matching
attribute in `schema.cedarschema` (decision 8).

Now send calls. Paste into a new wrapper in terminal 2 (after `initialize`), or
use this helper to print lines you can paste:

```bash
mk() { printf '{"jsonrpc":"2.0","id":%s,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"%s"}}}\n' "$1" "$2"; }
mk 10 "$ROVER_DIR/projects/app/notes.txt"
mk 11 "../../etc/hosts"
```

The first is inside the root. It is permitted and you get
`{"jsonrpc":"2.0","id":10,"result":{"content":[{"text":"project note\n","type":"text"}]}}`.

The second is a relative path with `../..`. Rover resolves it against the first
root, finds it outside, and no permit matches:

```
{"jsonrpc":"2.0","id":11,"result":{"content":[{"type":"text","text":"Blocked by Rover policy (rule none): no permit matched. Do not retry this call; tell the user what you were trying to do."}],"isError":true}}
```

`(rule none)` is honest: no rule decided, default deny did. Run
`./bin/rover log | tail` and find `(no permit matched)` on that entry.

## (d) Three attacks to try against it

Stay in `mode: enforce` with the policy from the last exercise, unless a step
says otherwise. Use the `mk` helper from part (c) and a fresh wrapper per
batch, with `initialize` first.

### Attack 1: every row of the path matrix against the root policy

Send one line per row of the table in decision 3:

```bash
mk 21 "../outside/secret"
mk 22 "%2e%2e/outside/secret"
mk 23 "$ROVER_DIR/projects/escape/secret"
mk 24 "$ROVER_DIR/projects/../.ssh"
mk 25 "$ROVER_DIR/projects∕app/notes.txt"          # the slash here is U+2215
mk 26 "$ROVER_DIR/projects/app/notes.txt"'\u0000'   # JSON escape for a NUL byte
```

Expected, from `./bin/rover log | grep 'tools/call' | grep -v reply`:

```
block  id=21 tools/call [read_file] (no permit matched)
block  id=22 tools/call [read_file] (norm_reject)
block  id=23 tools/call [read_file] (no permit matched)
block  id=24 tools/call [read_file] (no permit matched)
block  id=25 tools/call [read_file] (no permit matched)
block  id=26 tools/call [read_file] (norm_reject)
```

None of them reads `TOP SECRET`. Now think about the two reasons. Why are rows
22 and 26 `norm_reject` while the others are `no permit matched`? Which of the
six would a plain `like "/tmp/rover-lab-m2/projects/*"` rule on `context.args.path`
have let through? (Rows 23 and 24: both start with that text.) Check by writing
that rule and running `rover policy test` on the log. Row 25 shows what the
normaliser noticed: run
`grep '"id":25' "$ROVER_DIR/state/audit.jsonl" | head -1 | jq '{action, reason, findings}'`
and look for `path_lookalike_separator`. Then create a sibling that shares a prefix
(`mkdir "$ROVER_DIR/projects2"; echo x > "$ROVER_DIR/projects2/x"`) and read
`$ROVER_DIR/projects2/x`. It is blocked, which shows why containment is checked
component by component and not with a string prefix.

For a challenge, try to find a seventh row. Ideas: a very long path, a path
that is a symlink to a symlink, `projects/./app/../../outside/secret`. Each
should end in `no permit matched` or `norm_reject`. If one reads the secret,
you found a bug, and `FuzzPath` missed it.

### Attack 2: duplicate keys and depth 17, in observe mode

Switch to observe. A reload cannot do that any more, so restart roverd
(Ctrl-C in terminal 1, then `./bin/rover daemon`):

```bash
sed -i '' 's/^mode: enforce/mode: observe/' "$ROVER_DIR/config/config.yaml"
```

Send a plain escape first as a control. It is forwarded as `would_deny`:

```bash
mk 31 "../outside/secret"
```

Then the two hostile messages (paste as written):

```
{"jsonrpc":"2.0","id":32,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"app/notes.txt","path":"../outside/secret"}}}
{"jsonrpc":"2.0","id":33,"method":"tools/call","params":{"name":"echo","arguments":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":1}}}}}}}}}}}}}}}}}}}
```

Expected, even though the mode is observe:

```
would_deny id=31 tools/call [read_file] (would_deny)
block      id=32 tools/call [read_file] (args_duplicate_keys)
block      id=33 tools/call [echo] (args_too_complex)
```

and the reply for id 32 reads `Blocked by Rover policy (rule none):
args_duplicate_keys. ...`. Message 33 has 17 levels of `"a"`. Remove one level
and re-send: it is allowed, because 16 is the limit
(`TestDepthSixteenArgumentsAreAllowed`).

Questions to answer from what you see: what would a parser that keeps the
first `path` have shown the policy? A parser that keeps the last? Which one
does Python's `json.loads` use? Which does Go's `encoding/json`? Why does
Rover not need to know? Then try a duplicate in a place that is not
`arguments`: put `"name":"read_file","name":"echo"` inside `params`. It
is still refused, now as `invalid_jsonrpc` with error `-32600`, and
`TestDuplicateToolNameInEnvelopeBlocks` is the test. Then try the review's
version: `"name":"echo","Name":"read_file"`. Before the review this one got
through.

### Attack 3: call the hidden tool, then rewrite the policy

Part A. Put the hide-rule policy from the first exercise back (the
`hide-read-file` forbid), set `mode: enforce`, apply, and in a fresh wrapper
send `tools/list`. `read_file` is not listed. Now call it anyway:

```
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/hosts"}}}
```

It is blocked with `rule hide-read-file`. Hiding changed what the model sees;
the forbid is what stopped the call. Edit the policy to remove
`@rover_hide("true")` but keep the forbid: `read_file` reappears in the list
and is still blocked. Remove the forbid too and `read_file` is still blocked, now by default deny
(`no permit matched`), because nothing permits it.

Part B. Now behave like a manipulated agent that has a shell. Pretend you are
the agent and have no special access: you can only run commands as your own
user.

```bash
echo 'permit (principal, action, resource);' > "$ROVER_DIR/config/policy.cedar"
./bin/rover policy validate
./bin/rover policy apply
```

`validate` prints `policy0  permit` and `ok: 1 policies`. Terminal 1 prints
`policy reloaded (mode enforce)`. Send a `read_file` for
`$ROVER_DIR/outside/secret` from a fresh wrapper. The reply is
`{"jsonrpc":"2.0","id":2,"result":{"content":[{"text":"TOP SECRET\n","type":"text"}]}}`. The file
you were protecting is returned. Every control in this lesson was just
undone with three commands. You can also skip the CLI:
`kill -HUP "$(cat $ROVER_DIR/run/roverd.pid)"` does the same.

Discuss:

- Why does `rover policy apply` work for this? (Same uid. The `0600` file mode
  and the socket peer check both pass for you, and for any process you run.)
- Which M1 decision says the same thing about `kill`? (Decision 3 there:
  killing roverd is denial of service. This is worse. Here the attacker
  does not stop Rover, it *rewrites* it.)
- What does M9 change? The plan's answer: applying a policy, and moving from
  enforce to observe, will need an OS authentication dialog the agent cannot
  answer, and roverd will refuse a `policy.cedar` whose hash a human did not
  approve. After M9, the rewrite in this step does nothing until a person
  taps their finger. What is the remaining weakness? (An attacker who can click
  that dialog, or who talks the human into approving. That is the M9 lesson.)

Put the good policy back, apply, and stop the daemon when you are done.

### Clean up

```bash
# terminal 1: Ctrl-C
rm -rf /tmp/rover-lab-m2
```

## (e) Five explain-back questions

1. Draw the M2 picture from memory: agent, wrapper, roverd, `internal/policy`,
   the MCP server. Mark the decision point and the enforcement point. Say why
   `Decide` returns an `Outcome` instead of forwarding anything itself, and
   name one benefit for testing and one for security.
2. Explain default deny and "forbid wins" to someone who has only used
   allow-lists with an order of rules. A server adds a tool called
   `delete_everything` tomorrow: what happens, and why? Then: you write a broad
   `permit` for the filesystem server and a narrow `forbid` for one tool.
   Which wins, and does the order in the file matter?
3. A colleague proposes `permit ... when { context.args.path like
   "/home/me/projects/*" }` for the filesystem server. Show two inputs that
   pass that rule and read outside `projects`. Explain what Rover does instead
   (name the three things the path normaliser does before Cedar runs) and why
   `%2e%2e` and a trailing NUL are `norm_reject` instead of a quiet
   `under_projects = false`.
4. State the parser-differential problem for `{"path":"a","path":"b"}`. Why
   does Rover deny the call rather than pick the first or the last value? Why
   is exceeding a depth or size limit a deny rather than a truncation? Why do
   both still block in observe mode, and which other failures do the same?
5. Two questions on honesty. (i) A blocked `tools/call` returns a result with
   `isError: true`, a blocked `sampling/createMessage` returns error `-32001`,
   and a hidden tool is still blocked when called: explain each choice in one
   sentence. (ii) Describe in your own words how an agent with a shell can
   weaken the policy today, which commands it would run, why file permissions
   and the peer-credential check do not stop it, and what M9 adds. Then name
   the one case in the decision-8 limitation where Rover blocks more than it
   should, and how to write the forbid so it does not.
