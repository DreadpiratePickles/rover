# M9 · Approvals and OS authentication

**Goal:** some calls are fine only if a human says so right now: push to
`main`, send this email, delete that bucket. Until M9 Rover could only allow
or block. M9 adds a third answer, **hold**: the call waits while Rover asks
you, and only your answer in the operating system's own authentication
dialog (Touch ID or your password on macOS, polkit on Linux) lets it
through. The same dialog now guards everything that changes Rover itself:
`rover policy init`, `rover policy apply`, `rover pin approve`, `rover pin
reset`, `rover install`/`uninstall`'s changes to the tamper watch, and
switching enforce back to observe. Lesson focus: human-in-the-loop design,
confused deputies, "the agent can click anything it can reach", platform
authentication, PID-reuse races, and why there is no trust on first use for
policies.

## (a) What was built

- **Hold.** A permit annotated `@rover_require("approval")` (YAML:
  `require: approval`) now makes the policy answer `hold` in enforce mode.
  In observe mode it forwards and logs `would_deny` with reason
  `approval_required`: observe never waits for a human.
- **`internal/approve`**: the `Request`, `Decision`, `Authenticator` and
  `Prompter` types and the flow (`Flow`) roverd runs for every held call:
  1. record the approval in the `approvals` bucket as `pending`;
  2. if the agent app said `capabilities.elicitation` in `initialize`, send
     it an `elicitation/create` with id `rover-<uuid>`; a decline denies, an
     accept does **not** approve (it only means "show me the dialog");
  3. send a desktop notification with a link to the details page;
  4. show the OS dialog: `Rover [a1b2c3d4]: allow <client> to run <server>.<tool> (args: <names>)?`
     (the bracket is the approval id's start, also on the notification, the
     page and in `rover approvals list`, so concurrent approvals can be told
     apart; at most 5 per session and 20 in all, beyond which a new one is
     denied at once: `too many pending approvals`);
  5. yes forwards; cancel, failure, or no answer within
     `approvals.timeout_s` (default 120 s) denies with the §5.1 isError body
     `approval denied` / `approval timed out`.
  The record ends `allowed`, `denied` or `timed_out` with the method and
  time. Arguments are never written to disk (M10 has not built redaction
  yet).
- **Authenticators.** macOS: `LocalAuth`, cgo + Objective-C calling
  `LAContext evaluatePolicy:LAPolicyDeviceOwnerAuthentication`, answered
  over a channel, cancelled (`invalidate`) when the approval times out.
  Linux: `Polkit`, running `pkcheck --action-id org.rover.approve
  --process <pid>,<start-time>,<uid> --allow-user-interaction`; exit 0
  allows, exit 2 (no authentication agent: a headless box) denies and is
  logged `no_auth_agent`, anything else denies. Everywhere else, and in a
  macOS binary built without cgo: `Deny`.
- **Details page** (`internal/approve/page`): `127.0.0.1:<random port>`,
  exactly one route, `GET /approval/<id>?t=<128-bit token>`. Looks like a
  cwm menu (plan §4.7): white, black bold 14px sans-serif, one 1px black
  box, the heading `approval»<id>«`, one entry per line, the state line in
  cwm's urgent `#FC8814` while pending. No script, form, input, link, image
  or external anything. Arguments only with `approvals.show_args: true`,
  and the page says so. Screenshot: `docs/images/approval-page.png`.
- **Inject.** A new ipc frame, `inject {raw}`, lets roverd push its own
  request (the elicitation) to the wrapper, which writes it to the agent
  side. The agent's reply comes back on the client-to-server pipe; the
  wrapper sends it to roverd and **never** to the server, and roverd
  matches it to the elicitation of the same session.
- **Approved policy.** roverd loads only a policy whose hash (of the policy
  file, `config.yaml`, the schema and the normalizers file, read from a
  private snapshot so nothing can be swapped between hashing and loading)
  is the one recorded in `approved_policy`. `rover policy init` asks for the
  dialog too (in the CLI); without a yes it writes the files and records
  nothing. `rover policy apply` is only a messenger:
  it checks the files load and sends roverd an admin frame `policy_apply
  {hash}`; **roverd itself** shows the dialog (`Rover: approve policy <hash>
  (mode <m>)?`) and only on its yes records the hash and loads the policy.
  The reply says `allow`, `deny` or `no_auth_agent`. With no roverd running
  the CLI runs the same code in-process, so the CLI shows the dialog. A
  switch from enforce to observe is just another `policy_apply`. A bare
  SIGHUP reloads only the policy already approved. Only the latest
  approved hash counts, so rolling back to an older approved policy needs
  the dialog too. `rover doctor` checks hash on disk against the approved one.
- **Cancellation.** A `notifications/cancelled` for a held request stops
  its approval (the dialog closes) and releases it as a block, reason
  `cancelled by client` (plan §4.3).
- **Pins.** `rover pin approve` and `rover pin reset` show the dialog in the
  process that makes the change (roverd, or the CLI when no roverd runs);
  the pin's method is recorded as `osauth:<method>`.
- **`rover install --polkit`** prints (never runs) the `sudo` commands that
  install the polkit action, which uses `auth_self` and never `_keep`.

## (b) Design decisions and the attacks they prevent

### 1. Human in the loop, done so the human is really in it

An approval that a machine can give is not an approval. So every surface in
M9 is sorted into two kinds: things that **inform** (the notification, the
details page, the elicitation in the agent app) and the one thing that
**decides** (the OS dialog). Informing surfaces may at most say no: a
decline in the agent app denies, because a "no" from anyone is safe to
honour. Nothing but the dialog can say yes. And no answer is a no: the
timeout denies (D8), so a held call never drifts into "allowed because
nobody looked".

### 2. Confused deputies

A confused deputy is a program with authority that is tricked into using it
for someone else. Rover is the deputy here: it holds the power to release
calls. The classic way to confuse it is to make the request *look* like it
came from the right person. That is why the elicitation reply is matched by
an id only Rover chose (`rover-<random uuid>`), only from the session it was
sent to, and why a server that sends its own request with a `rover-` id is
refused (`rover_id_reserved`): otherwise a malicious server could ask the
agent app a question of its own and have the answer counted as yours.

### 3. The agent can click anything it can reach

An agent with a shell can run `curl`, `rover`, `kill` and `echo > file`. So:

- the details page has no POST, no button, no form; the only route is a
  GET that reads. A wrong token gets **404, not 403** (a 403 would confirm
  the id exists), compared in constant time, and the Host header must be
  the page's own address, which stops DNS rebinding from a web page;
- the CLI cannot approve by itself: `rover policy apply`, `rover pin
  approve` and `rover pin reset` only ask; the process that makes the
  change (roverd) shows the OS dialog, and the dialog wants a finger or a
  password the agent does not have. Sending the admin frame from a script
  is exactly as powerless as running the CLI;
- a file cannot approve a policy: editing `policy.cedar` and sending
  SIGHUP only logs `policy reload REFUSED` and audits it. There is no
  token or "approved" marker file anywhere for the agent to forge.

**Why the dialog moved into roverd.** A first version let the CLI show the
dialog and then leave roverd a one-time "nonce" file in `run/`. But the
agent can write to `run/` too, so it could forge the nonce and skip the
dialog: the gate was theatre. The lesson: a proof of a human must be
checked by the process that acts on it, never handed over in something the
agent can also write.

**This depends on the spike (b).** If macOS will not show the dialog for
roverd (a background process started with setsid), roverd answers every
`policy apply`, pin change and held call with deny, reason `no
interactive authentication from the daemon; see the spike notes`. The
fallback is the signed helper app `RoverAuth.app`, which needs Bobby's
Apple Developer account (plan §9). With no roverd running, `rover policy
apply` runs in the CLI (case (a)) and still works.

### 4. Platform authentication

- **macOS, LocalAuthentication.** `LAPolicyDeviceOwnerAuthentication`
  tries Touch ID (or a paired Apple Watch) and always offers "Use
  Password...". 🔍 We checked the SDK headers (`LAPublicDefines.h`,
  `LAContext.h`, `LARequirement.h`): there is **no password-only policy**;
  the policies are biometrics, device owner, companion/watch,
  biometrics-or-companion and wrist detection, and `LARequirement` offers
  biometry with a passcode fallback. So, per the plan's fallback, Touch ID
  and the password are both accepted (both prove the device owner is
  present, D9) and there is no `auth.require_password`. LocalAuthentication
  needs cgo: the release builds use `CGO_ENABLED=0` today, so a release
  macOS binary denies every approval, and `rover daemon` says so at
  startup (`WARN approvals will always deny: ...`). Darwin release builds
  need cgo on macOS runners (M14; noted in `.goreleaser.yaml`).
- **Linux, polkit.** The action file uses `allow_active: auth_self`: you type
  your own password each time. Never `auth_self_keep`, which would let one
  approval silently cover the next few minutes of agent calls. A headless
  machine has no polkit agent, pkcheck exits 2, and the call is denied
  (`no_auth_agent`). That is the right answer for CI.
- **Whose pkcheck?** roverd runs `/usr/bin/pkcheck` (else `/bin/pkcheck`),
  never "pkcheck" looked up on PATH: an auto-started roverd used to inherit
  the wrapper's environment, which the agent controls, and a fake pkcheck
  first on PATH that exits 0 would approve everything. An auto-started
  roverd now gets a minimal environment (`PATH=/usr/bin:/bin:/usr/sbin:/sbin`,
  HOME, ROVER_DIR, the XDG and locale variables, what notifications need)
  and nothing else: no LD_PRELOAD, no DYLD_*, no tokens.

### 5. PID-reuse races and the start-time form

polkit is asked "may process P do this?". A PID alone is a weak name:
processes die and PIDs are reused, so between Rover choosing the PID and
polkit checking it, a different process could hold that number. `pkcheck
--process pid,start-time,uid` names one process for its whole life; the
start time comes from field 22 of `/proc/<pid>/stat`, counted after the
*last* `)` because the command name may itself contain `) `. A new process
with the old PID has a different start time and polkit refuses.

### 6. No trust on first use for policies

Tool pins (M4) trust the first tools/list a server sends: there is no human
to ask at that moment and nothing better to compare with. A first version of
M9 did the same for the first policy: `rover policy init` recorded it
without a dialog, "only while no policy was ever approved". That window was
not small at all: `kill roverd; rm state/state.db; rover policy init
--force` reopened it whenever an agent wanted, and the restarted roverd ran
whatever the agent wrote. So now:

- `rover policy init` shows the dialog (in the CLI, since roverd is not
  running); without a yes the files are written, nothing is recorded, and
  roverd runs in enforce with **no** policy until `rover policy apply`;
- roverd distrusts its own database at start when it cannot be the one it
  wrote: state.db recreated or without any approval while the audit log has
  history, or an approval newer than the newest audit entry (roverd audits
  every approval it records, so a newer record came from someone else). It
  then loads no policy, stays in enforce, audits a `state` `reset` entry and
  sends a notification, and `rover doctor` fails.

### 7. Why the page looks like cwm

The details page copies cwm, OpenBSD's calm window manager (plan §4.7):
one face, one size, black on white, one 1px border, no icons, no colour but
the urgent orange of a pending approval. That restraint is a security
property here. There is nothing to misread (no logo, no green "safe" badge
for a server to imitate in its tool name), nothing to click by accident (no
buttons at all), and nothing an agent could forge convincingly: a fake page
would look exactly as plain, and it still could not approve, because only
the system dialog can. The PR needs a side-by-side screenshot of the page
(`docs/images/approval-page.png`) next to cwm; that cwm screenshot has to
come from Bobby (an xterm under cwm), since none was available here.

## (c) Exercise it by hand

The spike first; it decides whether roverd itself can show the dialog.

### The spike (PENDING: Bobby runs it; only when you are at the Mac)

```bash
make spike-auth                 # builds bin/spike-auth; builds only, shows nothing
bin/spike-auth direct           # (a) from a terminal
bin/spike-auth daemon           # (b) as a child of a setsid'd daemon started by a wrapper
```

Each prints `about to show the macOS authentication dialog` and waits for
Enter before anything appears. For each of (a) and (b), run it three times:
answer with Touch ID, then with "Use Password..." and your password, then
press Cancel. Record for each run: did the dialog appear (yes/no), which
app name and text it showed, the printed `ok=`, `method=`, `error code=`
and `message=` lines, and the `sid=` line (in (b) it must differ from your
shell's, proving the setsid). If you have no Touch ID (or close the lid
with an external keyboard), run (a) once more and record the code. Expected
codes: `-2` user cancel, `-1` failed, `-4` system cancel, `-1004` not
interactive.

If (b) shows no dialog or returns `-1004`: held calls, pin changes and
`rover policy apply` cannot be approved while roverd runs (roverd denies
them with `no interactive authentication from the daemon; see the spike
notes`), and the plan's fallback is a signed helper app (`RoverAuth.app`)
that roverd launches. That needs your Apple Developer account (plan §9), so
it was not built; stop and tell me what (b) printed. Until then, stop
roverd and run `rover policy apply` (it then runs in the CLI, case (a)).

### Approvals

```bash
export ROVER_DIR=$(mktemp -d /tmp/rover-m9-XXXX)
./bin/rover policy init         # writes the files and asks the dialog; say no for now
                                # ("nothing was recorded ...")
cat > "$ROVER_DIR/config/policy.cedar" <<'EOF'
@id("echo-list") permit (principal, action == Action::"list_tools", resource == Server::"echo");
@id("ask-echo") @rover_require("approval")
permit (principal, action == Action::"call_tool", resource == Tool::"echo/echo");
EOF
sed -i '' 's/^mode: observe/mode: enforce/' "$ROVER_DIR/config/config.yaml"
./bin/rover doctor | grep policy-approval     # FAIL: not yet applied
./bin/rover policy apply                       # the dialog: approve it
./bin/rover doctor | grep policy-approval     # PASS
./bin/rover daemon &                           # roverd in the foreground of this shell
./bin/rover wrap --name echo -- ./bin/echo-server
{"jsonrpc":"2.0","id":1,"method":"tools/list"}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}
{"jsonrpc":"2.0","id":3,"method":"ping"}
```

The ping answers at once while id 2 waits. A notification appears with the
page link (or run `rover approvals list`); open it, then answer the dialog. Yes: id 2 returns `hi`. Cancel:
`Blocked by Rover policy (rule ask-echo): approval denied`. Wait 120 s
instead: `approval timed out`. `rover log` shows the `approval` entries.

## (d) Three attacks to try against it

### Attack 1: curl the page with every method (expect: nothing changes)

Take the link from the notification and try `curl -X POST`, `PUT`,
`DELETE`, `PATCH`, `OPTIONS`, `HEAD`, a made-up `-X APPROVE`, the path with
`/approve` added, the id without the token, a wrong token, the token twice,
and `-H 'Host: evil.example'`. Every one is 405 or 404, and the dialog is
still waiting. (Test: `TestEveryOtherRequestIsRefusedAndChangesNothing`.)

### Attack 2: forge an elicitation answer from a server (expect: refused)

A malicious server sends the agent `{"jsonrpc":"2.0","id":"rover-<anything>",
"method":"elicitation/create",...}` hoping the agent's "accept" counts for a
held call. roverd blocks the request (`rover_id_reserved`, -32001 to the
server). Even an "accept" Rover did receive does not approve: only the OS
dialog does. (Test: `TestElicitationDeclineDeniesAndReplyIsSwallowed`.)

### Attack 3: edit policy.cedar and SIGHUP without apply (expect: refused)

```bash
echo 'permit (principal, action, resource);' > "$ROVER_DIR/config/policy.cedar"
kill -HUP $(cat "$ROVER_DIR/run/roverd.pid")
```

roverd logs `policy reload REFUSED: the policy files changed ...` and keeps
the approved policy; `rover doctor` reports `FAIL policy-approval TAMPERED`;
restarting roverd loads no policy at all and blocks every policed call.
Then forge an approval: write `run/apply.nonce` naming your file's hash
(the old design read it) and SIGHUP again: still refused, nothing reads it.
And send `{"type":"admin","op":"policy_apply","hash":"<hash>"}` to the
socket yourself: roverd shows *its* dialog, and only your yes there
loads it. (Tests: `TestTamperedPolicyIsNotLoadedAndDoctorReportsIt`,
`TestForgedNonceFileDoesNothing`, `TestPolicyApplyFrameAloneApprovesNothing`.)

## (e) Five explain-back questions

1. Why may the elicitation in the agent app deny a call but never approve
   one, while the OS dialog may do both?
2. The details page answers a wrong token with 404. What would a 403 tell
   an attacker, and why does the comparison take the same time either way?
3. What race does `pkcheck --process pid,start-time,uid` close that
   `--process pid` leaves open?
4. Why does roverd hash `config.yaml` and not just `policy.cedar`, and why
   does it hash a private copy rather than the files themselves?
5. Tool pins trust the first tools/list on first use, but policies no
   longer do. What attack did that close, and how does roverd notice a
   state.db it did not write?
