# M1 · roverd and thin wrappers

**Goal:** move every decision, and the only copy of the audit log, out of the
per-server wrapper and into one long-lived process, `roverd`. Lesson focus:
daemons, Unix sockets, peer credentials, file locks, tamper-evident logs, and
why "kill roverd" is denial of service rather than a bypass.

## (a) What was built

In A1 the proxy did everything itself: read a line, write it to the log,
forward it. That worked for one server. It does not work for the milestones
ahead, where a decision about server B depends on what the agent just did on
server A, and where a tool's pinned description has to be remembered between
runs. State like that must live in exactly one place, or the agent can get a
different answer by starting a different wrapper.

So M1 splits the gateway in two.

```
 Claude Code (pid 4242)
   │ stdin/stdout                 │ stdin/stdout
   ▼                              ▼
 rover wrap --name fs          rover wrap --name github        (thin)
   │  hello {client_pid: 4242}    │  hello {client_pid: 4242}
   │  decide ──▶ verdict          │  decide ──▶ verdict
   ▼                              ▼
 ┌──────────────── roverd (one per user) ─────────────────────┐
 │  sessions keyed by client pid ──▶ 4242 = {fs, github}      │
 │  decide(): observe, write audit entry, answer "forward"    │
 │  state/audit.jsonl (hash chain)   state/state.db (bbolt)   │
 │  run/roverd.sock (0600)           run/roverd.pid           │
 └────────────────────────────────────────────────────────────┘
   ▲
   │ stdin/stdout
 MCP server (filesystem, github, ...)
```

- **roverd** (`internal/daemon`, started by `rover daemon`) listens on a Unix
  socket, accepts one connection per wrapper, and owns the audit log. In M1 its
  whole decision is "observe, record, forward". M2 onward replaces the body of
  `decide` with policy, pinning and detection. The plumbing stays.
- **`rover wrap`** is now thin. For each line it reads it does four things:
  send a `decide` to roverd, wait for the `verdict`, apply it (forward the
  original bytes, write a replacement, or answer a block), move on. It holds
  no policy and no state. `internal/proxy` is that loop and nothing else.
- **Auto-start.** If no daemon answers, the wrapper takes an exclusive `flock`
  on `run/autostart.lock`, launches `rover daemon` detached, and retries for
  three seconds. If that fails it exits without starting the MCP server.
- **Sessions are keyed by the agent's pid.** The wrapper sends its parent pid
  (`os.Getppid()`, the Claude Code or Cursor process that spawned it) in the
  hello. Every wrapper under one agent shares one `Session`. That is what makes
  the cross-server checks in M8 possible.
- **Hash-chained audit log.** Each entry carries the SHA-256 of the previous
  one. `rover log --verify` walks the chain and names the first line that no
  longer fits.
- **bbolt state file** (`internal/state`, `state/state.db`) with the buckets
  later milestones need (`pins`, `observations`, `approved_policy`,
  `approvals`, `grants`, `meta`) and a schema version. In M1 nothing is stored
  in it yet, but its file lock already stops a second daemon.
- **Bodies are off by default.** `rover daemon --log-bodies` turns them on.
  Until M10 adds redaction, the safe default is metadata only.

Paths follow plan §4.2 (`~/Library/Application Support/Rover/{state,run}` on
macOS). `ROVER_DIR=/some/dir` puts everything under one directory instead,
which is how tests and this lab keep away from real state.

## (b) Design decisions and the attacks they prevent

### 1. Fail closed: no roverd, no server

The wrapper connects to roverd **before** it starts the MCP server. If it
cannot connect and cannot auto-start, it prints `cannot reach roverd,
refusing to start ...` and exits non-zero. The child command never runs.

Why this order matters: if the server started first, a window would exist in
which the agent could talk to an unguarded server. "Allow and log" is the
failure mode of most monitoring tools. Rover does the opposite.

Proof: `TestWrapperRefusesToStartServerWithoutDaemon` in
`cmd/rover/main_test.go` wraps a shell script that touches a marker file, sets
`ROVER_TEST_NO_AUTOSTART=1`, and asserts the marker never appears.
`TestFailsClosedWithoutVerdict` in `internal/proxy/proxy_test.go` covers the
same rule mid-session: an error from `Decide` ends the pump and forwards
nothing.

### 2. Who is on the other end? Ask the kernel

Before reading a single byte from a new connection, roverd calls
`ipc.PeerUID`. On Linux that is `getsockopt(SO_PEERCRED)`; on macOS it is
`getsockopt(LOCAL_PEERCRED)` at level `SOL_LOCAL`. Both return the credentials
of the process that called `connect(2)`, recorded by the kernel at that
moment. The peer cannot put a different uid in a message, because there is no
message: the answer comes from the kernel's own process table, not from
anything the peer sent. If the uid differs from roverd's, the connection is
closed without a welcome.

Any platform without such a call fails closed (`peer_other.go` returns an
error, and an error is a refusal).

Proof: `TestPeerUIDIsOurOwnOverLoopbackSocket` in `internal/ipc/peer_test.go`
checks the real syscall against `os.Getuid()`. `TestCheckPeerRejectsOtherUser`
checks the comparison. In `internal/daemon/daemon_test.go`,
`TestOtherUserIsRefusedBeforeHello` injects a peer uid of 1000 into a daemon
running as 501 and asserts the dial fails, and `TestPeerCredentialErrorIsRefused`
asserts that "cannot tell" is also a refusal.

The documented limit (plan §3): a process running **as you** passes this
check. That includes a manipulated agent using its shell tool. Rover resists
that adversary; it cannot stop it.

### 3. Killing roverd is denial of service, not a bypass

Put decisions 1 and 2 together. A same-user attacker can `kill` roverd. What
does that gain? Every wrapper's `Decide` returns an error on the next message,
the pump stops, the wrapper kills its MCP server and exits. New wrappers either
auto-start a fresh daemon, whose log continues the chain, or refuse to run.
At no point is a message forwarded without a verdict, and a verdict is only
issued after the audit entry is on disk. The attacker gets silence, not a
free call. Silence is loud: the agent stops working and the human notices.

Proof: the two tests under decision 1, plus `TestAuditFailureBlocks` (decision
10).

### 4. The socket is 0600 inside a 0700 directory

`Server.Listen` chmods the socket to `0600` after binding, and `paths.Ensure`
refuses to run if any Rover directory is reachable by group or others. The
daemon also sets `umask 077` so nothing it creates is ever looser.

This is a second fence, not the main one. Directory permissions stop other
users from even knocking; the peer check is what stops root, which ignores
file permissions. Two independent controls with different failure modes.

Unix socket paths have a hard limit: `sun_path` is 104 bytes on macOS and the
BSDs, 108 on Linux. `paths.SocketPath` keeps the preferred path if it is under
`MaxSocketPath` (100) and otherwise falls back to a short `0700` directory
under `os.TempDir()` named with the uid and a hash of the run directory, so
two profiles never share a fallback socket.

Proof: `TestSocketIsOwnerOnly` (daemon), `TestEnsureRefusesLooseDirectory`,
`TestSocketPathFallsBackWhenTooLong` and `TestSocketPathUsesRunDirWhenShort`
(`internal/paths/paths_test.go`).

### 5. One flock, one daemon

Claude Code starts all its MCP servers at once, so ten wrappers may find no
daemon in the same millisecond. Without coordination, ten of them would each
launch `rover daemon`. `connect` takes an exclusive `flock(LOCK_EX)` on
`run/autostart.lock`, re-dials (someone may have started roverd while we
waited), and only then spawns. The others block on the lock, then find a
daemon on their re-dial.

A file lock is a kernel object tied to an open file descriptor, so it is
released automatically if the holder crashes. A "lock file exists" convention
would not be.

Proof: `TestWrapperAutoStartsDaemon` in `cmd/rover/main_test.go` starts a
wrapper with no daemon, gets a reply, reads `run/roverd.pid`, signals the pid
to confirm it is alive, and checks `state/roverd.log` says `listening on`.

### 6. The hash chain

Each audit entry has `prev` (the previous entry's hash) and `hash` (SHA-256 of
this entry's canonical JSON with the `hash` field empty). `audit.Verify` walks
the file and, at each line, checks three things: `prev` equals the hash it
just computed, `hash` equals the hash of the contents, and the bytes on disk
equal the canonical re-encoding of the parsed entry.

What this detects: any edit, any dropped line, any reordering, anywhere in the
file, located to the first line that no longer fits. Even inserting a space
fails, because the canonical-form check compares bytes, not meaning.

What it does **not** detect: an attacker who rewrites the whole file from the
edited line to the end, recomputing every hash. The chain makes a surgical
edit detectable; it does not make the file unforgeable. Attack 2 in part (d)
makes you feel exactly where that line is.

The chain continues across rotation. At 50 MB (`DefaultRotateBytes`) the file
is renamed aside with a timestamp and a new one started; the first entry of
the new file links to the last hash of the old one. And `audit.Open` runs
`Verify` before it appends: if the tail is already broken, roverd refuses to
start, because appending valid entries after a break would bury it.

Proof: `TestChainVerifies`, `TestOneByteEditIsDetectedAtItsLine`,
`TestDroppedLineIsDetected`, `TestWhitespaceEditIsDetected`,
`TestRotationKeepsChainAcrossFiles` and `TestOpenResumesChainAndRefusesCorruptTail`
in `internal/audit/logger_test.go`. `TestEndToEndThroughDaemon` edits one byte
of a real file and asserts `rover log --verify` fails at line 4.

### 7. Base64 for the raw bytes

The IPC protocol carries the MCP message in a `raw` field. Go encodes `[]byte`
as base64, and that is the point. A JSON string would work for valid UTF-8,
but the wrapper must forward the exact bytes it received, even if they are not
valid UTF-8 or not valid JSON. Base64 is the only encoding that never alters
them. Same rule as A1: what roverd inspects must be byte-for-byte what the
server receives.

Proof: `TestRoundTrip` in `internal/ipc/protocol_test.go` pushes `\xff{not
json\n` through `Encode` and `Parse` unchanged. `TestPumpForwardsBytesExactly`
in the proxy tests still holds.

### 8. A hold must not block the pipe

A verdict of `hold` means "waiting for a human" (M9 approvals). The wrapper
hands the held line to a goroutine that waits for the `release`, and keeps
pumping. JSON-RPC allows out-of-order completion, so a later `ping` can be
answered while an earlier `send_email` is still pending. If a hold blocked the
pipe, one approval prompt would freeze the whole agent, and the pressure to
"just approve it" would be an attack on the human.

If the connection dies while a hold is pending, `Client.readLoop` delivers a
synthetic `release` with action `block`. A release that never comes is a deny.

Proof: `TestHoldDoesNotBlockLaterMessages` in `internal/proxy/proxy_test.go`.

### 9. An unknown verdict is a refusal

`apply` handles `forward`, `replace` and `block`. Anything else returns an
error and ends the session. A wrapper that guessed ("allow-ish probably means
allow") would be a wrapper an attacker could steer by corrupting one field.

Proof: `TestUnknownActionIsRefused`.

### 10. Audit failure makes roverd unhealthy

If `Audit.Write` fails, `decide` answers `block` and sets `unhealthy`. Every
later decision, from every wrapper, is a block until a human restarts roverd
and looks at the log. The disk filling up is not a reason to run unaudited.

Proof: `TestAuditFailureBlocks`: forward while healthy, block when the writer
fails, still block after the writer recovers.

### 11. bbolt's exclusive lock as a second-daemon guard

bbolt takes an exclusive file lock on `state.db`. `state.Open` waits one
second and then returns `ErrLocked`; `rover daemon` treats that as "another
roverd is running" and exits quietly. `Server.Listen` adds a second guard: it
dials the socket first, and refuses if anything answers. Two daemons would
mean two audit logs and two session tables, and a wrapper could land on
either.

Proof: `TestSecondOpenIsRefused` (`internal/state/state_test.go`) and
`TestListenRefusesWhenAnotherDaemonAnswers` (daemon).

### 12. Schema version in the state file

`meta/schema_version` is written on first open. A file from a newer rover is
refused with a message naming both versions. Guessing at a layout you do not
understand is how pins and approvals get silently misread.

Proof: `TestNewerSchemaIsRefused` and `TestOpenCreatesBucketsAndVersion`.

### 13. Protocol version in the hello

The first frame must be a `hello` with `version` equal to `ipc.Version` (1).
Anything else gets an `error` frame and a closed connection. A stale wrapper
talking to a new daemon fails loudly at the first byte instead of mis-parsing
verdicts later. `Validate` is strict about everything else too: pids must be
positive, `server_name` is 1 to 128 bytes, `transport` is `stdio` or `http`,
a `release` can never say `hold`.

Proof: `TestBadHelloGetsErrorFrame` (daemon), `TestValidateRejectsBadFrames`
(ipc), and `FuzzParse`, which runs in `make fuzz`: anything `Parse` accepts
must re-encode and parse again identically.

### 14. Size limits on every frame

One IPC line is capped at `ipc.MaxFrame`: 16 MiB (the MCP message limit)
inflated by 4/3 for base64, plus 64 KiB of JSON around it. `framing.ReadLine`
counts across buffer refills, so a peer cannot sneak past the limit by making
the reader refill. The same helper frames MCP stdio and the audit log.

Proof: `TestParseRejectsOversize` (ipc),
`TestReadLineEnforcesLimitAcrossBufferRefills` (framing),
`TestRejectsOversizedMessage` (proxy).

### 15. What the independent review changed

An independent review of M1 (a separate agent, given the plan and the diff, told to assume the work was broken) found four problems worth fixing before building on this milestone. They are good examples of the difference between "has a test" and "is secure".

- **Session identity was self-asserted.** The hello carried `client_pid`, and roverd believed it. Any same-user process could join another agent's session, or dodge its own, by naming a different pid. Now roverd asks the kernel for the connecting pid (`LOCAL_PEERPID` on macOS, the pid in `SO_PEERCRED` on Linux), requires it to equal `wrapper_pid`, and looks up that process's parent (`sysctl kern.proc.pid` on macOS, `/proc/<pid>/stat` on Linux) and requires it to equal `client_pid`. See `ipc.CheckHello` and `TestHelloMustMatchKernelView`. The lesson: never trust a claim you can check.
- **A hold could deadlock.** The wrapper registered its interest in a release only after it had read the hold verdict. A release arriving in that gap was dropped, and the held message, and the wrapper, waited forever. The registration now happens before the decide is even sent. Nothing in M1 holds, so this was latent until M9; it was still a bug.
- **`--verify` could not see a cut head or tail.** A hash chain proves that the lines you have fit together. It cannot prove that lines were not removed from the front (the first line's `prev` is simply believed) or from the end (nothing follows the last line). Two changes: `rover log --verify` now checks every rotated file plus the live one as a single chain, so the oldest file must start with `prev: ""` and each file must continue the last; and roverd writes the newest hash to `state/audit.anchor` after every entry, so a log whose tail was removed no longer contains the anchored hash and fails verification. An attacker who can rewrite the log can also rewrite the anchor, which is why plan §3 says a same-user attacker is only partly in scope; the anchor raises the bar from "delete lines" to "forge two files consistently".
- **Bodies could be inflated six-fold.** `encoding/json` escapes `<`, `>` and `&` as `\u003c` and friends, so a 3 MiB message of `<` became an 18 MiB audit line, larger than the verifier would read, and roverd refused to start the next time. HTML escaping is now off for the audit log, and a write larger than the limit is refused rather than written. Size limits belong on the way in and on the way out.

Smaller changes from the same review: joining and leaving a session happen under one lock, the wrapper prints only the server's base name on stderr (arguments often carry tokens), existing files are checked for owner and mode at startup, and `audit.Verify` and `framing.ReadLine` have fuzz targets.

## (c) Exercise it by hand

Run everything from the repo root on macOS. First, point Rover at a lab
directory so nothing here touches your real state. Do this in **every**
terminal you open.

```bash
export ROVER_DIR=/tmp/rover-lab
make build
```

**Terminal 1: run the daemon in the foreground**

```bash
export ROVER_DIR=/tmp/rover-lab
./bin/rover daemon
```

You should see one line ending `listening on /tmp/rover-lab/run/roverd.sock
(pid NNN, bodies=false)`. Leave it running.

**Terminal 2: wrap the echo server and drive it by hand**

```bash
export ROVER_DIR=/tmp/rover-lab
./bin/rover wrap --name echo -- ./bin/echo-server
```

The wrapper prints `[rover] session <id>: wrapping ./bin/echo-server as "echo"`
on stderr, and terminal 1 prints that `echo` attached with your shell's pid as
the client pid. Now paste these three lines, one at a time, pressing Return
after each:

```
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi rover"}}}
```

After the first and third you get a JSON result back. The notification gets
no reply (that is correct). Press Ctrl-D to end the session; the wrapper exits
0 and terminal 1 prints `session <id>: closed`.

**Read the log and verify the chain**

```bash
./bin/rover log
./bin/rover log --verify
```

`rover log` shows five entries: request, result, notification, request,
result. Every line has action `forward` and no body. `--verify` prints
`5 entries, chain intact`. Look at one raw line to see the fields:

```bash
tail -1 "$ROVER_DIR/state/audit.jsonl" | jq .
```

Note `prev` and `hash`, and that `prev` of line 5 equals `hash` of line 4.

**Tamper with one byte**

```bash
cp "$ROVER_DIR/state/audit.jsonl" /tmp/rover-lab/audit.good
sed -i '' 's/"method":"tools\/call"/"method":"tools\/cull"/' "$ROVER_DIR/state/audit.jsonl"
./bin/rover log --verify; echo "exit $?"
```

Output: `... line 4: audit chain broken: hash "..." does not match contents`
and exit 1. (If you pasted the three lines without waiting for replies, the
replies land later in the log and `tools/call` is line 3; `--verify` names
whichever line you changed.) Now stop the daemon in terminal 1 with Ctrl-C and start it again.
It refuses: `audit log: resume chain: line 4: ...`. A broken chain halts the
gateway until a human looks. Restore the good copy, then start the daemon
again in terminal 1:

```bash
cp /tmp/rover-lab/audit.good "$ROVER_DIR/state/audit.jsonl"
./bin/rover daemon      # terminal 1
```

**Look at the permissions**

```bash
ls -la "$ROVER_DIR" "$ROVER_DIR/run" "$ROVER_DIR/state"
```

Directories are `drwx------`, the socket is `srw-------`, and `audit.jsonl`,
`state.db`, `roverd.pid` are `-rw-------`. Try loosening one and watch the
refusal:

```bash
chmod 750 "$ROVER_DIR/state"
./bin/rover wrap -- ./bin/echo-server </dev/null; echo "exit $?"
chmod 700 "$ROVER_DIR/state"
```

The error names the path, its mode, and the exact `chmod` to fix it.

**Fail closed with no daemon**

Stop the daemon in terminal 1 (Ctrl-C). In terminal 2:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"ping"}' | ROVER_TEST_NO_AUTOSTART=1 ./bin/rover wrap -- ./bin/echo-server; echo "exit $?"
```

You get `[rover] cannot reach roverd, refusing to start "./bin/echo-server":
... (auto-start disabled by ROVER_TEST_NO_AUTOSTART)` and exit 1. No reply,
because the echo server was never started.

**Auto-start**

Same command without the variable:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"ping"}' | ./bin/rover wrap -- ./bin/echo-server
cat "$ROVER_DIR/run/roverd.pid"
cat "$ROVER_DIR/state/roverd.log"
ps -p "$(cat "$ROVER_DIR/run/roverd.pid")"
```

This time you get a reply. The pid file names a daemon you never started by
hand; `roverd.log` holds its stderr, including `listening on`; `ps` shows it
still running after the wrapper exited. It will serve every later wrapper.
Run `./bin/rover log --verify` once more: the new entries continue the same
chain. When you are done:

```bash
kill "$(cat "$ROVER_DIR/run/roverd.pid")"
```

## (d) Three attacks to try against it

Keep `ROVER_DIR=/tmp/rover-lab` exported and the daemon running in terminal 1
for all three.

### Attack 1: knock on the socket as the wrong peer

First, a wrong protocol version with plain `nc`:

```bash
printf '%s\n' '{"type":"hello","version":99,"wrapper_pid":1,"client_pid":1,"server_name":"x","transport":"stdio"}' \
  | nc -U "$ROVER_DIR/run/roverd.sock"
```

roverd answers `{"type":"error","message":"bad ipc frame: protocol version
99, want 1"}` and closes. Try a frame that is not a hello at all, or `"seq":0`
in a decide, and read the error each time. That is `Validate` refusing to
guess. Then send a **correct** hello (`"version":1`) and note you get a
`welcome` with a session id. You are the same user, so you are allowed. That
is the documented limit from decision 2. Ask yourself what a same-user
attacker gains from a session: in M1, only an audit entry with their name on
it.

Now as a different user. Non-root first:

```bash
sudo -u nobody nc -U "$ROVER_DIR/run/roverd.sock"
```

`Permission denied`: the `0700` directory stops the knock before the peer
check runs. Then as root, which ignores file permissions:

```bash
sudo nc -U "$ROVER_DIR/run/roverd.sock"
```

The connection opens and closes with nothing said. Terminal 1 shows
`refusing connection: peer is a different user: uid 0, roverd runs as <your uid>`.
Root got past the directory and was still refused, because the kernel told
roverd who connected.

### Attack 2: edit the log and try to fix the hashes

Make a session or two so the log has at least five lines, then copy it:

```bash
cp "$ROVER_DIR/state/audit.jsonl" /tmp/rover-lab/audit.good
```

First, three edits that `--verify` must catch. After each, run
`./bin/rover log --verify` and note the line it names, then restore from the
copy.

```bash
# 1. change meaning: a tools/call becomes something harmless-looking
sed -i '' '4s/"method":"tools\/call"/"method":"ping"/' "$ROVER_DIR/state/audit.jsonl"
# 2. delete a line
sed -i '' '3d' "$ROVER_DIR/state/audit.jsonl"
# 3. swap lines 2 and 3
awk 'NR==2{h=$0;next} NR==3{print;print h;next} {print}' /tmp/rover-lab/audit.good > "$ROVER_DIR/state/audit.jsonl"
```

Now try to be a competent attacker. Recompute a hash the way `audit.encode`
does: SHA-256 over the compact JSON with the `hash` field removed.

```bash
python3 - "$ROVER_DIR/state/audit.jsonl" <<'EOF'
import hashlib, json, sys
for n, line in enumerate(open(sys.argv[1]), 1):
    e = json.loads(line)
    claimed = e.pop("hash", "")
    canon = json.dumps(e, separators=(",", ":"), ensure_ascii=False)
    got = hashlib.sha256(canon.encode()).hexdigest()
    print(n, "ok" if got == claimed else "MISMATCH", got[:12])
EOF
```

Run it on the untouched file first. Every line should say `ok`. If one does
not, your encoder disagrees with Go's about canonical form, which is the
canonical-form check doing its job against you.

Then redo edit 1 and work through what a repair needs. Line 4's `hash`
changes, so line 5's `prev` must change, so line 5's `hash` changes, and so on
to the end of the file. Extend the script to rewrite `prev` and `hash` for
every line from the edit onward, write the result back, and run `--verify`.
It passes. That is the limit stated in decision 6: the chain detects a
surgical edit and nothing else. Two things still work against you, though.
Check both:

1. The daemon is still running and remembers the last hash it wrote. Run one
   more session, then `--verify`. The new entry links to the **old** hash, and
   the break shows up at the first line roverd wrote after your rewrite.
2. Stop the daemon before rewriting, rewrite, start it again. Now `Open`
   resumes from your forged tail and nothing notices. What would it take to
   catch this? Think about where a copy of "the latest hash" could live that
   the attacker cannot write to.

Restore the good copy and restart the daemon when you are done.

### Attack 3: kill roverd mid-session

In terminal 2, start a wrapped session and send the `initialize` line from
part (c). Get its reply. Now in terminal 1 press Ctrl-C (or
`kill "$(cat "$ROVER_DIR/run/roverd.pid")"` from a third terminal).

Nothing happens in terminal 2 yet: the wrapper is blocked reading stdin. Paste
the `tools/call` line. Immediately you see
`[rover] session ended with error: no verdict from roverd, stopping session
(fail closed): roverd connection closed: EOF`, the wrapper kills
the echo server and exits non-zero (`echo $?`). Nothing was written to stdout:
the agent on the other side of that pipe got no answer, just EOF.

Now check what the attacker gained. `./bin/rover log --verify` passes, and the
last entry is the reply to `initialize`. The `tools/call` was never forwarded
and never recorded, because it never got a verdict. Start another wrapped
session with no daemon running: auto-start brings up a fresh roverd, and its
first entry links to that last hash. The attacker caused an outage. They did
not cause an unrecorded call.

Last question: what if the attacker leaves roverd dead and sets
`ROVER_TEST_NO_AUTOSTART=1` in the agent's environment? The agent stops
working entirely. Loud failure is the design, not a defect.

## (e) Five explain-back questions

1. Draw the M1 picture from memory: agent, two wrappers, roverd, two MCP
   servers. Mark where decisions are made, where the audit log is written,
   and what the wrapper is allowed to do on its own. Why does the wrapper
   connect to roverd before starting the server, and which test proves it?
2. Explain `SO_PEERCRED` / `LOCAL_PEERCRED` to someone who has never heard of
   them. Why can the peer not lie about its uid? Why does root get refused
   even though it can open the `0700` directory? Name the one adversary this
   check does not stop.
3. A colleague says: "If the agent can just `kill` roverd, the whole gateway
   is pointless." Answer using what you saw in Attack 3: what the wrapper
   does on the next message, what the MCP client sees, what the audit log
   shows afterwards, and the difference between denial of service and bypass.
4. Describe what `rover log --verify` checks at each line (three things).
   Give one edit it catches and one attacker it does not catch. Why does
   `audit.Open` refuse to append to a broken file, and why does the first
   entry after rotation carry a non-empty `prev`?
5. Ten wrappers start at the same instant and find no daemon. Walk through
   `connect`: the flock, the second dial, the spawn, the retry loop. Why a
   kernel lock rather than a "lock file exists" check? Then list the other
   guards that stop two daemons from running (socket dial in `Listen`,
   bbolt's lock, the schema version) and say what each one catches that the
   others do not.
