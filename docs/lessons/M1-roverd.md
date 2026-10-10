# M1 · roverd and thin wrappers

**Goal:** split Rover into many small wrappers and one daemon that decides,
without opening a way around it. Lesson focus: daemons, Unix sockets, peer
credentials, file locks, tamper-evident logs, and why "kill roverd" is a
denial of service rather than a bypass.

```
 Claude Code (pid 4200)
   │ stdio            │ stdio
   ▼                  ▼
 rover wrap         rover wrap          one wrapper per MCP server
 (filesystem)       (github)            read · ask · apply verdict · forward
   │  ▲               │  ▲
   │  └── verdict ────┼──┘
   └──── decide ──────┴──▶  roverd  (one per user)
          unix socket        decides · owns audit.jsonl · owns rover.db
                             sees every server of client 4200 as ONE session
```

## (a) What was built

In A1, each `rover wrap` was a complete little gateway: it read messages,
classified them and wrote its own audit log. In M1 the wrapper gets *thinner*
and a new process, **roverd** (`rover daemon`), gets the brains.

- **The wrapper** (`rover wrap`) still starts the MCP server and sits on its
  stdin and stdout. For every line, in both directions, it asks roverd
  "what should I do with this?", does exactly what it's told, and forwards the
  original bytes. It no longer writes a log (`--log` and `--no-bodies` now give
  a usage error pointing at `rover daemon --log-bodies`).
- **roverd** is one long-running background process per user (a *daemon*). It
  classifies each message (A1's `observe` logic, moved to `internal/daemon`),
  writes the audit entry, and answers with a **verdict**. In M1 the verdict is
  always `forward`. Policy arrives in M2.
- **Around them:** a Unix socket only your user can use, auto-start that fails
  closed, a hash-chained audit log with `rover log --verify`, and a bbolt state
  database (`state/rover.db`) with empty buckets for later milestones.

**Why split it at all?** The dangerous attacks cross servers: read
`~/.ssh/id_rsa` with the filesystem server, then post it with the GitHub
server. Each wrapper sees only one server and can't notice that. roverd sees
all of them. Wrappers with the same parent process (`client_pid`, the
wrapper's `os.Getppid()`, i.e. the agent app that started them) share one
**session**. That shared view is what M8 needs to spot the *lethal trifecta*:
private data, untrusted content and a way to send data out, all in one
session.

**"Wrappers are thin; roverd decides" (D3) is itself a security property.**
There is exactly one *policy decision point*. If every wrapper made its own
decisions, ten wrappers could run ten slightly different versions of the
rules, and an attacker would only need the weakest. A thin wrapper has almost
nothing to get wrong: it can only forward, replace, block, or stop.

## (b) Design decisions and the attacks they prevent

### 1. The wire: newline-delimited JSON, parsed strictly

One JSON object per line, each an envelope with a `type` and one member of that
name (`internal/ipc/ipc.go`):

```
→ {"type":"hello","hello":{"version":1,"wrapper_pid":4242,"client_pid":4200,"server_name":"echo","server_cmd_sha256":"9f86…","transport":"stdio"}}
← {"type":"welcome","welcome":{"session_id":"a1b2c3d4e5f60718293a4b5c"}}
→ {"type":"decide","decide":{"session_id":"a1b2…","seq":1,"dir":"c2s","raw":{"jsonrpc":"2.0","id":1,"method":"ping"}}}
← {"type":"verdict","verdict":{"seq":1,"action":"forward","rule_ids":[]}}
```

| Rule | Attack or bug it prevents |
| --- | --- |
| `decide.raw` is spliced in byte for byte, never re-marshalled (`encodeDecide`) | A **parser differential**: roverd judging different bytes from the ones the wrapper forwards. Same rule as A1: forward (and inspect) the original bytes |
| 16 MiB per message (plus 64 KiB for the envelope) | One endless line exhausting memory |
| `DisallowUnknownFields`, exactly one payload matching `type`, nothing after the object, unknown `type` → close | Two programs disagreeing about what a message means. A lenient parser is a place for smuggling |
| `version` must be 1; the first message must be `hello`; `client_pid` > 0 | Talking to an incompatible or confused peer as if all were fine |
| `seq` must be exactly the previous `seq` + 1 on that connection; the wrapper checks the verdict's `seq` matches its question | A verdict being applied to the wrong message |
| Any error poisons the wrapper's client; every later decide fails | After one confusion, "which answer belongs to which question?" can't be trusted again |

Every protocol error ends the connection. roverd doesn't try to recover,
because recovering means guessing. `FuzzDecode` (in `make fuzz`, 10 s per
target) throws random bytes at the decoder.

### 2. A Unix socket, not a TCP port

| | TCP on `127.0.0.1:7777` | Unix socket `run/roverd.sock` |
| --- | --- | --- |
| Who can connect? | Any process of any user, and a web page in your browser can try | Only processes that can reach the file |
| Discoverable? | Port scans find it | It's a path; no scanning |
| Reachable from other hosts? | One wrong bind address away | Never: it doesn't exist on the network |
| Who connected? | You get a port number | The kernel tells you the uid (and pid) |

### 3. Three locks on one door

1. **File permissions.** The socket is `0600` inside a `0700` directory. Another
   user can't even look up the path, so `connect()` fails with
   "Permission denied" before roverd hears anything. (On Linux, connecting
   also needs write permission on the socket file itself. `man 7 unix` warns
   that POSIX doesn't promise this and some older BSDs ignored it, which is one
   reason the directory matters.)
2. **Peer credentials in roverd.** On every accepted connection roverd asks the
   *kernel* which uid is on the other end: `SO_PEERCRED` on Linux
   (`peercred_linux.go`), `LOCAL_PEERCRED` on macOS (`peercred_darwin.go`).
   The kernel recorded that at `connect()` time; the peer can't lie about it.
   If the uid isn't roverd's own, `Guard.Accept` closes the connection
   **before reading a single byte**, counts it, and logs `rejected connection`.
   If reading the credentials fails, that's a rejection too (fail closed).
3. **Peer credentials in the wrapper.** `ipc.Dial` checks the other direction:
   the process *listening* must be your uid too. Otherwise a socket planted at
   your path by someone else would receive every MCP message you send.

Why three? Each one can fail on its own:

- Someone runs `chmod 755` on the directory while roverd is running (it's
  only checked at start). Layer 1 is gone; layer 2 still holds.
- No `$XDG_RUNTIME_DIR` (no systemd login session), so the run dir falls back
  to `/tmp/rover-<uid>` in the shared `/tmp`, and another user could create it
  first and listen there. `CheckPerms` refuses a directory owned by someone
  else, and layer 3 refuses a daemon of another uid. You get an error, not a
  hijacked socket.
- A bug in the uid comparison: layer 1 still keeps other users out.

That's **defence in depth**: no single mistake is a breach.

### 4. Private directories, checked every start

| | macOS | Linux |
| --- | --- | --- |
| Config | `~/Library/Application Support/Rover/` | `$XDG_CONFIG_HOME/rover/` (fallback `~/.config/rover/`) |
| State: `rover.db`, `audit.jsonl`, `roverd.log` | `…/Rover/state/` | `$XDG_STATE_HOME/rover/` (fallback `~/.local/state/rover/`) |
| Run: `roverd.sock`, `roverd.pid`, `roverd.lock` | `…/Rover/run/` | `$XDG_RUNTIME_DIR/rover/` (fallback `$TMPDIR/rover-<uid>/`) |

`Dirs.Ensure` creates missing directories `0700`, then `CheckPerms` refuses any
directory that is a symlink (checked with `Lstat`, so it isn't followed), isn't
owned by you, or has *any* group or other bit set. It never quietly `chmod`s
an existing directory: if one is loose, someone changed it, and you should
know. Files are `0600`. `audit.Open` and `state.Open` also refuse a looser file,
and `state.Open` refuses a symlink.

**`ROVER_DIR`** puts everything under one directory (config in it, `state/`
and `run/` below it). It's for tests and labs. Be honest about what that
means: any process running as you can set it and point a wrapper at a
different roverd. That sits inside the threat model's exclusion: same-user
code can already do anything Rover could stop.

**Socket path length.** A socket path must fit in the kernel's `sun_path`:
104 bytes on macOS, including the final NUL. A long home directory can exceed
that, so above 100 bytes the socket moves to `$TMPDIR/rover-<uid>/roverd.sock`
(also checked as a private directory). If even that is too long, Rover errors
out and tells you to shorten `TMPDIR` or `ROVER_DIR`.

### 5. Fail closed (D4): auto-start, or the server never runs

`rover wrap`, step by step (`cmd/rover/main.go`, `autostart_unix.go`):

1. Dial the socket (1 s timeout, plus the uid check above).
2. If nobody answers, and `ROVER_TEST_NO_AUTOSTART` isn't set, auto-start:
   - `Ensure` the directories (this is where a `0755` directory is refused);
   - take an exclusive `flock` on `run/roverd.lock`, waiting at most 10 s, and
     dial again (another wrapper may have started roverd meanwhile);
   - start `os.Executable() daemon` detached: `Setsid` (a new session with no
     terminal, so the agent's Ctrl-C doesn't reach it), stdin from `/dev/null`,
     stdout and stderr appended to `state/roverd.log`. The environment is
     inherited, so `ROVER_DIR` and `ROVER_LOG_BODIES` carry over;
   - keep holding the lock and retry every 100 ms for up to 3 s.
3. Send `hello`; wait up to 5 s for `welcome`.
4. Any failure in steps 1–3: print
   `roverd is not reachable; refusing to start <cmd> (fail closed)`, exit **3**,
   and **never start the MCP server**. `TestFailClosedWithoutDaemon` proves it:
   the "server" is `sh -c 'touch marker'`, and the test asserts the marker
   file doesn't exist.
5. Only now is the server started. If roverd dies, freezes (10 s decide
   timeout) or sends something unexpected mid-session, the wrapper kills the
   server and exits 1.

**File locks in one paragraph.** `flock(2)` attaches a lock to an open file.
`LOCK_EX` means exclusive; `LOCK_NB` means "fail at once instead of waiting",
which lets the code poll and give up after a deadline. The kernel drops the
lock when the holder closes the file or dies, **even by `kill -9`**, so a crash
never leaves a lock behind. The locks are *advisory*: they only coordinate
processes that also call `flock`, and anyone who can open the file can still
write to it. They're a traffic light, not a wall.

Rover uses two:

| Lock | Held by | Why |
| --- | --- | --- |
| `run/roverd.lock` | a wrapper, during auto-start | Claude Code starts all its servers at once. Without it, five wrappers would each spawn a roverd and four would exit with "already running". The queue makes the others wait, then connect |
| `run/roverd.pid` | roverd, for its whole life | Single instance: a second `rover daemon` gets `roverd already running` and exits 1. The pid inside is a hint for humans; **the lock is the truth**. After a `kill -9` the file still holds the dead pid, but the lock is free |

Why is the auto-start wait **bounded** at 10 s? The holder needs about 4 s at
most. If the lock is still held after 10 s, something is badly stuck (for
example a wrapper frozen with `SIGSTOP` while holding it). An unbounded wait
would hang every MCP server of the agent app forever with no message. A
bounded one fails closed with a reason.

### 6. Killing roverd is a denial of service, not a bypass

The threat model's row "manipulated agent attacking Rover through its shell
tool" says it plainly: *a same-user process can always kill roverd*. The
agent's shell tool runs as you, and the kernel lets a uid signal every process
of that uid. Nothing Rover does can change that: a process can't protect itself
from its own user.

So the design question is what *happens* when roverd dies:

- **Fail open** (the wrapper forwards when roverd is missing): `kill roverd`
  becomes "turn off all policy". A bypass.
- **Fail closed** (what we built): running sessions stop at their next message,
  and new servers never start. The agent loses its tools. The attacker gains
  nothing they couldn't get by deleting the MCP config.

The second is a denial of service: annoying and visible, but nothing gets
through undecided.

### 7. The tamper-evident audit log

roverd alone writes `state/audit.jsonl`. Each line is one message:

```
{"ts":"…","session":"0799…","dir":"c2s","kind":"request","method":"initialize","id":1,"bytes":148,"server":"echo-server","prev":"","hash":"8e0d6f47…"}
```

How a line is made (`internal/audit/chain.go`):

1. Set `prev` to the previous entry's hash (`""` for the very first entry
   ever).
2. Marshal the entry *without* `hash` → bytes **B** (ending in `}`).
3. `hash = hex(SHA-256(B))`.
4. Write B with its final `}` replaced by `,"hash":"<64 hex>"}` and a newline.

To verify, cut the fixed-length suffix off, put the `}` back, and hash those
exact bytes (never decode and re-encode: two encoders can produce different
bytes for the same data). Then check each `prev` against the line before.

| Change | Detected as |
| --- | --- |
| One byte of an entry | `hash mismatch: the entry was modified` at that line |
| An entry deleted, inserted or reordered | `prev does not match the previous entry's hash` at the next line |
| The very first entry deleted | Same: the oldest entry must have `prev` `""` (only checked across the state dir, not with `--log FILE`) |
| A cut-off last line | `truncated: last line has no newline` |

- **Rotation.** At 50 MiB, `audit.jsonl` becomes `audit-<UTC time>.jsonl`, and
  the next entry's `prev` is the old file's last hash. `rover log --verify`
  (without `--log`) walks the rotated files oldest first, then `audit.jsonl`,
  so deleting a whole old file breaks the chain too.
- **Open refuses a damaged last line.** roverd reads the last line on start to
  continue the chain. If it's damaged, roverd won't start: appending to a
  broken chain would hide the break.
- **Write failures are sticky.** After one failed write the file may end in
  half a line, so the logger refuses every later write.
- **Log, then forward.** roverd writes the entry *before* it answers
  `forward`. If the write fails, the verdict is `block` with reason
  `audit_unavailable` and roverd hangs up, so the wrapper stops the session.
  An unrecorded message must not pass (`TestAuditFailureBlocksAndCloses`).
- **Bodies are off by default.** Entries hold method, id, tool name and size,
  not arguments or results. Those contain file contents, tokens and queries,
  and Rover can't redact secrets until M10. Turn bodies on with
  `rover daemon --log-bodies` or `ROVER_LOG_BODIES=1`.

**Be honest about the limit.** "Tamper-*evident*" is not "tamper-*proof*".
Anyone who can write the file (you, or anything running as you) can edit an
entry and recompute every hash after it. `--verify` then says `chain intact`.
Without an **anchor** (the latest hash stored somewhere the attacker can't
write, a signature with a key they don't hold, or a copy shipped off the
machine) this catches corruption and casual edits, not a determined same-user
attacker. An anchor is a natural hardening step for M14.

**Compare git.** Each commit names its parent's hash, so rewriting an old
commit changes every hash after it. git doesn't stop you doing that (`rebase`
does it all day). You notice because a remote, a colleague's clone or a signed
tag remembers the old hash. That outside copy is git's anchor.

### 8. State in bbolt

`state.Open` uses bbolt's own file lock with a 1 s timeout, so only one roverd
can own `rover.db`. A second open fails with "locked by another process"
instead of corrupting it. `meta/schema_version` is 1. A missing version is
written; a **newer** version than this binary understands is refused ("upgrade
rover"). Guessing at a format you don't understand is how security state (which
tools were pinned, which calls a human approved) gets silently misread.

### 9. Honest limits of M1

- **Every verdict is `forward`.** M1 builds the decision *path*; M2 puts Cedar
  policy on it. `block`, `replace` and `hold` already work in the wrapper (a
  `hold` stops the session until M9).
- **A non-JSON line stops the whole session.** MCP stdio carries only JSON-RPC,
  and roverd can only judge JSON, so forwarding a line it can't read would be
  failing open. The cost: a server that prints debug text to stdout gets
  stopped. In the agent app the server shows up as failed or disconnected, and
  the wrapper's stderr says
  `the server sent a line that is not JSON; MCP stdio carries only JSON-RPC messages, so the session stops (fail closed)`.
  The fix belongs in the server: log to stderr.
- **Your own user can talk to the socket.** A same-user process can say hello
  with any `client_pid` and add made-up entries to the log. That's the same
  "same user can do anything" exclusion. What matters is that nothing on this
  socket can approve a call or change policy, ever: that will need the OS
  authentication dialog (D9).

## (c) Exercise it by hand

Run these from the repo root. Each lab uses a throwaway `ROVER_DIR`, so your
real directories stay untouched.

**Build, then run one message through roverd:**

```bash
make build
export ROVER_DIR=$(mktemp -d) && chmod 700 "$ROVER_DIR"
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"lab","version":"0"}}}'
echo "$INIT" | ./bin/rover wrap -- ./bin/echo-server
```

stderr shows `[rover] session …: wrapping ["./bin/echo-server"] as "echo-server" via roverd`,
and stdout shows the server's `initialize` result. No roverd was running, so the
wrapper started one, and it's still running.

**Read and verify the log:**

```bash
./bin/rover log            # timeline: agent -> echo-server, reply to initialize, latency
./bin/rover log --verify   # ok: 2 entries, chain intact
head -c 400 "$ROVER_DIR"/state/audit.jsonl; echo   # note "prev":"" on line 1, and no body
```

**Look at the files and the daemon:**

```bash
ls -la "$ROVER_DIR"/{run,state}   # drwx------ dirs; srw------- roverd.sock; -rw------- the rest
cat "$ROVER_DIR"/run/roverd.pid   # roverd's pid
cat "$ROVER_DIR"/state/roverd.log # "roverd: pid … listening on …; audit log … (bodies: false)"
ss -xlp | grep roverd             # Linux: the listening socket and its process
lsof -U | grep roverd             # macOS (works on Linux too)
ps -o pid,ppid,pgid,args -p "$(cat "$ROVER_DIR"/run/roverd.pid)"  # pgid = its own pid: detached by setsid
```

**Two wrappers, one session.** Both pipelines below are children of the same
subshell, so they have the same `os.Getppid()`:

```bash
( { echo "$INIT"; sleep 1; } | ./bin/rover wrap --name alpha -- ./bin/echo-server >/dev/null &
  { echo "$INIT"; sleep 1; } | ./bin/rover wrap --name beta  -- ./bin/echo-server >/dev/null &
  wait )
./bin/rover log | tail -4   # alpha and beta entries carry the same session id
```

Run the two wrappers one after the other instead, and the ids differ: a session
ends when its last connection closes.

**Fail closed, proven with a marker file:**

```bash
kill "$(cat "$ROVER_DIR"/run/roverd.pid)"   # SIGTERM: clean stop, the socket is removed
ROVER_TEST_NO_AUTOSTART=1 ./bin/rover wrap -- sh -c 'touch /tmp/marker'
echo "exit=$?"                              # 3
ls /tmp/marker                              # No such file or directory: the "server" never ran
```

**Single instance:** in one terminal run `./bin/rover daemon` (foreground,
logs on stderr; keep `ROVER_DIR` exported there too). In another, run
`./bin/rover daemon` again: `roverd already running (… is locked)`, exit 1.
Leave the first one running for the attacks below. Its terminal is the best
place to watch roverd's reactions.

**Bodies:** stop roverd, start it with `./bin/rover daemon --log-bodies`, send
`$INIT` again, and compare the new line in `audit.jsonl`. Then think about what
a `read_file` result would put in that file.

## (d) Three attacks to try against it

### Attack 1: rewrite history

Make a few entries, stop roverd (Ctrl-C in terminal 1) so nothing writes
while you edit, and keep a good copy:

```bash
LOG="$ROVER_DIR"/state/audit.jsonl
cp "$LOG" "$ROVER_DIR"/audit.good
./bin/rover log --verify
```

Each step starts from the good copy (`cp "$ROVER_DIR"/audit.good "$LOG"`):

```bash
perl -pi -e 's/"bytes":(\d+)/"bytes":9$1/ if $. == 2' "$LOG"; ./bin/rover log --verify   # flip a value on line 2
perl -ni -e 'print unless $. == 3' "$LOG";              ./bin/rover log --verify        # delete a middle line
perl -ni -e 'print unless $. == 1' "$LOG";              ./bin/rover log --verify        # delete the FIRST line
./bin/rover log --log "$LOG" --verify                    # ...and the same file checked on its own
```

Expect `BROKEN at …:2: hash mismatch`, then `…:3: prev does not match`, then
`…:1: prev does not match`. The last command says `ok`: a single file can't know
what came before it, so `--log FILE` trusts its first `prev`. Which of the two
would you run after an incident?

Now forge an entry. First with a bogus hash, then with a correct one:

```bash
cp "$ROVER_DIR"/audit.good "$LOG"
PREV=$(tail -n 1 "$LOG" | sed 's/.*"hash":"\([0-9a-f]*\)"}$/\1/')
B='{"ts":"2026-10-09T12:00:00Z","session":"forged","dir":"c2s","kind":"request","method":"tools/call","tool":"delete_everything","bytes":10,"server":"echo-server","prev":"'"$PREV"'"}'
printf '%s,"hash":"%064d"}\n' "${B%\}}" 0 >> "$LOG"; ./bin/rover log --verify     # hash mismatch at the new line
perl -ni -e 'print unless eof' "$LOG"                                              # remove it again
H=$(printf '%s' "$B" | shasum -a 256 | cut -d' ' -f1)
printf '%s,"hash":"%s"}\n' "${B%\}}" "$H" >> "$LOG"; ./bin/rover log --verify     # ok: chain intact (!)
./bin/rover log | tail -1
```

The forgery passes. You just did by hand what a same-user attacker would
script. **Thought experiment:** the attacker wants to *erase* the line where
the agent read `~/.ssh/id_rsa`. Write out the steps (delete it, recompute
every later hash). What would you have to have stored, and where, *before* the
attack to catch it? Then damage the last line
(`perl -pi -e 's/"bytes":(\d+)/"bytes":9$1/ if eof' "$LOG"`) and start
`./bin/rover daemon`: it refuses to open the log. Is that a bypass or a denial
of service? Restore with `cp "$ROVER_DIR"/audit.good "$LOG"`, then start
`./bin/rover daemon` again in terminal 1 for the next attack.

### Attack 2: knock on roverd's door

With `./bin/rover daemon` running in terminal 1, connect as **yourself** from
terminal 2. Use `socat - UNIX-CONNECT:"$SOCK"`, or `nc -U "$SOCK"` if you have
no socat:

```bash
SOCK="$ROVER_DIR"/run/roverd.sock
echo 'hello there' | socat - UNIX-CONNECT:"$SOCK"
echo '{"type":"hello","hello":{"version":99,"wrapper_pid":1,"client_pid":1,"server_name":"x","server_cmd_sha256":"","transport":"stdio"}}' | socat - UNIX-CONNECT:"$SOCK"
echo '{"type":"hello","hello":{"version":1,"wrapper_pid":1,"client_pid":1,"server_name":"x","server_cmd_sha256":"","transport":"stdio","admin":true}}' | socat - UNIX-CONNECT:"$SOCK"
printf '%s\n' '{"type":"hello","hello":{"version":1,"wrapper_pid":1,"client_pid":1,"server_name":"x","server_cmd_sha256":"","transport":"stdio"}}' '{"type":"launch_missiles"}' | socat - UNIX-CONNECT:"$SOCK"
```

Terminal 1 logs a `closing connection` line for each: `invalid character 'h'`,
`protocol version 99, want 1`, `unknown field "admin"`, and (after a real
`welcome`) `unknown message type "launch_missiles"`. Try a valid hello followed
by a `decide` with a made-up `session_id`. `TestProtocolErrorsCloseConnection`
in `internal/daemon/daemon_test.go` lists the rest (seq skips and repeats, a
second hello, a verdict sent *to* roverd); read it as a checklist. Notice that
a *well-formed* hello and decide from you are accepted and logged: why is that
fine?

Now as **another user**. Make a lab dir that `nobody` can reach, start roverd,
and confirm layer 1 first:

```bash
export ROVER_DIR=$(mktemp -d /tmp/rvlab.XXXXXX) && chmod 700 "$ROVER_DIR"
./bin/rover daemon &                         # or in its own terminal
SOCK="$ROVER_DIR"/run/roverd.sock
sudo -u nobody nc -U "$SOCK" </dev/null      # Permission denied: file permissions stop it
```

Then deliberately remove layer 1 and connect again:

```bash
chmod 711 "$ROVER_DIR" "$ROVER_DIR"/run && chmod 666 "$SOCK"
echo '{"type":"hello","hello":{"version":1,"wrapper_pid":1,"client_pid":1,"server_name":"x","server_cmd_sha256":"","transport":"stdio"}}' | sudo -u nobody nc -U "$SOCK"
```

No `welcome` comes back, and roverd logs
`rejected connection: ipc: peer is a different user (uid …, want …)`. It hung
up before reading your hello. The same test exists in Go and runs in CI:
`go test ./internal/ipc -run TestRejectsOtherUserViaSudo -v` (it needs
non-interactive sudo; run `sudo -v` first, or it skips). Clean up with
`kill %1; rm -rf "$ROVER_DIR"`.

Stretch (reason it through): stop roverd and have *root* listen at your socket
path (`sudo socat UNIX-LISTEN:"$SOCK",fork -`), then run a wrapper. Which check
in `ipc.Dial` fires? What does the auto-started roverd's `Listen` say when it
finds a live socket that isn't its own? What exit code does the wrapper end
with?

### Attack 3: take roverd away

Back to a normal lab dir (`export ROVER_DIR=$(mktemp -d) && chmod 700 "$ROVER_DIR"`).
Start a session that stays open, with a FIFO as the agent's stdin:

```bash
mkfifo "$ROVER_DIR"/in
./bin/rover wrap -- ./bin/echo-server < "$ROVER_DIR"/in &
exec 3> "$ROVER_DIR"/in
echo "$INIT" >&3                                  # works: you see the result
kill -9 "$(cat "$ROVER_DIR"/run/roverd.pid)"      # SIGKILL: no clean-up at all
echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}' >&3
```

The wrapper notices on the next message, prints
`lost roverd's decision on a message from the agent … broken pipe`, kills the
server and exits 1 (`jobs`/`wait` shows it). The `tools/call` never reached
the server. Now look: `run/roverd.sock` and `run/roverd.pid` (with the dead
pid) are still there. Run `echo "$INIT" | ./bin/rover wrap -- ./bin/echo-server`.
It works: the pid lock was freed by the kernel, and `Listen` removed the dead
socket because nothing answered on it. `./bin/rover log --verify` is still
intact. Close the FIFO with `exec 3>&-`.

Repeat with **`kill -STOP`** instead of `-9`:

- Mid-session: the wrapper waits 10 s for a verdict, then stops with
  `i/o timeout`, exit 1.
- Before a session (`kill -STOP` first, then run a wrapper): `connect()`
  *succeeds*, because the kernel queues the connection for the frozen process.
  But `hello` gets no `welcome` within 5 s, so the wrapper exits 3 and the
  server never starts.
- Then `kill -CONT` it and read the log. The frozen roverd wakes up and logs
  the queued `tools/call` that was never forwarded. The log records what was
  *attempted*, not what was delivered. Is that the right way round?

Finally, the loose directory. Stop roverd, `chmod 755 "$ROVER_DIR"`, and run a
wrapper: `cannot start roverd: … has mode 0755; it must be 0700`, exit 3.
`./bin/rover daemon` refuses too. (Loosen it *while* roverd runs and wrappers
keep connecting; see "three locks" in (b) for why that's still safe.)

For each of these, write one sentence on why it's a denial of service and not
a bypass. Then one sentence on why Rover can't prevent any of them.

## (e) Five explain-back questions

1. Follow one `tools/call` from Claude Code to the MCP server and back,
   through the wrapper and roverd. Say what each process does with the
   message, where the audit entry is written relative to forwarding, which
   bytes are forwarded and why, and what changes if the audit write fails.
2. Rover protects the socket with directory and file permissions, roverd's
   peer-credential check, and the wrapper's check of the daemon. For each
   layer, describe a realistic mistake or attack that defeats it, and say
   which other layer still holds. Why is a Unix socket a better starting point
   than a TCP port on localhost?
3. Explain `flock`: what "advisory" means, what `LOCK_EX|LOCK_NB` does, and what
   happens to the lock on `kill -9`. Then explain Rover's two lock files, why
   the pid file's *contents* aren't trusted but its *lock* is, and why the
   auto-start wait gives up after 10 s instead of waiting forever.
4. A prompt-injected agent runs `kill -9` on roverd through its shell tool.
   Walk through what happens to the session already running and to the next
   MCP server Claude Code starts. Explain why this is a denial of service and
   not a bypass, what the fail-*open* version would have looked like, and why
   no design could stop a same-user process from doing it.
5. `rover log --verify` prints `ok: 812 entries, chain intact`. Explain how a
   line's hash is computed and checked (and why on exact bytes), what you can
   now conclude, and what you *can't* conclude about a same-user attacker.
   What anchor would close the gap, and how is git's commit chain the same
   idea?
