# A1 · Transparent stdio proxy and audit log

**Goal:** put rover-gate between a real agent and a real MCP server, with
nothing broken and every message recorded. Every later Track A feature is a
hook in this loop.

```
Claude Code ──stdin──▶ rover-gate ──stdin──▶ MCP server
            ◀─stdout── (log, then forward) ◀─stdout──
```

## Concepts

**1. Threat model first.** Draw the trust boundaries:

- The **agent** is semi-trusted. It acts for you, but whatever it reads can steer it.
- The **MCP server** is untrusted. It's third-party code, often fetched with `npx -y` at run time.
- The **gateway** is trusted. It's the only part we control at both ends.

The gateway's job: nothing crosses a boundary without being *seen* (A1),
then *judged* (A2 onward).

**2. Forward the original bytes.** The proxy logs a *parsed* view but
forwards the *exact* bytes it received. If you parse and re-encode, you can
change numbers (`12345678901234567890` loses precision as float64),
escapes or duplicate keys. Then what you inspected is not what the server
executes. This is a "parser differential", a real bug class in WAFs and
proxies. See `TestPumpForwardsBytesExactly`.

**3. Log first, then forward, and fail closed.** If the audit write fails, the
session stops (`TestFailsClosedWhenAuditFails`). A security control that
keeps going without its evidence trail "fails open".

**4. Limits are security.** `bufio.Scanner` has a silent 64 KiB line
limit. Real tool results exceed it, and naive proxies break. No limit at
all lets a hostile server send one endless line and exhaust memory. We cap
messages at 16 MiB and kill the session past that.

**5. Correlation.** Responses can arrive out of order. In the real
filesystem-server run, id 4 came back before id 3. We match replies by
`direction + id`, because the server can send its *own* requests (sampling,
elicitation) and its ids can collide with the client's.

**6. Audit logs are sensitive.** They hold paths, queries and file
contents. The file is created `0600`, and `--no-bodies` logs metadata only.
A5 adds redaction; A9 makes the log tamper-evident.

## Use it with Claude Code

In your MCP config, change
```json
"filesystem": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/you/lab"] }
```
to
```json
"filesystem": { "command": "/path/to/rover-gate", "args": ["wrap", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/you/lab"] }
```
Use Claude Code normally, then run `rover-gate log`.

## Lab

1. Wrap the filesystem server and ask Claude Code to "summarise every file in
   the lab folder". Read the log. How many tool calls did one prompt cause?
   Did it call anything you didn't expect?
2. Read the full `tools/list` body in `~/.rover/audit.jsonl`. That text
   goes straight into the model's context. Who wrote it?
3. Make the log unwritable (`chmod 000 ~/.rover/audit.jsonl`) and start a
   session. What happens, and why is that the right behaviour?
4. Stretch: write a server that prints a 20 MB line. Confirm rover-gate
   ends the session instead of using 20 MB+ of memory per message.

## Done when

- [ ] Claude Code works normally through rover-gate on your Mac
- [ ] You can explain each test in `internal/proxy/proxy_test.go` and the attack it prevents
- [ ] You can explain why the gateway forwards `line` and not `json.Marshal(m)`
- [ ] You can say what A1 can *see* but cannot yet *stop* (that's A2)
