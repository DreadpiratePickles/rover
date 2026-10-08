# A0 · MCP on the wire

**Goal:** see the protocol with nothing hiding it, so that every later security
decision is about real bytes, not SDK abstractions.

## Concepts

**1. MCP is JSON-RPC 2.0.** Four message shapes, nothing else:

| Shape | Has `id` | Has `method` | Expects reply |
| --- | --- | --- | --- |
| request | yes | yes | yes |
| notification | no | yes | no |
| result | yes | no (`result`) | – |
| error | yes (or null) | no (`error`) | – |

Read `internal/jsonrpc/message.go`. Notice that any message that doesn't fit
one shape cleanly is `invalid`. A gateway that guesses becomes a bypass.

**2. The lifecycle.**

```
client → initialize {protocolVersion, capabilities, clientInfo}
server ← result      {protocolVersion, capabilities, serverInfo}
client → notifications/initialized
client → tools/list                 ← the server describes its tools (TEXT THE MODEL READS)
client → tools/call {name, arguments}
server ← result {content:[...], isError?}
```

**3. Transports.** *stdio* uses one JSON message per line on stdin/stdout, and
stderr is free for logs. *Streamable HTTP* is for remote servers (A7). Our
gateway starts with stdio because that's how Claude Code and Cursor run most
servers.

**4. Why this matters for security.** Three things in that flow reach the
model as text: tool **descriptions** (from `tools/list`), tool **results**,
and resource contents. Anything the model reads can carry instructions. That
one fact drives A3, A4 and A5.

**5. Two kinds of failure.** A JSON-RPC `error` means the protocol failed. A
result with `isError: true` means the tool failed, and the model gets to see
why. Look at `toolError` in the echo server.

## Build

`examples/echo-server/main.go` is an MCP server in ~150 lines with no SDK.
`read_file` is dangerous on purpose: it reads any path.

## Lab

```bash
make build
./bin/echo-server
```
Now **be the client** and paste these lines one at a time:
```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"me","version":"0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/hosts"}}}
{"jsonrpc":"2.0","id":4,"method":"does/not/exist"}
not json at all
```

## Done when (explain these back without notes)

1. Why does the notification get no reply?
2. Why must the server never `fmt.Println` debug output?
3. What's the difference between the replies to id 3 (with a bad path) and id 4?
4. Name the three places where text reaches the model, and one attack for each.
