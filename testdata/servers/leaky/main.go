//go:build lab

// leaky is a test MCP server for the M10 lab (secrets and DLP). It hands
// whatever text it is given back through every channel a server has to
// reach the model, the way a server that reads an .env file or a CI log
// would leak the credentials in it:
//
//	leak        the text in a text block, in structuredContent and in an
//	            embedded resource
//	leak_split  the text cut in two halves, in two adjacent text blocks
//	fail        a JSON-RPC error whose message and data quote the text
//	leak_key    the text as a member NAME, in structuredContent
//	fail_key    the text as a member name in a JSON-RPC error's data
//	flood       the text repeated "count" times in one text block (a result
//	            that redaction would grow past the message cap)
//	send        an "egress" tool: pretends to send the text somewhere
//
// Build it only with `-tags lab`: it is not part of any release.
package main

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
)

type request struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

func tool(name, desc string) map[string]any {
	return map[string]any{"name": name, "description": desc, "inputSchema": map[string]any{
		"type": "object", "properties": map[string]any{"text": map[string]any{"type": "string"}},
	}}
}

var tools = []map[string]any{
	tool("leak", "Returns the text in every result channel."),
	tool("leak_split", "Returns the text in two text blocks."),
	tool("fail", "Fails with the text in the error."),
	tool("leak_key", "Returns the text as a member name."),
	tool("fail_key", "Fails with the text as a member name."),
	tool("flood", "Returns the text repeated count times."),
	tool("send", "Sends the text."),
}

func main() {
	in := bufio.NewReader(os.Stdin)
	enc := json.NewEncoder(os.Stdout)
	for {
		line, err := in.ReadBytes('\n')
		var req request
		if len(line) > 0 && json.Unmarshal(line, &req) == nil && len(req.ID) > 0 {
			_ = enc.Encode(handle(req))
		}
		if err == io.EOF || err != nil {
			return
		}
	}
}

func handle(req request) map[string]any {
	resp := map[string]any{"jsonrpc": "2.0", "id": req.ID}
	switch req.Method {
	case "initialize":
		resp["result"] = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}},
			"serverInfo": map[string]any{"name": "leaky", "version": "0.1.0"}}
	case "tools/list":
		resp["result"] = map[string]any{"tools": tools}
	case "tools/call":
		var p struct {
			Name      string            `json:"name"`
			Arguments map[string]string `json:"arguments"`
		}
		_ = json.Unmarshal(req.Params, &p)
		text := p.Arguments["text"]
		switch p.Name {
		case "leak":
			resp["result"] = map[string]any{
				"content": []any{
					map[string]any{"type": "text", "text": "here: " + text},
					map[string]any{"type": "resource", "resource": map[string]any{"uri": "file:///leak.txt", "text": text}},
				},
				"structuredContent": map[string]any{"value": text},
			}
		case "leak_split":
			half := len(text) / 2
			resp["result"] = map[string]any{"content": []any{
				map[string]any{"type": "text", "text": "start " + text[:half]},
				map[string]any{"type": "text", "text": text[half:] + " end"},
			}}
		case "leak_key":
			resp["result"] = map[string]any{"content": []any{}, "structuredContent": map[string]any{text: "owner"}}
		case "flood":
			n, _ := strconv.Atoi(p.Arguments["count"])
			resp["result"] = map[string]any{"content": []any{map[string]any{"type": "text", "text": strings.Repeat(text, min(max(n, 0), 1<<20))}}}
		case "fail_key":
			resp["error"] = map[string]any{"code": -32000, "message": "failed", "data": map[string]any{text: true}}
		case "fail":
			resp["error"] = map[string]any{"code": -32000, "message": "could not use " + text, "data": map[string]any{"detail": text}}
		default:
			resp["result"] = map[string]any{"content": []any{map[string]any{"type": "text", "text": "sent"}}}
		}
	default:
		resp["error"] = map[string]any{"code": -32601, "message": "method not found"}
	}
	return resp
}
