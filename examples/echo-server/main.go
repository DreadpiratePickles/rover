// echo-server is a deliberately tiny MCP server written WITHOUT an SDK (module A0).
//
// The point is to see the protocol with nothing hiding it. It exposes two tools:
//
//	echo       - harmless: returns its input
//	read_file  - DANGEROUS ON PURPOSE: reads any path it is given.
//	             This is the target for the A2 policy lab ("only allow ./sandbox").
//
// Never point a real agent at read_file outside the lab.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const latestProtocol = "2025-06-18"

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

var tools = []map[string]any{
	{
		"name":        "echo",
		"description": "Returns the text you send it.",
		"inputSchema": map[string]any{
			"type":       "object",
			"properties": map[string]any{"text": map[string]any{"type": "string"}},
			"required":   []string{"text"},
		},
	},
	{
		"name":        "read_file",
		"description": "Reads a file from disk and returns its contents.",
		"inputSchema": map[string]any{
			"type":       "object",
			"properties": map[string]any{"path": map[string]any{"type": "string"}},
			"required":   []string{"path"},
		},
	},
}

func main() {
	// stdout is the protocol channel. Anything human-readable goes to stderr,
	// or it would corrupt the JSON-RPC stream.
	logf := func(format string, a ...any) { fmt.Fprintf(os.Stderr, "[echo-server] "+format+"\n", a...) }

	in := bufio.NewReader(os.Stdin)
	enc := json.NewEncoder(os.Stdout) // Encode writes one JSON value + "\n": exactly MCP stdio framing.

	for {
		line, err := in.ReadBytes('\n')
		if len(line) > 0 {
			var req request
			if jerr := json.Unmarshal(line, &req); jerr != nil {
				_ = enc.Encode(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}})
			} else if len(req.ID) == 0 {
				logf("notification: %s", req.Method) // notifications never get a reply
			} else {
				_ = enc.Encode(handle(req))
			}
		}
		if err == io.EOF {
			return // client closed stdin: the MCP way of saying "shut down"
		}
		if err != nil {
			logf("read error: %v", err)
			return
		}
	}
}

func handle(req request) response {
	resp := response{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		version := latestProtocol
		if p.ProtocolVersion != "" {
			version = p.ProtocolVersion // naive negotiation: agree with the client
		}
		resp.Result = map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "rover-echo", "version": "0.1.0"},
		}
	case "ping":
		resp.Result = map[string]any{}
	case "tools/list":
		resp.Result = map[string]any{"tools": tools}
	case "tools/call":
		resp.Result = callTool(req.Params)
	default:
		resp.Error = &rpcError{-32601, "method not found: " + req.Method}
	}
	return resp
}

func callTool(params json.RawMessage) map[string]any {
	var p struct {
		Name      string            `json:"name"`
		Arguments map[string]string `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return toolError("bad params: " + err.Error())
	}
	switch p.Name {
	case "echo":
		return toolText(p.Arguments["text"])
	case "read_file":
		b, err := os.ReadFile(p.Arguments["path"]) // no checks at all - that's the lab
		if err != nil {
			return toolError(err.Error())
		}
		return toolText(string(b))
	default:
		return toolError("unknown tool: " + p.Name)
	}
}

// Tool failures are reported INSIDE a normal result with isError=true,
// not as JSON-RPC errors, so the model can see what went wrong.
func toolText(s string) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": s}}}
}

func toolError(s string) map[string]any {
	r := toolText(s)
	r["isError"] = true
	return r
}
