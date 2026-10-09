package pin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
)

// ReasonPinMismatch is the block reason for a tool that is not pinned as sent.
const ReasonPinMismatch = "pin_mismatch"

// Event kinds.
const (
	KindPinned       = "pinned"         // first sight, trusted (TOFU)
	KindChanged      = "changed"        // definition differs from the pin
	KindNewAfterPins = "new_after_pins" // a tool the pinned server never listed
	KindInvalid      = "invalid"        // definition has no canonical form
)

// tofuWindow is how long the first listing of a server may take across
// pages (nextCursor). Tools on later pages within it are trusted on first
// use too; after it, a server that keeps paginating gets no more free pins.
const tofuWindow = time.Minute

// maxToolName bounds a tool name (it becomes a database key).
const maxToolName = 1024

// Errors from Check. On any error the caller must not forward the list.
var (
	ErrToolsList = errors.New("tools/list result rejected by pinning")
	// ErrNotToolsList: the result has no "tools" member at all. For a reply
	// to tools/list that is still an error; for an uncorrelated result it
	// just means it is not a tool list.
	ErrNotToolsList = errors.New("result has no tools member")
)

// Event is one thing Check did, for the audit log and the notification.
type Event struct {
	Server, Tool, Kind string
	Old, New           Digest
	Diff               string // unified diff of pretty canonical JSON, at most 4 KiB
	Problem            string // KindInvalid: why
}

// Checker compares tools/list results with the pins in a Store. It is safe
// for concurrent use. Pins are cached in memory per server; the Store is the
// source of truth on start, and every change is written to it before Check
// returns.
type Checker struct {
	store Store
	now   func() time.Time
	logf  func(string, ...any)

	mu      sync.Mutex
	cache   map[string]map[string]Pinned // server -> tool -> pin
	tofu    map[string]time.Time         // server -> first-listing window start
	recheck map[string]bool
}

// NewChecker returns a Checker over store. now and logf may be nil.
func NewChecker(store Store, now func() time.Time, logf func(string, ...any)) *Checker {
	if now == nil {
		now = time.Now
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Checker{store: store, now: now, logf: logf, cache: map[string]map[string]Pinned{}, tofu: map[string]time.Time{}, recheck: map[string]bool{}}
}

// load returns the cached pins of server, reading the Store the first time.
func (c *Checker) load(server string) (map[string]Pinned, error) {
	if m, ok := c.cache[server]; ok {
		return m, nil
	}
	ps, err := c.store.List(server)
	if err != nil {
		return nil, err
	}
	m := make(map[string]Pinned, len(ps))
	for _, p := range ps {
		m[p.Tool] = p
	}
	c.cache[server] = m
	return m, nil
}

type listedTool struct {
	name string
	raw  json.RawMessage
}

// parseList reads a tools/list result strictly: its members, the tools
// array, and each tool's exact name. Duplicate names are refused (a client
// might use either copy).
func parseList(result []byte) (jsonrpc.Fields, int, []listedTool, bool, error) {
	members, err := jsonrpc.Object(result)
	if err != nil {
		return nil, 0, nil, false, fmt.Errorf("%w: %w", ErrToolsList, err)
	}
	at, more := -1, false
	for i, m := range members {
		switch m.Key {
		case "tools":
			at = i
		case "nextCursor":
			more = !bytes.Equal(bytes.TrimSpace(m.Value), []byte("null"))
		}
	}
	if at < 0 {
		return nil, 0, nil, false, ErrNotToolsList
	}
	var raws []json.RawMessage
	if err := json.Unmarshal(members[at].Value, &raws); err != nil {
		return nil, 0, nil, false, fmt.Errorf("%w: tools: %w", ErrToolsList, err)
	}
	tools := make([]listedTool, 0, len(raws))
	seen := map[string]bool{}
	for i, r := range raws {
		name, err := toolName(r)
		if err != nil {
			return nil, 0, nil, false, fmt.Errorf("%w: tool %d: %w", ErrToolsList, i, err)
		}
		if seen[name] {
			return nil, 0, nil, false, fmt.Errorf("%w: tool %q listed twice", ErrToolsList, name)
		}
		seen[name] = true
		tools = append(tools, listedTool{name, r})
	}
	return members, at, tools, more, nil
}

func toolName(raw json.RawMessage) (string, error) {
	fields, err := jsonrpc.Object(raw)
	if err != nil {
		return "", err
	}
	v, ok := fields.Get("name")
	if !ok {
		return "", errors.New("tool has no name")
	}
	var name string
	if err := json.Unmarshal(v, &name); err != nil {
		return "", errors.New("name is not a string")
	}
	if len(name) > maxToolName {
		return "", fmt.Errorf("name longer than %d bytes", maxToolName)
	}
	return name, nil
}

// Check compares a tools/list result (the value of "result") with the pins
// of server. A server with no pins is trusted on first use: every tool is
// pinned (method "tofu"). After that, a tool whose digest changed, a tool
// never seen before, or a tool with no canonical form is removed from the
// list and marked mismatched until Approve. changed reports whether filtered
// differs from listResult; filtered keeps every other byte of the original.
func (c *Checker) Check(server string, listResult json.RawMessage) (filtered json.RawMessage, changed bool, events []Event, err error) {
	members, at, tools, more, err := parseList(listResult)
	if err != nil {
		return nil, false, nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	pins, err := c.load(server)
	if err != nil {
		return nil, false, nil, fmt.Errorf("%w: load pins: %w", ErrToolsList, err)
	}
	now := c.now()
	tofu := c.tofuOpen(server, len(pins) == 0, now)

	var writes []Pinned
	kept := make([]json.RawMessage, 0, len(tools))
	for _, t := range tools {
		p, ev, keep := judgeTool(server, t, pins, tofu, now)
		if p != nil {
			writes = append(writes, *p)
		}
		if ev != nil {
			events = append(events, *ev)
		}
		if keep {
			kept = append(kept, t.raw)
		}
	}
	if !more {
		delete(c.tofu, server) // the first listing is complete
	}
	if err := c.store.Put(writes...); err != nil {
		return nil, false, nil, fmt.Errorf("%w: save pins: %w", ErrToolsList, err)
	}
	for _, p := range writes {
		pins[p.Tool] = p
	}
	delete(c.recheck, server)
	if len(kept) == len(tools) {
		return listResult, false, events, nil
	}
	return splice(listResult, members[at], joinArray(kept)), true, events, nil
}

// tofuOpen reports whether tools not yet pinned may be trusted on first use.
func (c *Checker) tofuOpen(server string, noPins bool, now time.Time) bool {
	if noPins {
		c.tofu[server] = now
		return true
	}
	start, ok := c.tofu[server]
	return ok && now.Sub(start) < tofuWindow
}

// judgeTool decides one listed tool: the record to write (nil: none), the
// event (nil: none) and whether the agent may see it.
func judgeTool(server string, t listedTool, pins map[string]Pinned, tofu bool, now time.Time) (*Pinned, *Event, bool) {
	canon, cerr := Canonical(t.raw)
	var d Digest
	problem := ""
	if cerr == nil {
		d = digest(canon)
	} else {
		problem = cerr.Error()
	}
	p, known := pins[t.name]
	switch {
	case !known && tofu && cerr == nil:
		np := Pinned{Server: server, Tool: t.name, Digest: d, ApprovedAt: now.UTC(), Method: MethodTOFU, Canonical: capCanonical(canon)}
		return &np, &Event{Server: server, Tool: t.name, Kind: KindPinned, New: d}, true
	case !known:
		np := Pinned{Server: server, Tool: t.name, Mismatch: true, Latest: d, LatestCanonical: capCanonical(canon), Problem: problem}
		kind := KindNewAfterPins
		if cerr != nil {
			kind = KindInvalid
		}
		return &np, mismatchEvent(np, kind), false
	case p.Mismatch:
		// Still blocked. Record what the server sends now; tell the user
		// only when it is something new.
		if p.Latest == d && p.Problem == problem {
			return nil, nil, false
		}
		p.Latest, p.LatestCanonical, p.Problem = d, capCanonical(canon), problem
		return &p, mismatchEvent(p, kindOf(p, cerr)), false
	case cerr != nil || d != p.Digest:
		p.Mismatch, p.Latest, p.LatestCanonical, p.Problem = true, d, capCanonical(canon), problem
		return &p, mismatchEvent(p, kindOf(p, cerr)), false
	default:
		return nil, nil, true
	}
}

func kindOf(p Pinned, cerr error) string {
	switch {
	case cerr != nil:
		return KindInvalid
	case p.Digest == "":
		return KindNewAfterPins
	default:
		return KindChanged
	}
}

func mismatchEvent(p Pinned, kind string) *Event {
	return &Event{Server: p.Server, Tool: p.Tool, Kind: kind, Old: p.Digest, New: p.Latest, Diff: DiffOf(p), Problem: p.Problem}
}

// AllowCall reports whether a tools/call of tool may proceed as far as pins
// are concerned. A server with no pins yet allows everything (there is
// nothing to compare against; policy still decides). Once a server is
// pinned, a mismatched tool or a tool it never listed is refused.
func (c *Checker) AllowCall(server, tool string) (ok bool, reason string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	pins, err := c.load(server)
	if err != nil {
		return false, "", err
	}
	if len(pins) == 0 {
		return true, "", nil
	}
	p, known := pins[tool]
	if !known || p.Mismatch {
		return false, ReasonPinMismatch, nil
	}
	return true, "", nil
}

// MarkRecheck notes a notifications/tools/list_changed. Every tools/list
// result is checked anyway; the mark only records that one is expected.
func (c *Checker) MarkRecheck(server string) {
	c.mu.Lock()
	c.recheck[server] = true
	c.mu.Unlock()
}

// RecheckPending reports whether server announced a change that no
// tools/list has been checked against since.
func (c *Checker) RecheckPending(server string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.recheck[server]
}

// ErrNothingToApprove is returned by Approve for a tool that is not blocked.
var ErrNothingToApprove = errors.New("nothing to approve")

// Approve re-pins a mismatched tool to the definition the server sent most
// recently. TODO(M9): only after OS authentication; until then the CLI is
// the only caller, and it is not reachable through the MCP stream.
func (c *Checker) Approve(server, tool, method string) (Pinned, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	pins, err := c.load(server)
	if err != nil {
		return Pinned{}, err
	}
	p, known := pins[tool]
	switch {
	case !known:
		return Pinned{}, fmt.Errorf("%w: %s/%s has never been listed", ErrNothingToApprove, server, tool)
	case !p.Mismatch:
		return Pinned{}, fmt.Errorf("%w: %s/%s matches its pin", ErrNothingToApprove, server, tool)
	case p.Latest == "":
		return Pinned{}, fmt.Errorf("%s/%s cannot be approved: its definition has no canonical form (%s)", server, tool, p.Problem)
	}
	np := Pinned{Server: server, Tool: tool, Digest: p.Latest, ApprovedAt: c.now().UTC(), Method: method, Canonical: p.LatestCanonical}
	if err := c.store.Put(np); err != nil {
		return Pinned{}, err
	}
	pins[tool] = np
	return np, nil
}

// Reset forgets every pin of server; its next tools/list is trusted on
// first use again. TODO(M9): OS authentication.
func (c *Checker) Reset(server string) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err := c.store.DeleteServer(server)
	delete(c.cache, server) // reload from the store either way
	delete(c.tofu, server)
	return n, err
}

// List returns the stored pins of server ("" for all), read fresh.
func (c *Checker) List(server string) ([]Pinned, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.store.List(server)
}

func joinArray(items []json.RawMessage) []byte {
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, it := range items {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(it)
	}
	buf.WriteByte(']')
	return buf.Bytes()
}

func splice(raw []byte, f jsonrpc.Field, v []byte) []byte {
	out := make([]byte, 0, len(raw)-(f.End-f.Start)+len(v))
	out = append(out, raw[:f.Start]...)
	out = append(out, v...)
	return append(out, raw[f.End:]...)
}
