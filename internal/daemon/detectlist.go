package daemon

import (
	"errors"
	"fmt"

	"github.com/DreadpiratePickles/rover/internal/detect"
	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
)

// listTool is one entry of a tools/list result: its bytes and members,
// offsets absolute in the result.
type listTool struct {
	at     [2]int
	name   string
	fields jsonrpc.Fields
}

// detectList scans every tool of one tools/list page (result, the value of
// "result"; cursor, the request's params.cursor) and removes the tools with
// a high finding. findings are the ids of everything else (medium and low),
// for the list's audit entry; flags are the medium ones, which flag the
// tools/list observation in learn mode (M6).
//
// Which tools exist is remembered per session and per server (review M4):
// one agent's evil server cannot make tool names count against another
// agent's servers, and a server's own names never count against itself.
func (s *Server) detectList(sess *Session, server string, result []byte, cursor string) (rep []byte, removed []poisonEvent, findings, flags []string, err error) {
	members, err := splitObject(result, 0, len(result))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	tf, ok := field(members, "tools")
	if !ok {
		return result, nil, nil, nil, nil
	}
	next := ""
	if nf, ok := field(members, "nextCursor"); ok {
		next, _ = stringValue(nf.Value)
	}
	els, err := splitArray(result, tf.Start, tf.End)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("tools: %w", err)
	}
	tools := make([]listTool, 0, len(els))
	names := make([]string, 0, len(els))
	for i, e := range els {
		fs, ferr := splitObject(result, e[0], e[1])
		if ferr != nil {
			return nil, nil, nil, nil, fmt.Errorf("tool %d: %w", i, ferr)
		}
		nf, _ := field(fs, "name")
		name, isString := stringValue(nf.Value)
		if !isString {
			return nil, nil, nil, nil, fmt.Errorf("tool %d: name is not a string", i)
		}
		tools = append(tools, listTool{at: e, name: name, fields: fs})
		names = append(names, name)
	}
	// Own names: everything this server ever listed in the session, and
	// every tool it has pinned. Until a paged listing is complete, its
	// later pages may still hold the name a description refers to, so a
	// bare name mention cannot be high yet (review N2).
	own := names
	if pinned, perr := s.pins.List(server); perr == nil {
		for _, p := range pinned {
			own = append(own, p.Tool)
		}
	}
	known := sess.noteTools(server, own)
	opts := []detect.Option{detect.WithKnownTools(known), detect.WithServer(server)}
	if cursor != "" || next != "" {
		opts = append(opts, detect.WithProvisionalNames())
	}
	rules := detect.NewRules(opts...)
	kept := make([][]byte, 0, len(tools))
	var all []detect.Finding
	for _, t := range tools {
		fs, serr := scanTool(rules, result, t)
		if serr != nil {
			return nil, nil, nil, nil, fmt.Errorf("tool %q: %w", t.name, serr)
		}
		if detect.Max(fs) == detect.High {
			removed = append(removed, poisonEvent{server: server, tool: t.name, ids: detect.Score(fs).IDs})
			continue
		}
		all = append(all, fs...)
		kept = append(kept, result[t.at[0]:t.at[1]])
	}
	s.det.page(server, cursor, next, removed)
	findings, flags = detect.Score(all).IDs, flagIDs(all)
	if len(removed) == 0 {
		return result, nil, findings, flags, nil
	}
	rep, err = applyEdits(result, []edit{{tf.Start, tf.End, joinArray(kept)}})
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return rep, removed, findings, flags, nil
}

// scanTool scans every string of a tool the model may read: name, title,
// description, annotations.title, and every key and string of inputSchema
// and outputSchema, each decoded and scanned on its own (reviews M3, N1).
func scanTool(rules detect.Scanner, b []byte, t listTool) ([]detect.Finding, error) {
	fs := rules.Scan(detect.KindToolDescription, []byte(t.name))
	scan := func(text []byte) { fs = append(fs, rules.Scan(detect.KindToolDescription, text)...) }
	for _, key := range []string{"title", "description"} {
		if f, ok := field(t.fields, key); ok {
			text, isString := textValue(f.Value)
			if !isString {
				return nil, errors.New(key + " is not a string")
			}
			scan(text)
		}
	}
	if a, ok := field(t.fields, "annotations"); ok {
		af, err := splitObject(b, a.Start, a.End)
		if err != nil {
			return nil, fmt.Errorf("annotations: %w", err)
		}
		if f, ok := field(af, "title"); ok {
			if text, isString := textValue(f.Value); isString {
				scan(text)
			}
		}
	}
	for _, key := range []string{"inputSchema", "outputSchema"} {
		if f, ok := field(t.fields, key); ok {
			// every key and string, decoded: property names and enum
			// values reach the model as much as descriptions do
			if err := walkAll(b, f.Start, f.End, scan, 0); err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
		}
	}
	return fs, nil
}
