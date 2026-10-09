package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/daemon"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/paths"
	"github.com/DreadpiratePickles/rover/internal/pin"
	"github.com/DreadpiratePickles/rover/internal/state"
)

const pinUsage = `usage:
  rover pin list [server]            show pinned tools; a MISMATCH or new tool gets a diff
  rover pin approve <server> <tool> <digest>
                                     trust the definition with this digest (the 12+ hex
                                     digits "rover pin list" prints); refused if the
                                     server changed the tool again since
  rover pin reset <server>           forget a server's pins: its next tools/list is trusted on first use

roverd holds the state database locked while it runs (bbolt allows no reader
beside a writer), so these commands ask roverd over its socket; with no
roverd running they open the database themselves.`

// runPin dispatches `rover pin <sub>`.
func runPin(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, pinUsage)
		return 2
	}
	var req ipc.Frame
	switch {
	case args[0] == "list" && len(args) <= 2:
		req = ipc.Frame{Op: ipc.OpPinList}
		if len(args) == 2 {
			req.ServerName = args[1]
		}
	case args[0] == "approve" && len(args) == 4:
		// TODO(M9): OS authentication. Until then anyone who can run this
		// CLI as the user can approve, which the plan accepts for M4.
		req = ipc.Frame{Op: ipc.OpPinApprove, ServerName: args[1], Tool: args[2], Digest: args[3]}
	case args[0] == "reset" && len(args) == 2:
		// TODO(M9): OS authentication.
		req = ipc.Frame{Op: ipc.OpPinReset, ServerName: args[1]}
	default:
		fmt.Fprintln(os.Stderr, pinUsage)
		return 2
	}
	req.Type = ipc.TypeAdmin
	if err := req.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	result, err := pinAdmin(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rover pin:", err)
		return 1
	}
	switch req.Op {
	case ipc.OpPinList:
		return printPins(result)
	case ipc.OpPinApprove:
		var p pin.Pinned
		if err := json.Unmarshal(result, &p); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("approved %s/%s: pinned to %s (method %s)\n", cell(p.Server), cell(p.Tool), p.Digest.Short(), p.Method)
	case ipc.OpPinReset:
		var r struct{ Removed int }
		_ = json.Unmarshal(result, &r)
		fmt.Printf("removed %d pin(s) for %s; its next tools/list is trusted on first use\n", r.Removed, req.ServerName)
	}
	fmt.Println("TODO(M9): this will require OS authentication")
	return 0
}

// pinAdmin asks roverd; if none is running it does the same work itself on
// the state database (whose lock keeps a daemon from starting meanwhile).
func pinAdmin(req ipc.Frame) (json.RawMessage, error) {
	dirs, err := paths.Resolve()
	if err == nil {
		err = paths.Ensure(dirs)
	}
	if err != nil {
		return nil, err
	}
	sock, err := paths.SocketPath(dirs)
	if err != nil {
		return nil, err
	}
	f, err := ipc.Admin(sock, req)
	if err == nil {
		return f.Result, nil
	}
	if !errors.Is(err, ipc.ErrNoDaemon) {
		return nil, err
	}
	db, err := state.Open(filepath.Join(dirs.State, "state.db"))
	if errors.Is(err, state.ErrLocked) {
		return nil, errors.New("roverd holds the state database but did not answer on its socket; is it stuck?")
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	o := daemon.Options{State: db}
	if req.Op != ipc.OpPinList {
		logPath := filepath.Join(dirs.State, "audit.jsonl")
		log, err := audit.Open(logPath)
		if err != nil {
			return nil, fmt.Errorf("audit log: %w", err)
		}
		defer func() { _ = log.Close() }()
		log.AnchorPath = anchorPath(logPath)
		o.Audit = log
	}
	resp := daemon.New(o).Admin(req)
	if resp.Type == ipc.TypeError {
		return nil, errors.New(resp.Message)
	}
	return resp.Result, nil
}

// printPins prints the table, then the diff of every blocked tool.
func printPins(result json.RawMessage) int {
	var ps []pin.Pinned
	if err := json.Unmarshal(result, &ps); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if len(ps) == 0 {
		fmt.Println("no pins yet: a server is pinned the first time it answers tools/list")
		return 0
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SERVER\tTOOL\tDIGEST\tAPPROVED\tMETHOD\tSTATE")
	for _, p := range ps {
		approved := "-"
		if !p.ApprovedAt.IsZero() {
			approved = p.ApprovedAt.UTC().Format(time.RFC3339)
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", cell(p.Server), cell(p.Tool), orDash(p.Digest.Short()), approved, orDash(p.Method), p.State())
	}
	if err := tw.Flush(); err != nil {
		return 1
	}
	for _, p := range ps {
		if !p.Mismatch {
			continue
		}
		approve := "cannot be approved (no canonical form)"
		if p.Latest != "" {
			approve = fmt.Sprintf("approve with: rover pin approve %s %s %s", cell(p.Server), cell(p.Tool), p.Latest.Short())
		}
		fmt.Printf("\n%s %s/%s (latest %s); %s\n", p.State(), cell(p.Server), cell(p.Tool), orDash(p.Latest.Short()), approve)
		fmt.Print(pin.TerminalSafe(pin.DiffOf(p)))
	}
	return 0
}

// cell makes server-supplied text safe for one table cell on a terminal.
func cell(s string) string {
	return strings.NewReplacer("\t", `\t`, "\n", `\n`).Replace(pin.TerminalSafe(s))
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
