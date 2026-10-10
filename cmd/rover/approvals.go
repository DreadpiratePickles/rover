package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/DreadpiratePickles/rover/internal/approve"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/paths"
)

const approvalsUsage = `usage:
  rover approvals list    the approvals waiting for you: id, client, server.tool, age and
                          the read-only details page (it cannot approve; the system dialog does)`

// runApprovals dispatches `rover approvals <sub>` (M9). Listing is
// read-only; there is deliberately no approve subcommand.
func runApprovals(args []string) int {
	if len(args) != 1 || args[0] != "list" {
		fmt.Fprintln(os.Stderr, approvalsUsage)
		return 2
	}
	dirs, err := paths.Resolve()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	sock, err := paths.SocketPath(dirs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	res, err := ipc.Admin(sock, ipc.Frame{Op: ipc.OpApprovalsList})
	if errors.Is(err, ipc.ErrNoDaemon) {
		fmt.Println("roverd is not running: no approvals are pending")
		return 0
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "rover approvals:", err)
		return 1
	}
	var list []approve.PendingApproval
	if err := json.Unmarshal(res.Result, &list); err != nil {
		fmt.Fprintln(os.Stderr, "rover approvals:", err)
		return 1
	}
	return printApprovals(os.Stdout, list, time.Now())
}

// printApprovals prints plain fixed-width columns (plan §4.7, cwm style).
func printApprovals(w io.Writer, list []approve.PendingApproval, now time.Time) int {
	if len(list) == 0 {
		_, _ = fmt.Fprintln(w, "no approvals pending")
		return 0
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tCLIENT\tCALL\tAGE\tPAGE")
	for _, p := range list {
		age := now.Sub(p.Created).Round(time.Second)
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s.%s\t%s\t%s\n", approve.ShortID(p.ID), cell(p.Client), cell(p.Server), cell(p.Tool), age, orDash(p.URL))
	}
	if err := tw.Flush(); err != nil {
		return 1
	}
	return 0
}
