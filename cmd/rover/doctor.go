package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/DreadpiratePickles/rover/internal/clients"
	"github.com/DreadpiratePickles/rover/internal/daemon"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/paths"
)

// `rover doctor`: one line per check, in the cwm style of plan §4.7: plain
// fixed-width columns, no boxes or symbols, and colour only on a terminal,
// and then only the cwm "urgent" colour #FC8814 for WARN and FAIL.

// urgent is cwm's urgent border colour, #FC8814, as a 24-bit SGR sequence.
const (
	urgent    = "\x1b[38;2;252;136;20m"
	sgrReset  = "\x1b[0m"
	nameWidth = 15
)

func runDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print the checks as JSON (for scripts)")
	_ = fs.Parse(args)

	checks, err := doctorChecks()
	if err != nil {
		fmt.Fprintln(os.Stderr, "rover doctor:", err)
		return 1
	}
	if *asJSON {
		err = writeDoctorJSON(os.Stdout, checks)
	} else {
		err = writeDoctor(os.Stdout, checks, isTerminal(os.Stdout) && isTerminal(os.Stderr))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "rover doctor:", err)
		return 1
	}
	return doctorExit(checks)
}

// doctorChecks runs every check against this machine.
func doctorChecks() ([]check, error) {
	dirs, err := paths.Resolve()
	if err != nil {
		return nil, err
	}
	sock, err := paths.SocketPath(dirs)
	if err != nil {
		return nil, err
	}
	env, _, envErr := clientEnv()
	if envErr != nil {
		home, _ := os.UserHomeDir()
		env = clients.Env{Home: home, BackupDir: filepath.Join(dirs.State, "backups")}
	}
	rover, roverErr := selfPath("")

	st, stErr := fetchDoctorState(sock, ipc.Admin)
	out := []check{checkDaemon(st, stErr), checkSocket(sock, os.Getuid()), checkDirs(dirs)}
	_, cfg, note, _, perr := loadAll(dirs)
	disk, diskErr := loadedHash(dirs)
	approved, apprErr := approvedPolicy(st, stErr, filepath.Join(dirs.State, "state.db"))
	out = append(out, checkPolicy(string(cfg.Mode), note, perr, daemonState(st, stErr)), checkPolicyApproval(disk, diskErr, approved, apprErr))
	if roverErr != nil {
		out = append(out, fail("client", "cannot tell which rover binary this is: %v", roverErr))
	} else {
		out = append(out, checkClients(env, clients.All(env), rover)...)
	}
	out = append(out, checkAudit(defaultLogPath()), checkTLS(probeTLS), checkNet(), checkTamper(st, stErr))
	return out, nil
}

func doctorExit(checks []check) int {
	for _, c := range checks {
		if c.Status == statusFail {
			return 1
		}
	}
	return 0
}

// writeDoctor prints `STATUS  name  detail` lines.
func writeDoctor(w io.Writer, checks []check, colour bool) error {
	for _, c := range checks {
		status := c.Status
		if colour && status != statusPass {
			status = urgent + status + sgrReset
		}
		if _, err := fmt.Fprintf(w, "%s  %-*s  %s\n", status, nameWidth, c.Name, cell(c.Detail)); err != nil {
			return err
		}
	}
	return nil
}

func writeDoctorJSON(w io.Writer, checks []check) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		OK     bool    `json:"ok"`
		Checks []check `json:"checks"`
	}{doctorExit(checks) == 0, checks})
}

// daemonState is st when roverd answered, else nil.
func daemonState(st *daemon.DoctorState, err error) *daemon.DoctorState {
	if err != nil {
		return nil
	}
	return st
}
