package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/DreadpiratePickles/rover/internal/approve"
	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/clients"
	"github.com/DreadpiratePickles/rover/internal/daemon"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/paths"
	"github.com/DreadpiratePickles/rover/internal/state"
)

// Each doctor check is a function of its inputs, so tests can feed it a
// broken socket, a tampered log or an unwrapped config without a machine
// in that state.

// Check statuses.
const (
	statusPass = "PASS"
	statusWarn = "WARN"
	statusFail = "FAIL"
)

type check struct {
	Status string `json:"status"`
	Name   string `json:"name"`
	Detail string `json:"detail"`
}

func pass(name, f string, a ...any) check { return check{statusPass, name, fmt.Sprintf(f, a...)} }
func warn(name, f string, a ...any) check { return check{statusWarn, name, fmt.Sprintf(f, a...)} }
func fail(name, f string, a ...any) check { return check{statusFail, name, fmt.Sprintf(f, a...)} }

// fetchDoctorState asks roverd for its view (doctor_state).
func fetchDoctorState(sock string, admin func(string, ipc.Frame) (ipc.Frame, error)) (*daemon.DoctorState, error) {
	f, err := admin(sock, ipc.Frame{Op: ipc.OpDoctorState})
	if err != nil {
		return nil, err
	}
	var st daemon.DoctorState
	if err := json.Unmarshal(f.Result, &st); err != nil {
		return nil, fmt.Errorf("doctor_state: %w", err)
	}
	return &st, nil
}

func checkDaemon(st *daemon.DoctorState, err error) check {
	switch {
	case errors.Is(err, ipc.ErrNoDaemon):
		return warn("daemon", "roverd is not running; it starts with the first wrapped server, or run `rover install --service`")
	case err != nil:
		return fail("daemon", "roverd did not answer: %v; restart it", err)
	case !st.AuditHealthy:
		return fail("daemon", "roverd's audit log failed and it is blocking everything; restart roverd and check the log")
	}
	return pass("daemon", "roverd answered (mode %s, protocol %d)", orDash(st.Mode), st.ServerVersion)
}

func checkSocket(sock string, uid int) check {
	fi, err := os.Lstat(sock)
	if errors.Is(err, os.ErrNotExist) {
		return warn("socket", "%s does not exist (roverd not running)", sock)
	}
	if err != nil {
		return fail("socket", "%v", err)
	}
	if fi.Mode().Type() != os.ModeSocket {
		return fail("socket", "%s is not a socket; remove it and restart roverd", sock)
	}
	if err := paths.CheckPrivate(sock, 0o600); err != nil {
		return fail("socket", "%v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		return fail("socket", "%s is %04o, want 0600", sock, fi.Mode().Perm())
	}
	return pass("socket", "%s is 0600, owned by uid %d", sock, uid)
}

func checkDirs(d paths.Dirs) check {
	for _, dir := range []string{d.Config, d.State, d.Run} {
		if err := paths.CheckPrivate(dir, 0o700); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return warn("dirs", "%s does not exist yet (created on first use)", dir)
			}
			return fail("dirs", "%v", err)
		}
	}
	return pass("dirs", "config, state and run are 0700 and yours")
}

// checkPolicy loads the policy exactly as roverd does (loadAll). st is
// roverd's view (nil when it is not running): files that load but are not
// approved leave roverd with no policy, in enforce.
func checkPolicy(mode, note string, err error, st *daemon.DoctorState) check {
	if st != nil && !st.PolicyLoaded {
		return fail("policy", "no policy (%s): roverd blocks every policed message until `rover policy apply` succeeds", orDash(st.Mode))
	}
	if err != nil {
		return fail("policy", "%v; roverd blocks every policed message until it loads (`rover policy validate`)", err)
	}
	return pass("policy", "loads, mode %s%s", mode, map[bool]string{true: " (" + note + ")"}[note != ""])
}

// checkPolicyApproval compares the hash of the policy files on disk with
// the approved one (M9). A mismatch means someone changed the policy, or
// config.yaml, without `rover policy apply`: roverd will not load it.
//
// distrusted is what roverd's own check (distrust) says about the approval
// in state.db; doctor fails whenever roverd would refuse it.
func checkPolicyApproval(disk string, diskErr error, approved *approve.PolicyApproval, approvedErr error, distrusted string) check {
	switch {
	case distrusted != "":
		return fail("policy-approval", "roverd will not load a policy: %s; check who changed it, then `rover policy apply`", distrusted)
	case approvedErr != nil:
		return fail("policy-approval", "cannot read approved_policy: %v", approvedErr)
	case diskErr != nil:
		return fail("policy-approval", "cannot hash the policy files: %v", diskErr)
	case approved == nil:
		return fail("policy-approval", "no policy has been approved; roverd loads none until `rover policy apply` (hash on disk %s)", short(disk))
	case approved.Hash != disk:
		return fail("policy-approval", "TAMPERED or not yet applied: the policy files on disk (hash %s) are not the approved policy %s (approved %s by %s); roverd will not load them. Check who changed them, then `rover policy apply`",
			short(disk), short(approved.Hash), approved.ApprovedAt.UTC().Format(time.RFC3339), approved.Method)
	}
	return pass("policy-approval", "the files on disk are the approved policy %s (approved %s by %s)", short(disk), approved.ApprovedAt.UTC().Format(time.RFC3339), approved.Method)
}

// approvedPolicy reads the approved policy from roverd's doctor_state, or
// from the state database when roverd is not running.
func approvedPolicy(st *daemon.DoctorState, stErr error, stateDB string) (*approve.PolicyApproval, error) {
	if stErr == nil {
		if st.ApprovedErr != "" {
			return nil, errors.New(st.ApprovedErr)
		}
		return st.ApprovedPolicy, nil
	}
	if _, err := os.Stat(stateDB); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	db, err := state.Open(stateDB)
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	a, found, err := approve.CurrentPolicy(db)
	if err != nil || !found {
		return nil, err
	}
	return &a, nil
}

// checkClients reports, per config file, whether every server runs through
// this rover binary.
func checkClients(env clients.Env, adapters []clients.Adapter, rover string) []check {
	installed, errs := clients.InstalledFiles(env.BackupDir)
	var out []check
	for _, err := range errs {
		out = append(out, fail("client", "backup manifest unreadable, the config it records is unknown: %v", err))
	}
	found := false
	for _, a := range adapters {
		files, err := a.Detect()
		if errors.Is(err, clients.ErrUnsupported) {
			continue
		}
		if err != nil {
			out = append(out, fail("client", "%s: %v", a.Name(), err))
			continue
		}
		seen := map[string]bool{}
		for _, f := range append(files, installed...) {
			if f.Adapter != a.Name() || seen[f.Path] {
				continue
			}
			seen[f.Path] = true
			if _, err := os.Stat(f.Path); err != nil {
				continue
			}
			found = true
			out = append(out, checkClientFile(a, f, rover))
		}
	}
	if !found {
		out = append(out, warn("client", "no client configs found; nothing is wrapped (`rover install`)"))
	}
	return out
}

// checkClientFile fails on any server that does not run through rover:
// unwrapped, wrapped by another binary, or not understood (a server rover
// cannot parse is one it cannot vouch for). Every problem is listed.
func checkClientFile(a clients.Adapter, f clients.ConfigFile, rover string) check {
	where := a.Name() + " " + f.Path
	doc, err := a.Read(f)
	if err != nil {
		return fail("client", "%s: does not parse: %v", where, err)
	}
	var problems, remote []string
	wrapped := 0
	for _, s := range doc.Servers {
		switch {
		case s.Status == clients.StatusStdio:
			problems = append(problems, "not wrapped: "+s.Key)
		case s.Status == clients.StatusUnknown:
			problems = append(problems, "not understood: "+s.Key+" ("+s.Problem+")")
		case s.Status == clients.StatusWrapped && !s.WrappedBy(rover):
			problems = append(problems, "wrapped by "+s.Command+", not "+rover+": "+s.Key)
		case s.Status == clients.StatusWrapped:
			wrapped++
		case s.Status == clients.StatusRemote:
			remote = append(remote, s.Key)
		}
	}
	switch {
	case len(problems) > 0:
		return fail("client", "%s: %s; check it, then run `rover install`", where, cell(strings.Join(problems, "; ")))
	case len(remote) > 0:
		return warn("client", "%s: %d wrapped; remote and not bridged (run `rover install`, or see its warning): %s", where, wrapped, cell(strings.Join(remote, ", ")))
	}
	return pass("client", "%s: all %d servers wrapped", where, wrapped)
}

func checkAudit(logPath string) check {
	files, err := audit.ChainFiles(logPath)
	if err != nil {
		return fail("audit", "%v", err)
	}
	if len(files) == 0 {
		return warn("audit", "%s does not exist yet (roverd creates it)", logPath)
	}
	anchor, err := audit.ReadAnchor(anchorPath(logPath))
	if err != nil {
		return fail("audit", "anchor: %v", err)
	}
	res := audit.VerifyChain(files, anchor)
	if res.Err != nil {
		return fail("audit", "%s line %d: %v", res.File, res.Line, res.Err)
	}
	a := "no anchor"
	if anchor != "" {
		a = "anchor matches"
	}
	return pass("audit", "%d entries in %d file(s), chain intact, %s", res.Entries, len(files), a)
}

// checkTLS runs probe, an in-process handshake with crypto/tls defaults.
func checkTLS(probe func() (tls.CurveID, error)) check {
	id, err := probe()
	if err != nil {
		return fail("tls-pq", "in-process TLS handshake failed: %v", err)
	}
	if id != tls.X25519MLKEM768 {
		return fail("tls-pq", "key exchange was %v, not X25519MLKEM768 (is GODEBUG=tlsmlkem=0 set?)", id)
	}
	return pass("tls-pq", "crypto/tls defaults negotiate X25519MLKEM768 (post-quantum hybrid)")
}

func checkNet() check {
	return warn("rover-net", "not configured until N5")
}

func checkTamper(st *daemon.DoctorState, err error) check {
	if err != nil {
		return warn("tamper", "unknown: roverd is not answering, so no tamper watch is running")
	}
	if len(st.TamperAlerts) == 0 {
		return pass("tamper", "no alerts (%d config file(s) watched)", st.WatchedFiles)
	}
	var parts []string
	for _, a := range st.TamperAlerts {
		parts = append(parts, fmt.Sprintf("%s %s in %s", a.Server, a.Kind, a.File))
	}
	return fail("tamper", "%s; rerun `rover install` after checking who changed it", cell(strings.Join(parts, "; ")))
}

// probeTLS handshakes a client and a server over an in-memory pipe, both
// with crypto/tls default curve preferences, and returns the key exchange
// they agreed on. Nothing touches the network.
func probeTLS() (tls.CurveID, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return 0, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"doctor.rover.test"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return 0, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return 0, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	deadline := now.Add(5 * time.Second)
	_ = a.SetDeadline(deadline)
	_ = b.SetDeadline(deadline)
	srv := tls.Server(a, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13})
	cli := tls.Client(b, &tls.Config{RootCAs: pool, ServerName: "doctor.rover.test", MinVersion: tls.VersionTLS13})
	errc := make(chan error, 1)
	go func() { errc <- srv.Handshake() }()
	if err := cli.Handshake(); err != nil {
		return 0, err
	}
	if err := <-errc; err != nil {
		return 0, err
	}
	return cli.ConnectionState().CurveID, nil
}
