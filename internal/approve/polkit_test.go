package approve

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakePkcheck writes a script that records its arguments and exits code.
func fakePkcheck(t *testing.T, code string) (bin, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	bin = filepath.Join(dir, "pkcheck")
	script := "#!/bin/sh\necho \"$@\" > " + argsFile + "\necho 'pkcheck: no agent' >&2\nexit " + code + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { //nolint:gosec // G306: an executable test script
		t.Fatal(err)
	}
	return bin, argsFile
}

func polkitWith(bin string) Polkit {
	return Polkit{Pkcheck: bin, PID: 4242, UID: 501, StartTime: func(int) (uint64, error) { return 987654, nil }}
}

// Acceptance (plan M9): headless Linux, no polkit agent (pkcheck exit 2)
// means deny, logged as no_auth_agent.
func TestHeadlessPkcheckDeniesWithNoAuthAgent(t *testing.T) {
	// Arrange
	bin, argsFile := fakePkcheck(t, "2")
	f, _, _ := flow(polkitWith(bin), nil)
	var logs []string
	f.Logf = func(format string, a ...any) { logs = append(logs, fmt.Sprintf(format, a...)) }

	// Act
	d, _ := f.Prompt(context.Background(), request())

	// Assert
	if d.Allow || d.Method != ReasonNoAuthAgent || !strings.Contains(strings.Join(logs, "\n"), "no_auth_agent") {
		t.Fatalf("decision %+v, logs %q", d, logs)
	}
	args, _ := os.ReadFile(argsFile) //nolint:gosec // G304: the test's temp file
	if got := strings.TrimSpace(string(args)); got != "--action-id org.rover.approve --process 4242,987654,501 --allow-user-interaction" {
		t.Fatalf("pkcheck args %q", got)
	}
}

func TestPkcheckExitCodes(t *testing.T) {
	for code, want := range map[string]struct {
		ok      bool
		noAgent bool
		isErr   bool
	}{"0": {ok: true}, "1": {isErr: true}, "2": {noAgent: true, isErr: true}, "3": {}, "127": {isErr: true}} {
		bin, _ := fakePkcheck(t, code)
		ok, method, err := polkitWith(bin).Authenticate(context.Background(), "x")
		if ok != want.ok || method != "polkit" || (err != nil) != want.isErr || errors.Is(err, ErrNoAuthAgent) != want.noAgent {
			t.Errorf("exit %s: ok %v err %v", code, ok, err)
		}
	}
}

func TestMissingPkcheckDenies(t *testing.T) {
	ok, _, err := polkitWith(filepath.Join(t.TempDir(), "absent")).Authenticate(context.Background(), "x")
	if ok || err == nil {
		t.Fatalf("ok %v err %v", ok, err)
	}
}

func TestParseStartTimeCountsFromTheLastParen(t *testing.T) {
	// comm may contain ") " itself; starttime is field 22.
	stat := "1234 (evil) 1 2 3) S 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 55555 1000 10 18446744073709551615"
	got, err := parseStartTime([]byte(stat))
	if err != nil || got != 55555 {
		t.Fatalf("got %d, %v", got, err)
	}
	if _, err := parseStartTime([]byte("1234 (x) S 1")); err == nil {
		t.Fatal("short stat must fail")
	}
}

func TestPolkitPolicyIsAuthSelfWithoutKeep(t *testing.T) {
	if !strings.Contains(PolkitPolicy, "<allow_active>auth_self</allow_active>") || strings.Contains(PolkitPolicy, "_keep") ||
		!strings.Contains(PolkitPolicy, `id="`+PolkitAction+`"`) {
		t.Fatal(PolkitPolicy)
	}
}

func TestDenyAuthenticatorAlwaysDenies(t *testing.T) {
	ok, _, err := Deny{Why: "test"}.Authenticate(context.Background(), "x")
	if ok || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ok %v err %v", ok, err)
	}
}
