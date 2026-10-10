package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/rover/internal/paths"
)

// fakeCedar puts a `cedar` script on a fresh PATH directory. It records
// its arguments and the mode of the --schema file, prints a line and exits
// with code. It returns the PATH directory and the record file.
func fakeCedar(t *testing.T, code int) (binDir, record string) {
	t.Helper()
	binDir = t.TempDir()
	record = filepath.Join(binDir, "args")
	script := "#!/bin/sh\n" +
		"echo \"$@\" > '" + record + "'\n" +
		"/bin/ls -l \"$3\" >> '" + record + "'\n" +
		"echo 'fake cedar says hello'\n" +
		"exit " + string(rune('0'+code)) + "\n"
	if err := os.WriteFile(filepath.Join(binDir, "cedar"), []byte(script), 0o700); err != nil { //nolint:gosec // G306: test script must be executable
		t.Fatal(err)
	}
	return binDir, record
}

func runWithPath(dir, pathDir string, args ...string) (string, error) {
	cmd := exec.Command(bins.rover, args...) //nolint:gosec // G204: test runs the binary it just built
	cmd.Env = env(dir, "PATH="+pathDir)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// Plan §5.1 / review M5: validate also runs the official Cedar CLI when it
// is installed, against the schema roverd would use.
func TestPolicyValidateRunsCedarCLI(t *testing.T) {
	// Arrange
	dir := roverDir(t)
	usePolicy(t, dir, e2ePolicy, "observe")
	binDir, record := fakeCedar(t, 0)
	policyPath := filepath.Join(dir, "config", "policy.cedar")

	// Act
	out, err := runWithPath(dir, binDir, "policy", "validate")

	// Assert
	if err != nil || !strings.Contains(out, "fake cedar says hello") || !strings.Contains(out, "cedar validate: ok") {
		t.Fatalf("validate with cedar: %v\n%s", err, out)
	}
	rec, rerr := os.ReadFile(record) //nolint:gosec // G304: test temp file
	if rerr != nil {
		t.Fatal(rerr)
	}
	fields := strings.Fields(strings.SplitN(string(rec), "\n", 2)[0])
	if len(fields) != 5 || fields[0] != "validate" || fields[1] != "--schema" || fields[3] != "--policies" || fields[4] != policyPath {
		t.Fatalf("cedar args = %q", fields)
	}
	if !strings.Contains(string(rec), "-rw-------") {
		t.Fatalf("schema temp file is not 0600: %s", rec)
	}
	if _, serr := os.Stat(fields[2]); !os.IsNotExist(serr) {
		t.Fatalf("schema temp file %s left behind: %v", fields[2], serr)
	}
}

func TestPolicyValidateFailsWhenCedarCLIFails(t *testing.T) {
	dir := roverDir(t)
	usePolicy(t, dir, e2ePolicy, "observe")
	binDir, _ := fakeCedar(t, 1)

	out, err := runWithPath(dir, binDir, "policy", "validate")

	if err == nil || !strings.Contains(out, "fake cedar says hello") || !strings.Contains(out, "cedar validate: failed") {
		t.Fatalf("cedar exit 1 must fail validate: %v\n%s", err, out)
	}
}

func TestPolicyValidateSaysWhenCedarCLIIsMissing(t *testing.T) {
	dir := roverDir(t)
	usePolicy(t, dir, e2ePolicy, "observe")

	out, err := runWithPath(dir, t.TempDir(), "policy", "validate")

	if err != nil || !strings.Contains(out, "cedar CLI not installed; skipped") {
		t.Fatalf("validate without cedar: %v\n%s", err, out)
	}
}

// Review L2/L3: validate refuses files roverd would refuse, and roverd
// checks the normalizers file config.yaml names.
func TestPolicyValidateAndDaemonCheckFilePermissions(t *testing.T) {
	for _, name := range []string{"policy.cedar", "schema.cedarschema", "config.yaml", "normalizers.yaml"} {
		t.Run(name, func(t *testing.T) {
			// Arrange
			dir := roverDir(t)
			usePolicy(t, dir, e2ePolicy, "observe")
			cfgDir := filepath.Join(dir, "config")
			norm := filepath.Join(cfgDir, "normalizers.yaml")
			if err := os.WriteFile(norm, []byte("servers: {}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			cfgPath := filepath.Join(cfgDir, "config.yaml")
			f, err := os.OpenFile(cfgPath, os.O_APPEND|os.O_WRONLY, 0) //nolint:gosec // G304: test's ROVER_DIR
			if err != nil {
				t.Fatal(err)
			}
			_, _ = f.WriteString("normalizers: normalizers.yaml\n")
			_ = f.Close()
			if out, err := runWithPath(dir, t.TempDir(), "policy", "validate"); err != nil {
				t.Fatalf("private files must validate: %v\n%s", err, out)
			}
			if err := os.Chmod(filepath.Join(cfgDir, name), 0o644); err != nil { //nolint:gosec // G302: the test makes it too open on purpose
				t.Fatal(err)
			}

			// Act
			out, verr := runWithPath(dir, t.TempDir(), "policy", "validate")
			_, _, lerr := loadAll(paths.Dirs{Config: cfgDir})

			// Assert
			if verr == nil || !strings.Contains(out, "permissions too open") {
				t.Fatalf("validate with %s 0644: %v\n%s", name, verr, out)
			}
			if lerr == nil || !strings.Contains(lerr.Error(), "permissions too open") {
				t.Fatalf("roverd load with %s 0644: %v", name, lerr)
			}
		})
	}
}
