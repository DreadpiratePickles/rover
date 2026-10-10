package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/DreadpiratePickles/rover/internal/clients"
	"github.com/DreadpiratePickles/rover/internal/paths"
)

// `rover install --service` (plan §4.4): run roverd at login instead of
// waiting for the first wrapper to start it. macOS gets a launchd agent,
// Linux a systemd user unit. The file is written 0600; the command that
// loads it runs only with --yes, otherwise it is printed.

const (
	launchdLabel = "net.rover.roverd"
	systemdUnit  = "roverd.service"
)

type serviceSpec struct {
	path    string
	content []byte
	load    [][]string // run after writing (with --yes)
	unload  [][]string // run before removing
}

func serviceFor(goos, home, rover string, dirs paths.Dirs) (serviceSpec, error) {
	logPath := filepath.Join(dirs.State, "roverd.log")
	roverDir := os.Getenv("ROVER_DIR")
	switch goos {
	case "darwin":
		p := filepath.Join(home, "Library", "LaunchAgents", launchdLabel+".plist")
		uid := strconv.Itoa(os.Getuid())
		return serviceSpec{path: p, content: launchdPlist(rover, logPath, roverDir),
			load:   [][]string{{"launchctl", "bootstrap", "gui/" + uid, p}},
			unload: [][]string{{"launchctl", "bootout", "gui/" + uid + "/" + launchdLabel}}}, nil
	case "linux":
		p := filepath.Join(home, ".config", "systemd", "user", systemdUnit)
		return serviceSpec{path: p, content: systemdUnitFile(rover, logPath, roverDir),
			load:   [][]string{{"systemctl", "--user", "daemon-reload"}, {"systemctl", "--user", "enable", "--now", systemdUnit}},
			unload: [][]string{{"systemctl", "--user", "disable", "--now", systemdUnit}}}, nil
	}
	return serviceSpec{}, fmt.Errorf("--service is supported on macOS and Linux, not %s", goos)
}

func xmlText(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s)) // writes to a buffer: cannot fail
	return b.String()
}

func launchdPlist(rover, logPath, roverDir string) []byte {
	env := ""
	if roverDir != "" {
		env = "\t<key>EnvironmentVariables</key>\n\t<dict>\n\t\t<key>ROVER_DIR</key>\n\t\t<string>" + xmlText(roverDir) + "</string>\n\t</dict>\n"
	}
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + launchdLabel + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + xmlText(rover) + `</string>
		<string>daemon</string>
	</array>
` + env + `	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardErrorPath</key>
	<string>` + xmlText(logPath) + `</string>
</dict>
</plist>
`)
}

// systemdQuote quotes one word for an ExecStart= line: double quotes, with
// backslash and quote escaped, and % doubled (systemd's specifier escape).
func systemdQuote(s string) string {
	s = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%").Replace(s)
	return `"` + s + `"`
}

func systemdUnitFile(rover, logPath, roverDir string) []byte {
	env := ""
	if roverDir != "" {
		env = "Environment=" + systemdQuote("ROVER_DIR="+roverDir) + "\n"
	}
	return []byte(`[Unit]
Description=roverd, the Rover MCP security gateway daemon

[Service]
ExecStart=` + systemdQuote(rover) + ` daemon
` + env + `Restart=on-failure
StandardError=append:` + strings.ReplaceAll(logPath, "%", "%%") + `

[Install]
WantedBy=default.target
`)
}

// runCmd is replaced in tests.
var runCmd = func(argv []string) ([]byte, error) {
	return exec.Command(argv[0], argv[1:]...).CombinedOutput() //nolint:gosec // G204: fixed launchctl/systemctl argument vectors built above
}

func installService(out io.Writer, cf clientFlags, rover string) int {
	sp, err := currentService(rover)
	if err != nil {
		_, _ = fmt.Fprintln(out, "rover install --service:", err)
		return 1
	}
	_, _ = fmt.Fprintf(out, "%s:\n%s", sp.path, sp.content)
	if cf.dryRun {
		return 0
	}
	if err := os.MkdirAll(filepath.Dir(sp.path), 0o700); err != nil {
		_, _ = fmt.Fprintln(out, "fail ", err)
		return 1
	}
	if err := clients.WriteAtomic(sp.path, sp.content, 0o600); err != nil {
		_, _ = fmt.Fprintln(out, "fail ", err)
		return 1
	}
	_, _ = fmt.Fprintf(out, "ok    wrote %s (0600)\n", sp.path)
	return runService(out, cf, sp.load, "load it")
}

func uninstallService(out io.Writer, cf clientFlags) int {
	sp, err := currentService("rover")
	if err != nil {
		_, _ = fmt.Fprintln(out, "rover uninstall --service:", err)
		return 1
	}
	if _, err := os.Stat(sp.path); errors.Is(err, os.ErrNotExist) {
		_, _ = fmt.Fprintf(out, "ok    %s does not exist\n", sp.path)
		return 0
	}
	if cf.dryRun {
		_, _ = fmt.Fprintf(out, "would stop the service and remove %s\n", sp.path)
		return 0
	}
	if rc := runService(out, cf, sp.unload, "stop it"); rc != 0 || !cf.yes {
		return rc
	}
	if err := os.Remove(sp.path); err != nil {
		_, _ = fmt.Fprintln(out, "fail ", err)
		return 1
	}
	_, _ = fmt.Fprintf(out, "ok    removed %s\n", sp.path)
	return 0
}

func currentService(rover string) (serviceSpec, error) {
	dirs, err := paths.Resolve()
	if err != nil {
		return serviceSpec{}, err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return serviceSpec{}, err
	}
	return serviceFor(runtime.GOOS, home, rover, dirs)
}

// runService runs cmds only with --yes; otherwise it prints them.
func runService(out io.Writer, cf clientFlags, cmds [][]string, what string) int {
	if !cf.yes {
		_, _ = fmt.Fprintf(out, "to %s, run (or rerun with --yes):\n", what)
		for _, c := range cmds {
			_, _ = fmt.Fprintf(out, "  %s\n", strings.Join(c, " "))
		}
		return 0
	}
	for _, c := range cmds {
		if b, err := runCmd(c); err != nil {
			_, _ = fmt.Fprintf(out, "fail  %s: %v %s\n", strings.Join(c, " "), err, strings.TrimSpace(string(b)))
			return 1
		}
		_, _ = fmt.Fprintf(out, "ok    %s\n", strings.Join(c, " "))
	}
	return 0
}
