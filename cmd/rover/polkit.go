package main

import (
	"fmt"
	"io"
	"runtime"

	"github.com/DreadpiratePickles/rover/internal/approve"
)

// installPolkit prints how to install the polkit action org.rover.approve
// (plan M9, §9). Writing to /usr/share/polkit-1/actions needs root, and
// Rover never runs sudo itself: the human reads the file and runs the
// commands.
func installPolkit(w io.Writer, goos string) int {
	if goos != "linux" {
		_, _ = fmt.Fprintf(w, "polkit is for Linux; on %s Rover asks LocalAuthentication (Touch ID or your password), nothing to install\n", goos)
		return 0
	}
	_, _ = fmt.Fprintf(w, `rover approvals on Linux ask polkit (pkcheck) for the action %[1]s.
installing the action needs root, so rover prints the commands instead of running sudo.
read the file below, then run:

sudo tee %[2]s >/dev/null <<'EOF'
%[3]sEOF
sudo chmod 0644 %[2]s
pkaction --action-id %[1]s --verbose

the action uses auth_self (you type your own password each time, never the _keep
variants). a desktop session runs a polkit authentication agent; on a headless
machine there is none, and every approval is denied (logged as no_auth_agent).
`, approve.PolkitAction, approve.PolkitActionPath, approve.PolkitPolicy)
	return 0
}

// goos is runtime.GOOS; a variable so tests can print the Linux text.
var goos = runtime.GOOS
