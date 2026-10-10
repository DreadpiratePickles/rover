// Command rover is the Rover MCP security gateway.
//
//	rover wrap [--name NAME] -- <mcp server command> [args...]
//	rover daemon [--no-bodies]
//	rover log [--log FILE] [--verify]
//	rover policy init|validate|test|apply|propose|diff|labels
//	rover pin list [server] | approve <server> <tool> <digest> | reset <server>
//	rover eval [--corpus DIR]
//	rover install|uninstall [--client NAME ...] [--yes] [--dry-run] [--service]
//	rover install --polkit
//	rover doctor [--json]
//	rover version
//
// "wrap" starts the real MCP server as a child process and sits between it and
// the agent, asking roverd (started on demand) about every message. To use
// it, change the agent's MCP config from
//
//	"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
//
// to
//
//	"command": "rover", "args": ["wrap", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
package main

import (
	"fmt"
	"os"
)

func main() {
	os.Args = append(os.Args[:1:1], stripTestFlags(os.Args[1:])...)
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "wrap":
		os.Exit(wrap(os.Args[2:]))
	case "daemon":
		os.Exit(runDaemon(os.Args[2:]))
	case "log":
		os.Exit(showLog(os.Args[2:]))
	case "policy":
		os.Exit(runPolicy(os.Args[2:]))
	case "pin":
		os.Exit(runPin(os.Args[2:]))
	case "approvals":
		os.Exit(runApprovals(os.Args[2:]))
	case "eval":
		os.Exit(runEval(os.Args[2:]))
	case "install":
		os.Exit(runInstall(os.Args[2:]))
	case "uninstall":
		os.Exit(runUninstall(os.Args[2:]))
	case "doctor":
		os.Exit(runDoctor(os.Args[2:]))
	case "version", "--version":
		os.Exit(runVersion(os.Args[2:]))
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:\n  rover wrap [--name NAME] -- <server command> [args...]\n  rover daemon [--no-bodies]\n  rover log [--log FILE] [--verify]\n"+
		"  rover policy init [--force]\n  rover policy validate [--policy FILE]\n  rover policy test <audit.jsonl>\n  rover policy apply\n"+
		"  rover policy propose [--out FILE [--force]] [--yaml]\n  rover policy diff [FILE]\n  rover policy labels [server]\n"+
		"  rover pin list [server]\n  rover pin approve <server> <tool> <digest>\n  rover pin reset <server>\n  rover approvals list\n  rover eval [--corpus DIR]\n"+
		"  rover install [--client NAME ...] [--yes] [--dry-run] [--rover PATH]\n  rover install --service [--yes]\n  rover install --polkit\n"+
		"  rover uninstall [--client NAME ...] [--yes] [--dry-run] [--service]\n  rover doctor [--json]\n  rover version")
	os.Exit(2)
}

// errf prints one diagnostic line to stderr. stdout belongs to the protocol.
func errf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "[rover] "+format+"\n", a...)
}
