package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/DreadpiratePickles/rover/internal/config"
	"github.com/DreadpiratePickles/rover/internal/labels"
	"github.com/DreadpiratePickles/rover/internal/paths"
)

// policyLabels implements `rover policy labels [server]`: the effective
// labels of every tool some source names, with the source of each, so the
// operator can see why a tool is (or is not) treated as egress. Without a
// server it lists every configured server and every built-in one.
func policyLabels(args []string) int {
	if len(args) > 1 || (len(args) == 1 && strings.HasPrefix(args[0], "-")) {
		fmt.Fprintln(os.Stderr, "usage: rover policy labels [server]")
		return 2
	}
	cfg, err := labelsConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	servers := labelServers(cfg)
	if len(args) == 1 {
		servers = []string{args[0]}
	}
	printLabels(os.Stdout, servers, cfg.Labels)
	return 0
}

// labelsConfig is the config roverd would use: config.yaml with the labels
// of policy.yaml applied when policy.yaml is the policy in force. With no
// policy file, config.yaml alone (or the defaults).
func labelsConfig() (config.Config, error) {
	dirs, err := paths.Resolve()
	if err != nil {
		return config.Config{}, err
	}
	file, _, err := pickPolicyFile(dirs.Config)
	if errors.Is(err, errNoPolicyFile) {
		return loadConfig(dirs.Config, "")
	}
	if err != nil {
		return config.Config{}, err
	}
	cfg, err := loadConfig(dirs.Config, file)
	if err != nil {
		return config.Config{}, err
	}
	l, err := loadPolicy(file, dirs.Config, cfg)
	if err != nil {
		return config.Config{}, err
	}
	return l.cfg, nil
}

// labelServers is every configured server, then every built-in server not
// configured under its canonical name, sorted.
func labelServers(cfg config.Config) []string {
	seen := map[string]bool{}
	var out []string
	for s := range cfg.Labels {
		seen[s] = true
		out = append(out, s)
	}
	for _, s := range labels.KnownServers() {
		if !seen[s] {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func printLabels(w io.Writer, servers []string, user map[string]map[string][]string) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SERVER\tTOOL\tLABELS\tSOURCE")
	for _, s := range servers {
		known := labels.KnownServer(s)
		for _, r := range labels.List(s, user) {
			src := r.Source
			if src == labels.SourceBuiltIn && known != s {
				src += " (" + known + ")"
			}
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", s, r.Tool, labelText(r.Labels), src)
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", s, "(any other tool)", labelText(labels.Default()), labels.SourceDefault)
	}
	_ = tw.Flush()
}

func labelText(ls []string) string {
	if len(ls) == 0 {
		return "-"
	}
	return strings.Join(ls, ",")
}
