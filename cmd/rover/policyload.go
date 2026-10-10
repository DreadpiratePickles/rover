package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/DreadpiratePickles/rover/internal/config"
	"github.com/DreadpiratePickles/rover/internal/daemon"
	"github.com/DreadpiratePickles/rover/internal/paths"
	"github.com/DreadpiratePickles/rover/internal/policy"
	"github.com/DreadpiratePickles/rover/internal/policy/yaml2cedar"
	policyfiles "github.com/DreadpiratePickles/rover/policy"
)

// Files in the config directory.
const (
	policyFile     = "policy.cedar"
	policyYAMLFile = "policy.yaml"
	schemaFile     = "schema.cedarschema"
)

// starterConfig is the config.yaml `rover policy init` writes.
const starterConfig = `# Rover configuration, written by ` + "`rover policy init`" + `.
# Edit it, then run ` + "`rover policy apply`" + `: roverd loads only a policy you
# approved in the system authentication dialog (editing alone changes nothing).

# mode: observe or enforce.
#   observe  every message the policy would deny is still forwarded, and the
#            audit log records it as "would_deny". Rover starts here so you
#            can watch ` + "`rover log`" + ` before anything is blocked (plan D6:
#            learn, then enforce). Malformed arguments are blocked even here.
#   enforce  denied messages are blocked. Switch to this once the log shows
#            no surprises.
mode: observe

# roots: named directories your policies can refer to. A root named
# "projects" gives every normalised path argument the attribute
# context.norm.<arg>.under_projects. "~" means your home directory.
# The schema is generated from these names, so any root you add here can be
# used in a policy (see ` + "`rover policy validate --print-schema`" + `).
# A policy.yaml with its own roots: section replaces this list.
roots: {}
#  projects: ~/projects

# labels: what each tool can do, for policies such as the trifecta guard in
# policy.cedar. Allowed labels: reads_private, reads_untrusted, egress,
# destructive. Rover already knows the official servers (filesystem, fetch,
# git, github, memory, slack, ...); a tool listed here REPLACES its built-in
# labels ([] means none). A tool nobody labelled gets the conservative
# default [reads_untrusted, egress]. ` + "`rover policy labels [server]`" + ` shows
# the labels in force and where each came from.
labels: {}
#  filesystem:
#    read_file: [reads_private]
#  fetch:
#    fetch: [reads_untrusted, egress]

# normalizers: a normalizers.yaml replacing the built-in argument mappings
# for the official filesystem, fetch, git and GitHub servers.
# normalizers: normalizers.yaml

# approvals: calls a permit marks @rover_require("approval") wait for you to
# confirm them in the system authentication dialog (Touch ID or your password
# on macOS, polkit on Linux). No answer within timeout_s means deny.
# show_args puts the call's arguments on the read-only details page; leave it
# off until secrets are redacted (M10).
# approvals:
#   timeout_s: 120
#   show_args: false
`

// errNoPolicyFile means neither policy.cedar nor policy.yaml exists.
var errNoPolicyFile = errors.New("no policy file (run `rover policy init` or `rover policy init --yaml`)")

// readSchema returns config/schema.cedarschema when it exists, else the
// schema built into the binary, and says which it used. It is the base that
// policy.SchemaFor completes from the configuration.
func readSchema(configDir string) ([]byte, string, error) {
	p := filepath.Join(configDir, schemaFile)
	b, err := readCapped(p, policy.MaxSchemaBytes)
	if errors.Is(err, os.ErrNotExist) {
		return policyfiles.Schema, "built-in", nil
	}
	if err != nil {
		return nil, "", err
	}
	return b, p, nil
}

// loaded is one policy, loaded the way roverd loads it.
type loaded struct {
	engine     *policy.Engine
	cfg        config.Config // config.yaml, with policy.yaml's settings applied
	schema     []byte        // the effective schema (policy.SchemaFor)
	schemaName string        // where the base schema came from
	compiled   *yaml2cedar.Compiled
}

// checkPrivateFiles fails unless every file that exists is owner-only: a
// policy anyone else can write is not the owner's policy. A missing file is
// not an error here (loading it reports that, or a default applies).
func checkPrivateFiles(files ...string) error {
	for _, f := range files {
		if f == "" {
			continue
		}
		if err := paths.CheckPrivate(f, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// loadConfig loads config.yaml after checking it, the schema and the policy
// file are owner-only, then checks the normalizers file it names. roverd
// and `rover policy validate` both use it, so they refuse the same files.
func loadConfig(configDir, policyPath string) (config.Config, error) {
	if err := checkPrivateFiles(filepath.Join(configDir, config.FileName), policyPath, filepath.Join(configDir, schemaFile)); err != nil {
		return config.Config{}, err
	}
	cfg, err := config.Load(configDir)
	if err != nil {
		return config.Config{}, err
	}
	if err := checkPrivateFiles(cfg.NormalizersFile); err != nil {
		return config.Config{}, err
	}
	return cfg, nil
}

// isYAML reports whether file is a policy.yaml by its extension.
func isYAML(file string) bool {
	ext := strings.ToLower(filepath.Ext(file))
	return ext == ".yaml" || ext == ".yml"
}

// loadPolicy loads a policy file against cfg. A .yaml/.yml file is compiled
// to Cedar first, and its mode, roots and labels override cfg. The schema is
// generated from the resulting config, then every policy is validated.
func loadPolicy(file, configDir string, cfg config.Config) (loaded, error) {
	limit := policy.MaxPolicyBytes
	if isYAML(file) {
		limit = yaml2cedar.MaxSourceBytes
	}
	src, err := readCapped(file, limit)
	if errors.Is(err, os.ErrNotExist) {
		return loaded{}, fmt.Errorf("%s: %w", file, errNoPolicyFile)
	}
	if err != nil {
		return loaded{}, err
	}
	l := loaded{cfg: cfg}
	if isYAML(file) {
		c, cerr := yaml2cedar.Compile(src, file)
		if cerr != nil {
			return loaded{}, cerr
		}
		l.compiled = &c
		l.cfg, err = cfg.WithPolicySettings(config.PolicySettings{
			Mode: c.Mode, RootOrder: c.RootOrder, Roots: c.Roots, Labels: c.Labels,
		})
		if err != nil {
			return loaded{}, fmt.Errorf("%s: %w", file, err)
		}
		src = c.Cedar
	}
	base, schemaName, err := readSchema(configDir)
	if err != nil {
		return loaded{}, err
	}
	ext := policy.NewSchemaExtension(policy.RootNames(l.cfg.Roots), l.cfg.Normalizers)
	if l.schema, err = policy.SchemaFor(base, ext); err != nil {
		return loaded{}, err
	}
	l.schemaName = schemaName
	if l.engine, err = policy.Load(src, filepath.Base(file), l.schema); err != nil {
		return loaded{}, err
	}
	return l, nil
}

// pickPolicyFile applies the precedence rule: policy.cedar when it exists,
// else policy.yaml. note says which was chosen and why, for the log.
func pickPolicyFile(configDir string) (file, note string, err error) {
	cedarPath := filepath.Join(configDir, policyFile)
	yamlPath := filepath.Join(configDir, policyYAMLFile)
	cedarErr := existsErr(cedarPath)
	yamlErr := existsErr(yamlPath)
	switch {
	case cedarErr == nil && yamlErr == nil:
		return cedarPath, "both policy.cedar and policy.yaml exist: using policy.cedar (it wins); policy.yaml is ignored", nil
	case cedarErr == nil:
		return cedarPath, "using policy.cedar", nil
	case !errors.Is(cedarErr, os.ErrNotExist):
		return "", "", cedarErr
	case yamlErr == nil:
		return yamlPath, "no policy.cedar: compiling policy.yaml (its mode, roots and labels override config.yaml)", nil
	case !errors.Is(yamlErr, os.ErrNotExist):
		return "", "", yamlErr
	}
	return "", "", fmt.Errorf("%s: %w", configDir, errNoPolicyFile)
}

func existsErr(path string) error {
	_, err := os.Lstat(path)
	return err
}

// loadSnapshot loads config.yaml and the policy from dirs.Config (a
// snapshot, see loadAll): policy.cedar when it exists, else policy.yaml
// compiled at load (pickPolicyFile). The config, the chosen policy file, the
// schema and the normalizers file must be owner-only (loadConfig). note
// says which policy file was used.
func loadSnapshot(dirs paths.Dirs) (pol daemon.Policy, cfg config.Config, note string, err error) {
	file, note, perr := pickPolicyFile(dirs.Config)
	cfg, err = loadConfig(dirs.Config, file)
	if err != nil {
		return nil, config.Config{}, note, err
	}
	if perr != nil {
		return nil, cfg, note, perr
	}
	l, err := loadPolicy(file, dirs.Config, cfg)
	if err != nil {
		return nil, cfg, note, err
	}
	return l.engine, l.cfg, note, nil
}

func readCapped(path string, limit int) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the operator's own policy files
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return b, nil
}
