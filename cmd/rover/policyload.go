package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/DreadpiratePickles/rover/internal/config"
	"github.com/DreadpiratePickles/rover/internal/daemon"
	"github.com/DreadpiratePickles/rover/internal/paths"
	"github.com/DreadpiratePickles/rover/internal/policy"
	policyfiles "github.com/DreadpiratePickles/rover/policy"
)

// Files in the config directory.
const (
	policyFile = "policy.cedar"
	schemaFile = "schema.cedarschema"
)

// starterConfig is the config.yaml `rover policy init` writes.
const starterConfig = `# Rover configuration, written by ` + "`rover policy init`" + `.
# Edit it, then run ` + "`rover policy apply`" + ` (or restart roverd).

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
# Until M3 generates the schema, a new root name also needs a matching
# under_<name> attribute in schema.cedarschema.
roots: {}
#  projects: ~/projects

# labels: what each tool can do, for policies such as the trifecta guard.
# Allowed labels: reads_private, reads_untrusted, egress, destructive.
labels: {}
#  filesystem:
#    read_file: [reads_private]
#  fetch:
#    fetch: [reads_untrusted, egress]

# normalizers: a normalizers.yaml replacing the built-in argument mappings
# for the official filesystem, fetch, git and GitHub servers.
# normalizers: normalizers.yaml
`

// errNoPolicyFile means policy.cedar does not exist yet.
var errNoPolicyFile = errors.New("no policy file (run `rover policy init`)")

// readSchema returns config/schema.cedarschema when it exists, else the
// schema built into the binary, and says which it used.
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

// loadEngine loads and validates a policy file against the schema.
func loadEngine(file, configDir string) (*policy.Engine, string, error) {
	src, err := readCapped(file, policy.MaxPolicyBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", fmt.Errorf("%s: %w", file, errNoPolicyFile)
	}
	if err != nil {
		return nil, "", err
	}
	schema, schemaName, err := readSchema(configDir)
	if err != nil {
		return nil, "", err
	}
	eng, err := policy.Load(src, filepath.Base(file), schema)
	if err != nil {
		return nil, "", err
	}
	return eng, schemaName, nil
}

// loadAll loads config.yaml and policy.cedar for roverd. The files must be
// owner-only: a policy anyone else can write is not the owner's policy.
// On any error the caller runs (or keeps running) without this pair.
func loadAll(dirs paths.Dirs) (daemon.Policy, config.Config, error) {
	for _, f := range []string{config.FileName, policyFile, schemaFile} {
		if err := paths.CheckPrivate(filepath.Join(dirs.Config, f), 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, config.Config{}, err
		}
	}
	cfg, err := config.Load(dirs.Config)
	if err != nil {
		return nil, config.Config{}, err
	}
	eng, _, err := loadEngine(filepath.Join(dirs.Config, policyFile), dirs.Config)
	if err != nil {
		return nil, cfg, err
	}
	return eng, cfg, nil
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
