// Package clients rewrites the MCP configuration of agent applications
// (Claude Code, Cursor, Claude Desktop, VS Code) so that every local stdio
// server runs behind `rover wrap`, and puts it back afterwards (plan D11, M7).
//
// A client config is the user's file, often hand-edited, and some clients
// (Claude Code) rewrite theirs constantly. So nothing here ever decodes a
// config into Go values and marshals it back: that would reorder keys, drop
// what we do not model and reformat everything. Instead the file is read
// with the strict reader (jsonrpc.Object: exact keys, no duplicates, offsets
// of every value), the few values that must change are spliced in place, and
// every other byte is left exactly as it was. Install followed by uninstall
// gives back the same bytes; that is the acceptance test.
//
// Writes are atomic (temp file in the same directory, fsync, rename) and the
// previous bytes are kept under the state directory (backup.go).
package clients

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Adapter names, as given to `rover install --client`.
const (
	NameClaudeCode    = "claude-code"
	NameCursor        = "cursor"
	NameClaudeDesktop = "claude-desktop"
	NameVSCode        = "vscode"
	// NameClaudeSettings is the pseudo-adapter of the Claude Code hardening
	// (permissions.deny in ~/.claude/settings.json); its backups live
	// beside the others.
	NameClaudeSettings = "claude-code-settings"
)

// ConfigFile is one client config file an adapter manages.
type ConfigFile struct {
	Adapter string `json:"adapter"`
	Path    string `json:"path"`  // absolute
	Scope   string `json:"scope"` // user, project, global
}

// Env is everything an adapter needs from the outside world, so tests can
// point it at a temporary home directory.
type Env struct {
	Home      string
	Cwd       string
	GOOS      string
	BackupDir string // <state>/backups
	Now       func() time.Time
}

func (e Env) now() time.Time {
	if e.Now == nil {
		return time.Now()
	}
	return e.Now()
}

// Adapter is one client application. Add a new client by writing a spec
// (see docs/adapters.md); the reading, planning, writing and restoring are
// shared.
type Adapter interface {
	Name() string
	// Detect lists the config files of this client that exist.
	Detect() ([]ConfigFile, error)
	// Read parses one file.
	Read(ConfigFile) (Doc, error)
	// Plan computes the wrapped file and its diff; it writes nothing.
	Plan(doc Doc, roverPath string) (Plan, error)
	// Apply writes a plan: backup first, then an atomic replace.
	Apply(Plan) error
	// Restore puts back the newest backup, refusing if the file changed
	// since rover wrote it or the backup does not match its checksum.
	Restore(ConfigFile) error
}

// ErrUnsupported means an adapter has no config on this platform.
var ErrUnsupported = errors.New("not supported on this platform")

// spec describes one client: where its files are and where in them the
// servers live. Everything else is generic.
type spec struct {
	name string
	// files lists candidate config files; Detect keeps those that exist.
	files func(Env) ([]ConfigFile, error)
	// containers finds the server maps in a parsed top-level object.
	// scope is the file's; servers at its top level are labelled with it.
	containers func(src []byte, top fields, scope string) ([]container, error)
}

// container is one JSON object of servers (key -> server definition).
type container struct {
	scope   string
	members fields
}

type adapter struct {
	s   spec
	env Env
}

func (a adapter) Name() string { return a.s.name }

func (a adapter) Detect() ([]ConfigFile, error) {
	cands, err := a.s.files(a.env)
	if err != nil {
		return nil, err
	}
	var out []ConfigFile
	for _, c := range cands {
		fi, err := os.Stat(c.Path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		if fi.Mode().IsRegular() {
			out = append(out, c)
		}
	}
	return out, nil
}

func (a adapter) Read(cf ConfigFile) (Doc, error) { return readDoc(a.s, cf) }

func (a adapter) Plan(doc Doc, roverPath string) (Plan, error) { return planWrap(doc, roverPath) }

func (a adapter) Apply(p Plan) error { return ApplyPlan(a.env, p) }

func (a adapter) Restore(cf ConfigFile) error { return Restore(a.env, cf) }

var specs = map[string]spec{
	NameClaudeCode:    claudeCodeSpec,
	NameCursor:        cursorSpec,
	NameClaudeDesktop: claudeDesktopSpec,
	NameVSCode:        vscodeSpec,
}

// Names lists the adapters, sorted.
func Names() []string {
	out := make([]string, 0, len(specs))
	for n := range specs {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Get returns the adapter called name.
func Get(name string, env Env) (Adapter, error) {
	s, ok := specs[name]
	if !ok {
		return nil, fmt.Errorf("unknown client %q (have %v)", name, Names())
	}
	return adapter{s: s, env: env}, nil
}

// All returns every adapter, sorted by name.
func All(env Env) []Adapter {
	var out []Adapter
	for _, n := range Names() {
		out = append(out, adapter{s: specs[n], env: env})
	}
	return out
}

// ReadConfig parses cf with the adapter it names (roverd's tamper watch
// uses this; it has a ConfigFile, not an Adapter).
func ReadConfig(cf ConfigFile) (Doc, error) {
	s, ok := specs[cf.Adapter]
	if !ok {
		return Doc{}, fmt.Errorf("unknown client %q", cf.Adapter)
	}
	return readDoc(s, cf)
}

// file is a small helper for specs.
func file(adapterName, scope string, elem ...string) ConfigFile {
	return ConfigFile{Adapter: adapterName, Scope: scope, Path: filepath.Join(elem...)}
}
