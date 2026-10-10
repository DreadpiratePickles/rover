// Package config reads config.yaml, the operator's settings for roverd:
// the policy mode, the named roots policies refer to, tool labels and the
// argument normalisers.
//
//	mode: observe            # or enforce
//	roots:
//	  projects: ~/projects   # becomes norm.<arg>.under_projects
//	labels:
//	  filesystem:
//	    read_file: [reads_private]
//	normalizers: normalizers.yaml   # optional; default: the built-in mapping
//
// LESSON (M2): the config is parsed strictly. An unknown key is an error, not
// a warning, because a misspelt "mdoe: enforce" that was silently ignored
// would leave the gateway in observe mode while the operator believes it
// blocks. The same reasoning applies to labels: an unknown label would never
// match any policy, so it is refused.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/DreadpiratePickles/rover/internal/policy"
	"github.com/DreadpiratePickles/rover/internal/policy/normalize"
)

// FileName is the config file inside the config directory.
const FileName = "config.yaml"

// maxConfigBytes bounds config.yaml (and a referenced normalizers file).
const maxConfigBytes = 1 << 20

// Labels a tool may carry (plan §5.1). Policies test them with
// resource.labels.contains("...").
var validLabels = map[string]bool{
	"reads_private":   true,
	"reads_untrusted": true,
	"egress":          true,
	"destructive":     true,
}

// A root name becomes part of a Cedar attribute (under_<name>), so it must be
// a Cedar identifier.
var cedarIdent = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Config is the parsed config.yaml.
type Config struct {
	// Mode defaults to observe (plan D6: learn, then enforce).
	Mode policy.Mode
	// Roots keeps the order of the file: a relative path argument is
	// resolved against the first root.
	Roots []normalize.Root
	// Labels maps server -> tool -> labels.
	Labels map[string]map[string][]string
	// Normalizers is the built-in mapping unless config.yaml names a file.
	Normalizers normalize.Config
	// NormalizersFile is the absolute path of that file, or "" for the
	// built-in mapping. roverd and `rover policy validate` check that it is
	// owner-only, like the other policy files.
	NormalizersFile string
}

// Default is the configuration used when config.yaml does not exist.
func Default() Config {
	return Config{Mode: policy.ModeObserve, Normalizers: normalize.BuiltIn()}
}

// ToolLabels returns the labels of one tool, or nil.
func (c Config) ToolLabels(server, tool string) []string {
	return c.Labels[server][tool]
}

// ToolNormalizers returns the normaliser rules of one tool, or nil.
func (c Config) ToolNormalizers(server, tool string) normalize.Rules {
	return c.Normalizers.Servers[server][tool]
}

type file struct {
	Mode        string                         `yaml:"mode"`
	Roots       rootList                       `yaml:"roots"`
	Labels      map[string]map[string][]string `yaml:"labels"`
	Normalizers string                         `yaml:"normalizers"`
}

// rootList decodes a YAML mapping {name: path} keeping the file's order.
type rootList []normalize.Root

// UnmarshalYAML implements yaml.Unmarshaler.
func (r *rootList) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode && n.Tag == "!!null" {
		return nil
	}
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: roots must be a mapping of name: path", n.Line)
	}
	seen := map[string]bool{}
	out := make(rootList, 0, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Kind != yaml.ScalarNode || v.Kind != yaml.ScalarNode {
			return fmt.Errorf("line %d: roots entries must be name: path", k.Line)
		}
		if seen[k.Value] {
			return fmt.Errorf("line %d: root %q defined twice", k.Line, k.Value)
		}
		seen[k.Value] = true
		out = append(out, normalize.Root{Name: k.Value, Path: v.Value})
	}
	*r = out
	return nil
}

// Load reads dir/config.yaml. A missing file yields Default().
func Load(dir string) (Config, error) {
	b, err := readLimited(filepath.Join(dir, FileName))
	if errors.Is(err, os.ErrNotExist) {
		return Default(), nil
	}
	if err != nil {
		return Config{}, err
	}
	return Parse(b, dir)
}

// Parse decodes config.yaml. dir resolves a relative normalizers path.
func Parse(b []byte, dir string) (Config, error) {
	var f file
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("config: %s: %w", FileName, err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("config: %s must contain exactly one YAML document", FileName)
	}
	cfg := Default()
	switch policy.Mode(f.Mode) {
	case "":
	case policy.ModeObserve, policy.ModeEnforce:
		cfg.Mode = policy.Mode(f.Mode)
	default:
		return Config{}, fmt.Errorf("config: mode %q: want observe or enforce", f.Mode)
	}
	roots, err := resolveRoots(f.Roots)
	if err != nil {
		return Config{}, err
	}
	cfg.Roots = roots
	if err := checkLabels(f.Labels); err != nil {
		return Config{}, err
	}
	cfg.Labels = f.Labels
	if f.Normalizers != "" {
		n, p, err := loadNormalizers(f.Normalizers, dir)
		if err != nil {
			return Config{}, err
		}
		cfg.Normalizers, cfg.NormalizersFile = n, p
	}
	return cfg, nil
}

func resolveRoots(in rootList) ([]normalize.Root, error) {
	out := make([]normalize.Root, 0, len(in))
	for _, r := range in {
		if !cedarIdent.MatchString(r.Name) {
			return nil, fmt.Errorf("config: root name %q must be a Cedar identifier (letters, digits, _; not starting with a digit)", r.Name)
		}
		p, err := expandPath(r.Path, "")
		if err != nil {
			return nil, fmt.Errorf("config: root %s: %w", r.Name, err)
		}
		out = append(out, normalize.Root{Name: r.Name, Path: p})
	}
	return out, nil
}

func checkLabels(labels map[string]map[string][]string) error {
	for server, tools := range labels {
		for tool, ls := range tools {
			for _, l := range ls {
				if !validLabels[l] {
					return fmt.Errorf("config: labels.%s.%s: unknown label %q (want reads_private, reads_untrusted, egress or destructive)", server, tool, l)
				}
			}
		}
	}
	return nil
}

func loadNormalizers(path, dir string) (normalize.Config, string, error) {
	p, err := expandPath(path, dir)
	if err != nil {
		return normalize.Config{}, "", fmt.Errorf("config: normalizers: %w", err)
	}
	b, err := readLimited(p)
	if err != nil {
		return normalize.Config{}, "", fmt.Errorf("config: normalizers: %w", err)
	}
	n, err := normalize.Parse(b)
	if err != nil {
		return normalize.Config{}, "", fmt.Errorf("config: normalizers %s: %w", p, err)
	}
	return n, p, nil
}

// expandPath expands a leading "~" to the home directory and makes p
// absolute; a relative path is taken relative to base, or to the working
// directory when base is "".
func expandPath(p, base string) (string, error) {
	if p == "" {
		return "", errors.New("empty path")
	}
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expand ~: %w", err)
		}
		p = filepath.Join(home, strings.TrimPrefix(p, "~"))
	}
	if !filepath.IsAbs(p) && base != "" {
		p = filepath.Join(base, p)
	}
	return filepath.Abs(p)
}

func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the path is the operator's own config file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxConfigBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxConfigBytes)
	}
	return b, nil
}
