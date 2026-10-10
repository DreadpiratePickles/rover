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
	"time"

	"gopkg.in/yaml.v3"

	"github.com/DreadpiratePickles/rover/internal/labels"
	"github.com/DreadpiratePickles/rover/internal/policy"
	"github.com/DreadpiratePickles/rover/internal/policy/normalize"
)

// FileName is the config file inside the config directory.
const FileName = "config.yaml"

// maxConfigBytes bounds config.yaml (and a referenced normalizers file).
const maxConfigBytes = 1 << 20

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
	// Approvals configures the approval flow (M9).
	Approvals Approvals
	// Audit configures the audit log (M10).
	Audit Audit
}

// Audit is config.yaml's audit section.
//
//	audit:
//	  bodies: true   # log full message bodies (secrets redacted); false: metadata only
type Audit struct {
	// Bodies logs full message bodies, with secrets redacted (M10). On by
	// default; `rover daemon --no-bodies` turns it off whatever this says.
	Bodies bool
}

// Approvals is config.yaml's approvals section.
//
//	approvals:
//	  timeout_s: 120    # no answer in time means deny (1..3600)
//	  show_args: false  # show call arguments on the details page
type Approvals struct {
	// TimeoutS is how long a held call waits for a human; 0 means the
	// default (120 s).
	TimeoutS int
	// ShowArgs shows the arguments on the details page, with secrets
	// redacted (M10). Off by default: the page needs only the summary.
	ShowArgs bool
}

// Timeout is the approval timeout.
func (a Approvals) Timeout() time.Duration {
	if a.TimeoutS <= 0 {
		return DefaultApprovalTimeout
	}
	return time.Duration(a.TimeoutS) * time.Second
}

// DefaultApprovalTimeout applies when approvals.timeout_s is not set.
const DefaultApprovalTimeout = 120 * time.Second

// maxApprovalTimeoutS bounds approvals.timeout_s (an hour).
const maxApprovalTimeoutS = 3600

// Default is the configuration used when config.yaml does not exist.
func Default() Config {
	return Config{Mode: policy.ModeObserve, Normalizers: normalize.BuiltIn(), Audit: Audit{Bodies: true}}
}

// ToolLabels returns the configured labels of one tool, or nil. Decisions
// use EffectiveLabels, which adds the built-in labels and the default.
func (c Config) ToolLabels(server, tool string) []string {
	return c.Labels[server][tool]
}

// EffectiveLabels returns the labels roverd uses for one tool and their
// source: built-in < configured (replaces) < the conservative default for a
// tool nobody knows (package labels, plan M8).
func (c Config) EffectiveLabels(server, tool string) (ls []string, source string) {
	return labels.Effective(server, tool, c.Labels)
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
	Approvals   struct {
		TimeoutS int  `yaml:"timeout_s"`
		ShowArgs bool `yaml:"show_args"`
	} `yaml:"approvals"`
	Audit struct {
		Bodies *bool `yaml:"bodies"`
	} `yaml:"audit"`
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

// Reader reads one file for Load (config.yaml and the normalizers file).
type Reader func(path string) ([]byte, error)

// ReadFile is the default Reader: the file, capped at 1 MiB.
func ReadFile(path string) ([]byte, error) { return readLimited(path) }

// Load reads dir/config.yaml. A missing file yields Default().
func Load(dir string) (Config, error) { return LoadWith(dir, ReadFile) }

// LoadWith is Load reading every file through read. roverd passes a reader
// that serves a normalizers file outside the config directory from the
// snapshot it hashed, so the file is read exactly once (review M9).
func LoadWith(dir string, read Reader) (Config, error) {
	b, err := read(filepath.Join(dir, FileName))
	if errors.Is(err, os.ErrNotExist) {
		return Default(), nil
	}
	if err != nil {
		return Config{}, err
	}
	return parse(b, dir, read)
}

// Parse decodes config.yaml. dir resolves a relative normalizers path.
func Parse(b []byte, dir string) (Config, error) { return parse(b, dir, ReadFile) }

// NormalizersPath is the absolute path of the normalizers file config.yaml
// (b) names, or "" when it names none. It reads nothing.
func NormalizersPath(b []byte, dir string) (string, error) {
	var f struct {
		Normalizers string `yaml:"normalizers"`
	}
	if err := yaml.Unmarshal(b, &f); err != nil || f.Normalizers == "" {
		return "", err
	}
	return expandPath(f.Normalizers, dir)
}

func parse(b []byte, dir string, read Reader) (Config, error) {
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
	if f.Approvals.TimeoutS < 0 || f.Approvals.TimeoutS > maxApprovalTimeoutS {
		return Config{}, fmt.Errorf("config: approvals.timeout_s %d: want 1..%d (0 or absent means %d)", f.Approvals.TimeoutS, maxApprovalTimeoutS, int(DefaultApprovalTimeout/time.Second))
	}
	cfg.Approvals = Approvals{TimeoutS: f.Approvals.TimeoutS, ShowArgs: f.Approvals.ShowArgs}
	if f.Audit.Bodies != nil {
		cfg.Audit.Bodies = *f.Audit.Bodies
	}
	if f.Normalizers != "" {
		n, p, err := loadNormalizers(f.Normalizers, dir, read)
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

func checkLabels(byServer map[string]map[string][]string) error {
	for server, tools := range byServer {
		for tool, ls := range tools {
			for _, l := range ls {
				if !labels.Valid(l) {
					return fmt.Errorf("config: labels.%s.%s: unknown label %q (want reads_private, reads_untrusted, egress or destructive)", server, tool, l)
				}
			}
		}
	}
	return nil
}

func loadNormalizers(path, dir string, read Reader) (normalize.Config, string, error) {
	p, err := expandPath(path, dir)
	if err != nil {
		return normalize.Config{}, "", fmt.Errorf("config: normalizers: %w", err)
	}
	b, err := read(p)
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

// PolicySettings are the settings a policy.yaml may carry (plan §5.4). When
// roverd loads a policy.yaml they override config.yaml: a non-empty Mode
// replaces mode, a non-empty root list replaces roots, and non-empty labels
// replace labels. Normalizers always come from config.yaml.
type PolicySettings struct {
	Mode      string
	RootOrder []string          // root names in file order
	Roots     map[string]string // name -> path as written ("~" allowed)
	Labels    map[string]map[string][]string
}

// WithPolicySettings returns a copy of c with s applied. Root paths are
// expanded and checked exactly as config.yaml's are.
func (c Config) WithPolicySettings(s PolicySettings) (Config, error) {
	out := c
	switch policy.Mode(s.Mode) {
	case "":
	case policy.ModeObserve, policy.ModeEnforce:
		out.Mode = policy.Mode(s.Mode)
	default:
		return Config{}, fmt.Errorf("policy.yaml: mode %q: want observe or enforce", s.Mode)
	}
	if len(s.RootOrder) > 0 {
		list := make(rootList, 0, len(s.RootOrder))
		for _, name := range s.RootOrder {
			p, ok := s.Roots[name]
			if !ok {
				return Config{}, fmt.Errorf("policy.yaml: root %q has no path", name)
			}
			list = append(list, normalize.Root{Name: name, Path: p})
		}
		roots, err := resolveRoots(list)
		if err != nil {
			return Config{}, fmt.Errorf("policy.yaml: %w", err)
		}
		out.Roots = roots
	}
	if len(s.Labels) > 0 {
		if err := checkLabels(s.Labels); err != nil {
			return Config{}, fmt.Errorf("policy.yaml: %w", err)
		}
		out.Labels = s.Labels
	}
	return out, nil
}
