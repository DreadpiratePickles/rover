package normalize

import (
	"bytes"
	_ "embed" // for the built-in normalizers.yaml
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// maxConfigBytes caps the size of a normalizers.yaml we are willing to parse.
const maxConfigBytes = 1 << 20

//go:embed normalizers.yaml
var builtInYAML []byte

// Rules maps an argument name to the Kind of normaliser that applies to it,
// for one tool.
type Rules map[string]Kind

// Config is the parsed form of normalizers.yaml:
// servers -> server name -> tool name -> argument name -> Kind.
type Config struct {
	Servers map[string]map[string]Rules `yaml:"servers"`
}

// Parse decodes a normalizers.yaml document. It is strict, because a typo in
// a security config should be loud rather than silently ignored: unknown
// keys, unknown kinds, more than one YAML document, an empty document or a
// file over 1 MiB are all errors.
func Parse(b []byte) (Config, error) {
	if len(b) > maxConfigBytes {
		return Config{}, fmt.Errorf("normalize: config is %d bytes, limit %d", len(b), maxConfigBytes)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return Config{}, errors.New("normalize: config is empty")
		}
		return Config{}, fmt.Errorf("normalize: parse config: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("normalize: config must contain exactly one YAML document")
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	for server, tools := range c.Servers {
		for tool, rules := range tools {
			for arg, kind := range rules {
				if !kind.valid() {
					return fmt.Errorf("normalize: servers.%s.%s.%s: unknown kind %q", server, tool, arg, kind)
				}
			}
		}
	}
	return nil
}

// BuiltIn returns the embedded mappings for the official filesystem, fetch,
// git and GitHub servers. Each call returns a fresh Config, so callers may
// modify it without affecting anyone else.
func BuiltIn() Config {
	cfg, err := Parse(builtInYAML)
	if err != nil {
		// The file is compiled into the binary and covered by a test, so this
		// can only happen if someone ships a broken edit.
		panic("normalize: embedded normalizers.yaml is invalid: " + err.Error())
	}
	return cfg
}
