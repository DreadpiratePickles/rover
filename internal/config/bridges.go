package config

import (
	"fmt"
	"sort"

	"github.com/DreadpiratePickles/rover/internal/bridge"
	"github.com/DreadpiratePickles/rover/internal/ipc"
)

// Bridge is one remote MCP server reached through `rover bridge` (M11).
//
//	bridges:
//	  github:
//	    url: https://api.githubcopilot.com/mcp
//	    pq_required: true          # offer only X25519MLKEM768
//	    ca_file: ~/certs/corp.pem  # optional extra root CA (PEM)
//	    auth:
//	      type: oauth              # oauth (default), bearer, or none
//	      keychain: github         # keychain account; default: the bridge name
//	      client_id: abc123        # oauth: a pre-registered client id
//
// config.yaml is covered by `rover policy apply` (M9), so these settings,
// unlike the flags in a client's MCP config, cannot be changed by an agent
// without a human approving it. `rover bridge` therefore takes the stricter
// of the two: pq_required from either, and a url that must match.
type Bridge struct {
	Name       string
	URL        string
	PQRequired bool
	CAFile     string
	Auth       BridgeAuth
}

// BridgeAuth is a bridge's auth section.
type BridgeAuth struct {
	Type     string // AuthOAuth, AuthBearer or AuthNone
	Keychain string // the keychain account
	ClientID string
}

// Bridge auth types.
const (
	AuthOAuth  = "oauth"
	AuthBearer = "bearer"
	AuthNone   = "none"
)

type bridgeFile struct {
	URL        string `yaml:"url"`
	PQRequired bool   `yaml:"pq_required"`
	CAFile     string `yaml:"ca_file"`
	Auth       struct {
		Type     string `yaml:"type"`
		Keychain string `yaml:"keychain"`
		ClientID string `yaml:"client_id"`
	} `yaml:"auth"`
}

func parseBridges(in map[string]bridgeFile, dir string) (map[string]Bridge, error) {
	out := make(map[string]Bridge, len(in))
	for name, b := range in {
		if err := ipc.ValidServerName(name); err != nil {
			return nil, fmt.Errorf("config: bridges.%s: %w", name, err)
		}
		if _, err := bridge.CheckURL(b.URL, b.PQRequired); err != nil {
			return nil, fmt.Errorf("config: bridges.%s.url: %w", name, err)
		}
		br := Bridge{Name: name, URL: b.URL, PQRequired: b.PQRequired,
			Auth: BridgeAuth{Type: b.Auth.Type, Keychain: b.Auth.Keychain, ClientID: b.Auth.ClientID}}
		switch br.Auth.Type {
		case "":
			br.Auth.Type = AuthOAuth
		case AuthOAuth, AuthBearer, AuthNone:
		default:
			return nil, fmt.Errorf("config: bridges.%s.auth.type %q: want oauth, bearer or none", name, br.Auth.Type)
		}
		if br.Auth.Keychain == "" {
			br.Auth.Keychain = name
		} else if err := ipc.ValidServerName(br.Auth.Keychain); err != nil {
			return nil, fmt.Errorf("config: bridges.%s.auth.keychain: %w", name, err)
		}
		if b.CAFile != "" {
			p, err := expandPath(b.CAFile, dir)
			if err != nil {
				return nil, fmt.Errorf("config: bridges.%s.ca_file: %w", name, err)
			}
			br.CAFile = p
		}
		out[name] = br
	}
	return out, nil
}

// BridgeNames lists the configured bridges, sorted.
func (c Config) BridgeNames() []string {
	out := make([]string, 0, len(c.Bridges))
	for n := range c.Bridges {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
