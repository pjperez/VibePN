// Package config: TOML configuration loading and validation.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Identity Identity                 `toml:"identity"`
	Peers    []Peer                   `toml:"peers"`
	Networks map[string]NetworkConfig `toml:"networks"`
}

type Identity struct {
	Cert        string `toml:"cert"`
	Key         string `toml:"key"`
	Fingerprint string `toml:"fingerprint"` // optional if using TOFU
}

type Peer struct {
	Name        string   `toml:"name"`
	Address     string   `toml:"address"`
	Fingerprint string   `toml:"fingerprint"` // optional if using TOFU
	Networks    []string `toml:"networks"`
}

type NetworkConfig struct {
	Address string `toml:"address"` // "auto" or static IP
	Prefix  string `toml:"prefix"`  // required if address is "auto"
	Export  bool   `toml:"export"`  // whether to announce to peers
}

// Load reads and parses the config file.
func Load(path string) (*Config, error) {
	var cfg Config

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if _, err := toml.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Write serializes cfg to path atomically with restrictive permissions.
func Write(path string, cfg *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(cfg); err != nil {
		return fmt.Errorf("encode config TOML: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if err := os.Chmod(tmp, 0600); err != nil {
		return fmt.Errorf("set config permissions: %w", err)
	}

	if err := os.Rename(tmp, path); err != nil {
		// Windows cannot rename over an existing file; fall back.
		if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
			return fmt.Errorf("remove old config: %w", rmErr)
		}
		if err2 := os.Rename(tmp, path); err2 != nil {
			return fmt.Errorf("rename config into place: %w", err2)
		}
	}
	return nil
}

// Validate checks the config for structural consistency.
func (c *Config) Validate() error {
	var errs []string

	if strings.TrimSpace(c.Identity.Cert) == "" {
		errs = append(errs, "identity.cert is required")
	}
	if strings.TrimSpace(c.Identity.Key) == "" {
		errs = append(errs, "identity.key is required")
	}
	if fp := strings.TrimSpace(c.Identity.Fingerprint); fp != "" && !validFingerprint(fp) {
		errs = append(errs, "identity.fingerprint must be 64 hex characters")
	}

	if len(c.Networks) == 0 {
		errs = append(errs, "at least one network is required")
	}
	for name, netCfg := range c.Networks {
		if strings.TrimSpace(name) == "" {
			errs = append(errs, "network name must not be empty")
		}
		prefix := strings.TrimSpace(netCfg.Prefix)
		if prefix == "" {
			errs = append(errs, fmt.Sprintf("network %q: prefix is required", name))
		} else if _, _, err := net.ParseCIDR(prefix); err != nil {
			errs = append(errs, fmt.Sprintf("network %q: invalid prefix %q: %v", name, prefix, err))
		}
		addr := strings.TrimSpace(netCfg.Address)
		if addr == "" {
			errs = append(errs, fmt.Sprintf("network %q: address is required (or \"auto\")", name))
		} else if addr != "auto" && net.ParseIP(addr) == nil {
			errs = append(errs, fmt.Sprintf("network %q: invalid address %q", name, addr))
		}
	}

	seenPeers := make(map[string]bool, len(c.Peers))
	for i, p := range c.Peers {
		if strings.TrimSpace(p.Name) == "" {
			errs = append(errs, fmt.Sprintf("peers[%d]: name is required", i))
		} else if seenPeers[p.Name] {
			errs = append(errs, fmt.Sprintf("peers[%d]: duplicate peer name %q", i, p.Name))
		}
		seenPeers[p.Name] = true

		if err := validatePeerAddress(p.Address); err != nil {
			errs = append(errs, fmt.Sprintf("peers[%d] (%s): %v", i, p.Name, err))
		}
		if fp := strings.TrimSpace(p.Fingerprint); fp != "" && !validFingerprint(fp) {
			errs = append(errs, fmt.Sprintf("peers[%d] (%s): fingerprint must be 64 hex characters", i, p.Name))
		}
		for _, n := range p.Networks {
			if _, ok := c.Networks[n]; !ok {
				errs = append(errs, fmt.Sprintf("peers[%d] (%s): references unknown network %q", i, p.Name, n))
			}
		}
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func validatePeerAddress(address string) error {
	host, port, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return fmt.Errorf("address %q must be host:port", address)
	}
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("address %q has empty host", address)
	}
	if strings.TrimSpace(port) == "" {
		return fmt.Errorf("address %q has empty port", address)
	}
	return nil
}

func validFingerprint(fp string) bool {
	if len(fp) != 64 {
		return false
	}
	for _, c := range fp {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
