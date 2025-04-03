package config

import (
	"os"

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

// Load reads and parses the config file
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
