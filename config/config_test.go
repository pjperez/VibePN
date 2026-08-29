package config

import (
	"errors"
	"net"
	"strings"
	"testing"
)

func TestResolveAddressForNetworkStatic(t *testing.T) {
	networks := map[string]NetworkConfig{
		"corp": {
			Address: "10.42.0.10",
			Prefix:  "10.42.0.0/24",
		},
	}

	addr, err := ResolveAddressForNetwork("corp", "node-a", networks)
	if err != nil {
		t.Fatalf("ResolveAddressForNetwork returned error: %v", err)
	}
	if addr != "10.42.0.10" {
		t.Fatalf("unexpected static address: got %q want %q", addr, "10.42.0.10")
	}
}

func TestResolveAddressForNetworkAutoDeterministic(t *testing.T) {
	networks := map[string]NetworkConfig{
		"corp": {
			Address: "auto",
			Prefix:  "10.42.0.0/24",
		},
	}

	addr1, err := ResolveAddressForNetwork("corp", "node-a", networks)
	if err != nil {
		t.Fatalf("first auto resolution failed: %v", err)
	}
	addr2, err := ResolveAddressForNetwork("corp", "node-a", networks)
	if err != nil {
		t.Fatalf("second auto resolution failed: %v", err)
	}
	if addr1 != addr2 {
		t.Fatalf("auto address should be deterministic: %q != %q", addr1, addr2)
	}

	ip := net.ParseIP(addr1)
	if ip == nil {
		t.Fatalf("auto address is not a valid IP: %q", addr1)
	}
	_, subnet, err := net.ParseCIDR("10.42.0.0/24")
	if err != nil {
		t.Fatalf("failed to parse subnet: %v", err)
	}
	if !subnet.Contains(ip) {
		t.Fatalf("auto address %q not inside subnet %s", addr1, subnet.String())
	}
}

func TestResolveAddressForNetworkAutoNeverNetworkOrBroadcast(t *testing.T) {
	// A /30 has exactly 2 usable host addresses. The derived address must be
	// one of them and never the network or broadcast address.
	networks := map[string]NetworkConfig{
		"tiny": {
			Address: "auto",
			Prefix:  "192.0.2.0/30",
		},
	}

	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		addr, err := ResolveAddressForNetwork("tiny", strings.Repeat("n", i+1), networks)
		if err != nil {
			t.Fatalf("auto resolution failed: %v", err)
		}
		ip := net.ParseIP(addr)
		if ip == nil {
			t.Fatalf("invalid derived IP %q", addr)
		}
		if addr == "192.0.2.0" || addr == "192.0.2.3" {
			t.Fatalf("derived address %q is the network/broadcast address", addr)
		}
		seen[addr] = true
	}
	if len(seen) < 2 {
		t.Fatalf("expected both usable hosts to be reachable, got %v", seen)
	}
}

func TestResolveAddressForNetworkErrors(t *testing.T) {
	if _, err := ResolveAddressForNetwork("missing", "node-a", map[string]NetworkConfig{}); err == nil {
		t.Fatalf("expected error for missing network")
	}

	networks := map[string]NetworkConfig{
		"nohost": {Address: "auto", Prefix: "10.0.0.0/31"},
	}
	if _, err := ResolveAddressForNetwork("nohost", "node-a", networks); err == nil {
		t.Fatalf("expected error for /31 prefix")
	}

	networks = map[string]NetworkConfig{
		"badprefix": {Address: "auto", Prefix: "not-a-cidr"},
	}
	if _, err := ResolveAddressForNetwork("badprefix", "node-a", networks); err == nil {
		t.Fatalf("expected error for invalid prefix")
	}

	networks = map[string]NetworkConfig{
		"badaddr": {Address: "999.1.1.1", Prefix: "10.0.0.0/24"},
	}
	if _, err := ResolveAddressForNetwork("badaddr", "node-a", networks); err == nil {
		t.Fatalf("expected error for invalid static address")
	}
}

func TestConfigValidate(t *testing.T) {
	base := &Config{
		Identity: Identity{Cert: "/c", Key: "/k", Fingerprint: strings.Repeat("ab", 32)},
		Networks: map[string]NetworkConfig{
			"corp": {Address: "auto", Prefix: "10.42.0.0/24", Export: true},
		},
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	bad := *base
	bad.Identity.Fingerprint = "zz"
	if err := bad.Validate(); err == nil {
		t.Fatalf("expected error for invalid fingerprint")
	}

	bad = *base
	bad.Networks["corp"] = NetworkConfig{Address: "auto", Prefix: "nope"}
	if err := bad.Validate(); err == nil {
		t.Fatalf("expected error for invalid prefix")
	}

	bad = *base
	bad.Peers = []Peer{{Name: "p", Address: "no-port", Networks: []string{"corp"}}}
	if err := bad.Validate(); err == nil {
		t.Fatalf("expected error for invalid peer address")
	}

	bad = *base
	bad.Peers = []Peer{{Name: "p", Address: "1.2.3.4:51820", Networks: []string{"nope"}}}
	if err := bad.Validate(); err == nil {
		t.Fatalf("expected error for unknown network reference")
	}

	bad = *base
	bad.Peers = []Peer{
		{Name: "dup", Address: "1.2.3.4:51820", Networks: []string{"corp"}},
		{Name: "dup", Address: "1.2.3.5:51820", Networks: []string{"corp"}},
	}
	if err := bad.Validate(); err == nil {
		t.Fatalf("expected error for duplicate peer names")
	}

	empty := &Config{}
	if err := empty.Validate(); err == nil {
		t.Fatalf("expected error for empty config")
	}

	_ = errors.Is // keep errors import if unused paths change
}
