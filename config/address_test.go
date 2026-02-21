package config

import (
	"net"
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

func TestResolveAddressForNetworkMissingNetwork(t *testing.T) {
	_, err := ResolveAddressForNetwork("missing", "node-a", map[string]NetworkConfig{})
	if err == nil {
		t.Fatalf("expected error for missing network")
	}
}
