package config

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// ResolveAddressForNetwork returns the local IP address for a network:
// the configured static address, or a deterministic address derived from
// the network name and node ID when configured as "auto".
func ResolveAddressForNetwork(
	network string,
	nodeID string,
	networks map[string]NetworkConfig,
) (string, error) {
	cfg, ok := networks[network]
	if !ok {
		return "", fmt.Errorf("no config for network %q", network)
	}

	if cfg.Address == "" {
		return "", fmt.Errorf("network %q has no address assigned", network)
	}

	if cfg.Address == "auto" {
		if nodeID == "" {
			return "", fmt.Errorf("cannot derive auto address: nodeID is empty")
		}
		return deriveAutoAddress(network, nodeID, cfg.Prefix)
	}

	ip := net.ParseIP(cfg.Address)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address for network %q: %q", network, cfg.Address)
	}

	return cfg.Address, nil
}

func deriveAutoAddress(network, nodeID, prefix string) (string, error) {
	ip, ipnet, err := net.ParseCIDR(prefix)
	if err != nil {
		return "", fmt.Errorf("invalid CIDR prefix for %s: %v", network, err)
	}

	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return "", errors.New("only IPv4 prefixes are supported for auto addresses")
	}
	hostBits := 32 - ones
	if hostBits < 2 {
		return "", errors.New("prefix must have at least 2 host bits (a /30 or smaller)")
	}

	// Hash of network + nodeID ensures a deterministic IP per network per node.
	h := sha256.Sum256([]byte(network + ":" + nodeID))
	hostOffset := binary.BigEndian.Uint32(h[:4]) & ((1 << hostBits) - 1)

	base := ip.To4()
	if base == nil {
		return "", errors.New("prefix must be IPv4")
	}

	baseInt := binary.BigEndian.Uint32(base)

	// hostOffset == 0 would map to the network address itself; skip it.
	if hostOffset == 0 {
		hostOffset = 1
	}
	// The all-ones host offset is the broadcast address; skip it.
	if hostOffset == (1<<hostBits)-1 {
		hostOffset--
	}

	derived := baseInt + hostOffset

	var out net.IP = make([]byte, 4)
	binary.BigEndian.PutUint32(out, derived)

	if !ipnet.Contains(out) {
		return "", fmt.Errorf("derived IP %s not in subnet %s", out.String(), prefix)
	}

	return out.String(), nil
}
