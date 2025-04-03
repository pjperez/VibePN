package config

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

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
		return deriveAutoAddress(network, nodeID, cfg.Prefix)
	}

	ip := net.ParseIP(cfg.Address)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address for network %q: %q", network, cfg.Address)
	}

	return cfg.Address, nil
}

func deriveAutoAddress(network, nodeID, prefix string) (string, error) {
	_, ipnet, err := net.ParseCIDR(prefix)
	if err != nil {
		return "", fmt.Errorf("invalid CIDR prefix for %s: %v", network, err)
	}

	ones, bits := ipnet.Mask.Size()
	if bits != 32 || ones >= 31 {
		return "", errors.New("only IPv4 prefixes < /31 are supported")
	}

	// Hash nodeID to get host offset
	h := sha256.New()
	h.Write([]byte(network + ":" + nodeID))
	sum := h.Sum(nil)
	hostOffset := binary.BigEndian.Uint32(sum[:4]) & ((1 << (32 - ones)) - 2) // exclude .0 and .255

	// Add offset to base IP
	base := ipnet.IP.To4()
	if base == nil {
		return "", errors.New("prefix must be IPv4")
	}

	ip := make(net.IP, 4)
	copy(ip, base)
	ip[3] += byte(hostOffset & 0xff)
	ip[2] += byte((hostOffset >> 8) & 0xff)
	ip[1] += byte((hostOffset >> 16) & 0xff)
	ip[0] += byte((hostOffset >> 24) & 0xff)

	if !ipnet.Contains(ip) {
		return "", fmt.Errorf("derived IP %s not in subnet %s", ip.String(), prefix)
	}

	return ip.String(), nil
}
