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
	_, ipnet, err := net.ParseCIDR(prefix)
	if err != nil {
		return "", fmt.Errorf("invalid CIDR prefix for %s: %v", network, err)
	}

	ones, bits := ipnet.Mask.Size()
	if bits != 32 || ones >= 31 {
		return "", errors.New("only IPv4 prefixes < /31 are supported")
	}

	// Hash of network + nodeID ensures unique IP per network per node
	h := sha256.Sum256([]byte(network + ":" + nodeID))
	hostOffset := binary.BigEndian.Uint32(h[:4]) & ((1 << (32 - ones)) - 2) // exclude network/broadcast

	base := ipnet.IP.To4()
	if base == nil {
		return "", errors.New("prefix must be IPv4")
	}

	// Convert base IP to uint32, add offset, then back to IP
	baseInt := binary.BigEndian.Uint32(base)
	derived := baseInt + hostOffset

	var ip net.IP = make([]byte, 4)
	binary.BigEndian.PutUint32(ip, derived)

	if !ipnet.Contains(ip) {
		return "", fmt.Errorf("derived IP %s not in subnet %s", ip.String(), prefix)
	}

	return ip.String(), nil
}
