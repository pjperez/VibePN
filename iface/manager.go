package iface

import (
	"fmt"
	"net"

	"vibepn/config"
	"vibepn/log"
	"vibepn/tun"
)

// Manager owns the TUN devices for all local networks.
type Manager struct {
	Devices map[string]*tun.Device // network → device
	logger  *log.Logger
}

// Init creates a TUN device for every configured network. Networks that fail
// to initialize are skipped with a warning; an error is only returned if no
// device could be created at all.
func Init(cfg map[string]config.NetworkConfig, nodeID string) (*Manager, error) {
	logger := log.New("iface/init")
	devs := make(map[string]*tun.Device)

	for name, netcfg := range cfg {
		addr, err := config.ResolveAddressForNetwork(name, nodeID, cfg)
		if err != nil {
			logger.Errorf("Skipping network %s: %v", name, err)
			continue
		}

		cidr := fmt.Sprintf("%s/%d", addr, maskSize(netcfg.Prefix))
		dev, err := tun.Open(cidr, nodeID, name)
		if err != nil {
			logger.Errorf("Failed to open TUN for %s: %v", name, err)
			continue
		}

		logger.Infof("Network %s attached to %s (%s)", name, dev.Name(), cidr)
		devs[name] = dev
	}

	if len(devs) == 0 {
		return nil, fmt.Errorf("no network interfaces could be initialized")
	}

	return &Manager{
		Devices: devs,
		logger:  logger,
	}, nil
}

func maskSize(cidr string) int {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 24 // fallback
	}
	ones, _ := ipnet.Mask.Size()
	return ones
}
