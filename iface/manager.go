package iface

import (
	"fmt"
	"net"
	"vibepn/config"
	"vibepn/log"
	"vibepn/tun"
)

type Manager struct {
	Devices map[string]*tun.Device // network → device
	logger  *log.Logger
}

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
		dev, err := tun.Open(cidr, nodeID)
		if err != nil {
			logger.Errorf("Failed to open TUN for %s: %v", name, err)
			continue
		}

		logger.Infof("Network %s attached to %s (%s)", name, dev.Name(), cidr)
		devs[name] = dev
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
