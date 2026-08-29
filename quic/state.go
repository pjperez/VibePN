package quic

import (
	"sync"

	"vibepn/config"
)

var (
	netCfgMu sync.RWMutex
	netCfg   = map[string]config.NetworkConfig{}
)

// SetNetConfig replaces the snapshot of local network configuration used for
// route announcements.
func SetNetConfig(nc map[string]config.NetworkConfig) {
	copyCfg := make(map[string]config.NetworkConfig, len(nc))
	for name, cfg := range nc {
		copyCfg[name] = cfg
	}

	netCfgMu.Lock()
	netCfg = copyCfg
	netCfgMu.Unlock()
}

func netConfigSnapshot() map[string]config.NetworkConfig {
	netCfgMu.RLock()
	defer netCfgMu.RUnlock()

	out := make(map[string]config.NetworkConfig, len(netCfg))
	for name, cfg := range netCfg {
		out[name] = cfg
	}
	return out
}
