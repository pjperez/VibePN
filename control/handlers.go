package control

import (
	"encoding/json"
	"net/netip"
	"time"

	"vibepn/config"
	"vibepn/log"
)

type CommandRequest struct {
	Cmd string `json:"cmd"`
}

type CommandResponse struct {
	Status string      `json:"status"`
	Output interface{} `json:"output,omitempty"`
	Error  string      `json:"error,omitempty"`
}

func Handle(cmd string, _ json.RawMessage, logger *log.Logger) CommandResponse {
	switch cmd {
	case "routes":
		var output []map[string]interface{}
		for _, r := range GetRouteTable().AllRoutes() {
			output = append(output, map[string]interface{}{
				"network": r.Network,
				"prefix":  r.Prefix,
				"peer":    r.PeerID,
				"metric":  r.Metric,
				"expires": r.ExpiresAt.Format(time.RFC3339),
			})
		}
		return CommandResponse{Status: "ok", Output: output}

	case "peers":
		var output []map[string]interface{}
		for _, p := range GetPeerTracker().ListPeers() {
			output = append(output, map[string]interface{}{
				"id":        p.ID,
				"last_seen": p.LastSeen.Format(time.RFC3339),
			})
		}
		return CommandResponse{Status: "ok", Output: output}

	case "status":
		resp := map[string]interface{}{
			"uptime": Uptime(),
			"peers":  len(GetPeerTracker().ListPeers()),
			"routes": len(GetRouteTable().AllRoutes()),
		}
		return CommandResponse{Status: "ok", Output: resp}

	case "reload":
		cfg, err := config.Load("~/.vibepn/config.toml")
		if err != nil {
			return CommandResponse{
				Status: "error",
				Error:  "failed to reload config: " + err.Error(),
			}
		}

		// 🔍 Static validation
		seenNames := make(map[string]bool)
		for name, net := range cfg.Networks {
			if seenNames[name] {
				return CommandResponse{
					Status: "error",
					Error:  "duplicate network name: " + name,
				}
			}
			seenNames[name] = true

			if net.Address != "auto" && net.Address == "" {
				return CommandResponse{
					Status: "error",
					Error:  "network " + name + " must have address or use auto",
				}
			}

			_, err := netip.ParsePrefix(net.Prefix)
			if err != nil {
				return CommandResponse{
					Status: "error",
					Error:  "invalid prefix for network " + name + ": " + err.Error(),
				}
			}
		}

		if cfg.Identity.Fingerprint == "" || cfg.Identity.Cert == "" || cfg.Identity.Key == "" {
			return CommandResponse{
				Status: "error",
				Error:  "identity section is incomplete",
			}
		}

		// 🧠 If passed, apply
		routeTable := GetRouteTable()
		peerTracker := GetPeerTracker()
		routeTable.RemoveRoutesForPeer(cfg.Identity.Fingerprint)

		for name, net := range cfg.Networks {
			route := Route{
				Prefix:    net.Prefix,
				PeerID:    cfg.Identity.Fingerprint,
				Metric:    1,
				ExpiresIn: 30,
			}

			for _, p := range peerTracker.ListPeers() {
				SendRouteToPeer(p.ID, name, route)
			}
		}

		return CommandResponse{
			Status: "ok",
			Output: map[string]interface{}{
				"message": "config validated, reloaded, and routes re-announced",
			},
		}

	case "goodbye":
		TriggerGoodbye()
		return CommandResponse{
			Status: "ok",
			Output: map[string]interface{}{
				"message": "sent goodbye to all peers",
			},
		}

	default:
		logger.Warnf("Unknown control command: %s", cmd)
		return CommandResponse{
			Status: "error",
			Error:  "unknown command: " + cmd,
		}
	}
}
