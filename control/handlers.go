package control

import (
	"time"

	"vibepn/config"
	"vibepn/log"
	"vibepn/netgraph"
	"vibepn/shared"
)

// PeerLister lists currently-live peers.
type PeerLister interface {
	ListPeers() []shared.PeerState
	UpdatePeer(peerID string)
}

// PeerSender sends a route announcement to a peer.
type PeerSender interface {
	SendRoute(peerID, network string, route netgraph.Route) error
}

// PeerManager is the interface the daemon exposes to the control server for
// connection management.
type PeerManager interface {
	PeerLister
	PeerSender
	DisconnectAll()
	ReconcilePeers(cfg *config.Config) error
}

// ServerDeps wires the control server to daemon subsystems.
type ServerDeps struct {
	ConfigPath string
	Routes     *netgraph.RouteTable
	Peers      PeerManager
	// Tracker reports liveness (last-seen) state; when set it is the source
	// for the "peers" and "status" commands so stale QUIC connections that
	// have stopped sending keepalives are surfaced promptly.
	Tracker    PeerLister
	IdentityFP string
	Logger     *log.Logger
}

// Handler builds a command handler function for a UDS server.
func Handler(deps ServerDeps) func(cmd string, logger *log.Logger) CommandResponse {
	return func(cmd string, logger *log.Logger) CommandResponse {
		switch cmd {
		case "routes":
			var output []map[string]interface{}
			for _, r := range deps.Routes.AllRoutes() {
				output = append(output, map[string]interface{}{
					"network": r.Network,
					"prefix":  r.Prefix,
					"peer":    r.PeerID,
					"metric":  r.Metric,
					"expires": formatExpiry(r.ExpiresAt),
				})
			}
			return CommandResponse{Status: "ok", Output: output}

		case "peers":
			var output []map[string]interface{}
			for _, p := range peerList(deps).ListPeers() {
				output = append(output, map[string]interface{}{
					"id":        p.ID,
					"last_seen": p.LastSeen.Format(time.RFC3339),
				})
			}
			return CommandResponse{Status: "ok", Output: output}

		case "status":
			resp := map[string]interface{}{
				"uptime": Uptime(),
				"peers":  len(peerList(deps).ListPeers()),
				"routes": len(deps.Routes.AllRoutes()),
			}
			return CommandResponse{Status: "ok", Output: resp}

		case "reload":
			return handleReload(deps, logger)

		case "goodbye":
			deps.Peers.DisconnectAll()
			return CommandResponse{
				Status: "ok",
				Output: map[string]interface{}{"message": "sent goodbye to all peers"},
			}

		default:
			logger.Warnf("Unknown control command: %s", cmd)
			return CommandResponse{Status: "error", Error: "unknown command: " + cmd}
		}
	}
}

// peerList returns the liveness tracker when available, otherwise the peer
// manager's connection list.
func peerList(deps ServerDeps) PeerLister {
	if deps.Tracker != nil {
		return deps.Tracker
	}
	return deps.Peers
}

func handleReload(deps ServerDeps, logger *log.Logger) CommandResponse {
	cfg, err := config.Load(deps.ConfigPath)
	if err != nil {
		return CommandResponse{Status: "error", Error: "failed to reload config: " + err.Error()}
	}
	if err := cfg.Validate(); err != nil {
		return CommandResponse{Status: "error", Error: "invalid config: " + err.Error()}
	}

	// Re-announce local routes to all live peers.
	deps.Routes.RemoveByPeer(deps.IdentityFP)
	for name, netCfg := range cfg.Networks {
		if !netCfg.Export {
			continue
		}
		route := netgraph.Route{
			Network: name,
			Prefix:  netCfg.Prefix,
			PeerID:  deps.IdentityFP,
			Metric:  1,
		}
		deps.Routes.AddRoute(route)

		for _, p := range peerList(deps).ListPeers() {
			if err := deps.Peers.SendRoute(p.ID, name, route); err != nil {
				logger.Warnf("Failed to announce route to %s: %v", p.ID, err)
			}
		}
	}

	// Reconcile the peer set (add new peers, update addresses).
	if err := deps.Peers.ReconcilePeers(cfg); err != nil {
		logger.Warnf("Peer reconciliation failed: %v", err)
	}

	return CommandResponse{
		Status: "ok",
		Output: map[string]interface{}{
			"message": "config validated, reloaded, and routes re-announced",
		},
	}
}

func formatExpiry(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.Format(time.RFC3339)
}
