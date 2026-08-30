package control

import (
	"context"
	"errors"
	"time"

	"vibepn/config"
	"vibepn/log"
	"vibepn/netgraph"
	"vibepn/protocol"
	"vibepn/shared"

	"github.com/quic-go/quic-go"
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

// PeerProber opens a control stream to a peer and measures round-trip
// latency using the Ping/Pong protocol messages.
type PeerProber interface {
	Probe(peerID string, timeout time.Duration) (latency time.Duration, err error)
}

// ServerDeps wires the control server to daemon subsystems.
type ServerDeps struct {
	ConfigPath string
	Routes     *netgraph.RouteTable
	Peers      PeerManager
	// Tracker reports liveness (last-seen) state; when set it is the source
	// for the "peers" and "status" commands so stale QUIC connections that
	// have stopped sending keepalives are surfaced promptly.
	Tracker PeerLister
	// Prober measures peer latency for the "test" command; optional.
	Prober     PeerProber
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

		case "test":
			return handleTest(deps, logger)

		case "logs":
			return CommandResponse{
				Status: "ok",
				Output: map[string]interface{}{"logs": log.RecentLogs(200)},
			}

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

// handleTest measures round-trip latency to every live peer (or a named one).
func handleTest(deps ServerDeps, logger *log.Logger) CommandResponse {
	if deps.Prober == nil {
		return CommandResponse{Status: "error", Error: "latency probing not available"}
	}

	peers := peerList(deps).ListPeers()
	if len(peers) == 0 {
		return CommandResponse{Status: "ok", Output: map[string]interface{}{"results": []interface{}{}}}
	}

	results := make([]map[string]interface{}, 0, len(peers))
	for _, p := range peers {
		latency, err := deps.Prober.Probe(p.ID, 3*time.Second)
		entry := map[string]interface{}{"peer": p.ID}
		if err != nil {
			entry["ok"] = false
			entry["error"] = err.Error()
		} else {
			entry["ok"] = true
			entry["latency_ms"] = float64(latency.Microseconds()) / 1000.0
		}
		results = append(results, entry)
	}
	return CommandResponse{Status: "ok", Output: map[string]interface{}{"results": results}}
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

// ProbePeer implements PeerProber over a quic.Connection.
type ProbePeer struct {
	GetConn func(peerID string) quic.Connection
}

// Probe opens a control stream, sends a Ping, and waits for the matching Pong.
// The stream read is bounded by the timeout so a dead peer cannot hang the
// control socket.
func (p *ProbePeer) Probe(peerID string, timeout time.Duration) (time.Duration, error) {
	conn := p.GetConn(peerID)
	if conn == nil {
		return 0, errNoConn
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return 0, err
	}
	defer stream.Close()

	// Bound the read so a peer that accepts the stream but never replies
	// cannot block the probe indefinitely.
	_ = stream.SetDeadline(time.Now().Add(timeout))

	nonce := uint64(time.Now().UnixNano())
	start := time.Now()
	if err := protocol.WriteMessage(stream, protocol.Ping{Nonce: nonce}); err != nil {
		return 0, err
	}

	// Read messages until we get the matching Pong.
	for {
		msg, err := protocol.ReadMessage(stream)
		if err != nil {
			return 0, err
		}
		if pong, ok := msg.(protocol.Pong); ok && pong.Nonce == nonce {
			return time.Since(start), nil
		}
	}
}

var errNoConn = errors.New("no active connection to peer")
