package peer

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"vibepn/config"
	"vibepn/log"
	"vibepn/netgraph"
	"vibepn/protocol"

	"github.com/quic-go/quic-go"
)

// RoutePolicy decides whether a peer may announce a route.
type RoutePolicy interface {
	// Allow returns an error if the peer is not permitted to announce the
	// given network/prefix.
	Allow(peerID, network, prefix string) error
}

// ConfigRoutePolicy enforces that peers may only announce prefixes for
// networks they are assigned to. When a peer has no explicit network
// assignment, any configured network is allowed (open policy).
type ConfigRoutePolicy struct {
	netcfg func() map[string]config.NetworkConfig
	peers  func() map[string][]string // peer name → allowed networks
}

// NewConfigRoutePolicy builds a policy from the daemon's network config and
// configured peer network assignments.
func NewConfigRoutePolicy(
	netcfg func() map[string]config.NetworkConfig,
	peers func() map[string][]string,
) *ConfigRoutePolicy {
	return &ConfigRoutePolicy{netcfg: netcfg, peers: peers}
}

// Allow implements RoutePolicy.
func (p *ConfigRoutePolicy) Allow(peerID, network, prefix string) error {
	networks := p.netcfg()
	if _, ok := networks[network]; !ok {
		return fmt.Errorf("network %q is not configured locally", network)
	}

	// Validate the announced prefix is a well-formed CIDR.
	if _, _, err := net.ParseCIDR(prefix); err != nil {
		return fmt.Errorf("invalid announced prefix %q: %v", prefix, err)
	}

	// If the peer is pinned to specific networks, enforce them.
	if nets, ok := p.peers()[peerID]; ok && len(nets) > 0 {
		for _, n := range nets {
			if n == network {
				return nil
			}
		}
		return fmt.Errorf("peer %s is not allowed to announce network %q", peerID, network)
	}

	return nil
}

// HandleControlStream reads and processes control messages from a peer until
// the stream or connection closes.
func HandleControlStream(conn quic.Connection, stream io.ReadWriter, peerID string) {
	logger := log.New("peer/control")

	for {
		msg, err := protocol.ReadMessage(stream)
		if err != nil {
			logger.Warnf("Control stream from %s closed: %v", peerID, err)
			_ = conn.CloseWithError(0, "control stream closed")
			return
		}

		switch m := msg.(type) {
		case protocol.Hello:
			logger.Infof("Received Hello from %s (nonce=%d)", peerID, m.Nonce)

		case protocol.RouteAnnounce:
			logger.Infof("Received Route-Announce from %s for network %s", peerID, m.Network)
			handleRouteAnnounce(m, peerID)

		case protocol.RouteWithdraw:
			logger.Infof("Received Route-Withdraw from %s for network %s", peerID, m.Network)
			handleRouteWithdraw(m)

		case protocol.Keepalive:
			if tracker := GetPeerTracker(); tracker != nil {
				tracker.UpdatePeer(peerID)
			}

		case protocol.Ping:
			// Reply with a Pong carrying the same nonce.
			if err := protocol.WriteMessage(stream, protocol.Pong{Nonce: m.Nonce}); err != nil {
				logger.Warnf("Failed to send Pong to %s: %v", peerID, err)
			}

		case protocol.Pong:
			// Latency probes are handled by the caller (vpnctl test);
			// nothing to do here.

		case protocol.Goodbye:
			logger.Infof("Received Goodbye from %s", peerID)
			_ = conn.CloseWithError(0, "peer sent goodbye")
			return

		default:
			logger.Warnf("Unknown control message type %T from %s", msg, peerID)
		}
	}
}

func handleRouteAnnounce(msg protocol.RouteAnnounce, peerID string) {
	logger := log.New("peer/route-announce")

	for _, prefix := range msg.Prefixes {
		route := netgraph.Route{
			Network: msg.Network,
			Prefix:  prefix,
			PeerID:  peerID,
			Metric:  int(msg.Metric),
		}
		if err := GetRoutePolicy().Allow(peerID, msg.Network, prefix); err != nil {
			logger.Warnf("Rejected route from %s: %v", peerID, err)
			continue
		}
		if rt := GetRouteTable(); rt != nil {
			rt.AddRoute(route)
		}
		logger.Infof("Learned route: %+v", route)
	}
}

func handleRouteWithdraw(msg protocol.RouteWithdraw) {
	logger := log.New("peer/route-withdraw")
	logger.Infof("Withdraw route network=%s, prefix=%s", msg.Network, msg.Prefix)
	if rt := GetRouteTable(); rt != nil {
		rt.RemoveRoute(msg.Network, msg.Prefix)
	}
}

// StartKeepaliveLoop writes keepalives on a stream until the returned stop
// function is called or a write fails.
func StartKeepaliveLoop(stream quic.Stream) (stop func()) {
	logger := log.New("control/keepalive")
	done := make(chan struct{})
	var once sync.Once

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if err := protocol.WriteMessage(stream, protocol.Keepalive{Timestamp: protocol.NowTimestamp()}); err != nil {
					logger.Warnf("Failed to send keepalive: %v", err)
					return
				}
			}
		}
	}()

	return func() { once.Do(func() { close(done) }) }
}
