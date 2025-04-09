package peer

import (
	"context"
	"encoding/binary"
	"io"
	"time"

	"vibepn/config"
	"vibepn/control"
	"vibepn/crypto"
	"vibepn/log"
	"vibepn/netgraph"

	"github.com/quic-go/quic-go"
)

func ConnectToPeers(
	peers []config.Peer,
	identity config.Identity,
	routes *netgraph.RouteTable,
	netcfg map[string]config.NetworkConfig,
	registry *Registry,
) {
	logger := log.New("peer/manager")

	logger.Infof("identity.Fingerprint = %q", identity.Fingerprint)
	logger.Infof("netcfg contents: %+v", netcfg)

	for _, p := range peers {
		peer := p
		logger.Infof("Launching goroutine to connect to peer: %s", peer.Name)

		go func() {
			logger.Infof("Started goroutine for peer %s (%s)", peer.Name, peer.Address)

			tlsConf, err := crypto.LoadPeerTLSWithTOFU(peer.Name, peer.Address)
			if err != nil {
				logger.Errorf("Failed to create TLS config for %s: %v", peer.Name, err)
				return
			}
			logger.Infof("TLS config created for peer %s", peer.Name)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			logger.Infof("Dialing QUIC to %s...", peer.Address)
			conn, err := quic.DialAddr(ctx, peer.Address, tlsConf, nil)
			if err != nil {
				logger.Errorf("❌ QUIC dial to %s failed: %v", peer.Address, err)
				return
			}
			logger.Infof("✅ QUIC connection established to %s", peer.Address)

			registry.Add(peer.Fingerprint, conn)
			logger.Infof("Added connection to registry for peer %s", peer.Name)

			stream, err := conn.OpenStreamSync(context.Background())
			if err != nil {
				logger.Errorf("Failed to open control stream: %v", err)
				return
			}

			// 📨 Send Hello
			err = control.SendHello(stream)
			if err != nil {
				logger.Errorf("Failed to send hello: %v", err)
				return
			}

			// 🚀 Control Loop
			go HandleControlStream(conn, stream)
		}()
	}
}

func HandleControlStream(conn quic.Connection, stream quic.Stream) {
	logger := log.New("peer/control")

	for {
		lenBuf := make([]byte, 2)
		_, err := io.ReadFull(stream, lenBuf)
		if err != nil {
			logger.Warnf("Control stream closed: %v", err)
			conn.CloseWithError(0, "control stream closed")
			return
		}

		length := binary.BigEndian.Uint16(lenBuf)
		if length == 0 || length > 4096 {
			logger.Warnf("Invalid control message length: %d", length)
			conn.CloseWithError(0, "invalid control message length")
			return
		}

		msgBuf := make([]byte, length)
		_, err = io.ReadFull(stream, msgBuf)
		if err != nil {
			logger.Warnf("Failed to read full control message: %v", err)
			conn.CloseWithError(0, "invalid control payload")
			return
		}

		controlType := msgBuf[0]
		body := msgBuf[1:]

		switch controlType {
		case 'H':
			logger.Infof("Received Hello from %s", conn.RemoteAddr())
			// No-op for now

		case 'A':
			logger.Infof("Received Route-Announce from %s", conn.RemoteAddr())
			handleRouteAnnounce(body)

		case 'W':
			logger.Infof("Received Route-Withdraw from %s", conn.RemoteAddr())
			handleRouteWithdraw(body)

		case 'K':
			logger.Debugf("Received Keepalive from %s", conn.RemoteAddr())
			handleKeepalive(body)

		case 'G':
			logger.Infof("Received Goodbye from %s", conn.RemoteAddr())
			conn.CloseWithError(0, "peer sent goodbye")
			return

		default:
			logger.Warnf("Unknown control type: %q", controlType)
		}
	}
}

// 👇 Properly decode a Route-Announce message
func handleRouteAnnounce(body []byte) {
	logger := log.New("peer/route-announce")

	if len(body) < 2 {
		logger.Warnf("Invalid route-announce body")
		return
	}

	// First byte = network name length
	networkLen := int(body[0])
	if len(body) < 1+networkLen {
		logger.Warnf("Invalid route-announce network name length")
		return
	}

	networkName := string(body[1 : 1+networkLen])
	logger.Infof("Route-Announce for network: %s", networkName)

	cursor := 1 + networkLen

	for cursor < len(body) {
		if cursor+5 > len(body) {
			logger.Warnf("Invalid route-announce route length")
			return
		}

		// Parse each route
		prefixLen := int(body[cursor])
		prefixBytes := body[cursor+1 : cursor+1+prefixLen]
		metric := binary.BigEndian.Uint16(body[cursor+1+prefixLen : cursor+1+prefixLen+2])

		prefix := string(prefixBytes)
		cursor += 1 + prefixLen + 2

		route := netgraph.Route{
			Network: networkName,
			Prefix:  prefix,
			PeerID:  "", // PeerID unknown from packet; optional.
			Metric:  int(metric),
		}

		logger.Infof("Learned route: %+v", route)
		control.GetRouteTable().AddRoute(route)
	}
}

// 👇 Properly decode a Route-Withdraw message
func handleRouteWithdraw(body []byte) {
	logger := log.New("peer/route-withdraw")

	if len(body) < 2 {
		logger.Warnf("Invalid route-withdraw body")
		return
	}

	// First byte = network name length
	networkLen := int(body[0])
	if len(body) < 1+networkLen {
		logger.Warnf("Invalid route-withdraw network name length")
		return
	}

	networkName := string(body[1 : 1+networkLen])

	cursor := 1 + networkLen

	if cursor >= len(body) {
		logger.Warnf("Missing prefix in route-withdraw")
		return
	}

	// Next, prefix length and prefix bytes
	prefixLen := int(body[cursor])
	if cursor+1+prefixLen > len(body) {
		logger.Warnf("Invalid prefix in route-withdraw")
		return
	}

	prefix := string(body[cursor+1 : cursor+1+prefixLen])

	logger.Infof("Withdraw route network=%s, prefix=%s", networkName, prefix)

	control.GetRouteTable().RemoveRoute(networkName, prefix)
}

// 👇 Properly decode a Keepalive message
func handleKeepalive(body []byte) {
	logger := log.New("peer/keepalive")

	if len(body) < 8 {
		logger.Warnf("Invalid keepalive payload")
		return
	}

	timestamp := binary.BigEndian.Uint64(body)
	t := time.Unix(int64(timestamp), 0)

	logger.Debugf("Keepalive received: timestamp = %s", t.Format(time.RFC3339))
}
