package peer

import (
	"context"
	"time"

	"vibepn/config"
	"vibepn/control"
	"vibepn/crypto"
	"vibepn/log"
	"vibepn/netgraph"

	quic "github.com/quic-go/quic-go"
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

			hello := control.HelloMessage{
				NodeID: identity.Fingerprint,
				Networks: []struct {
					Name    string `json:"name"`
					Address string `json:"address"`
				}{},
				Features: map[string]bool{
					"metrics": true,
				},
			}

			for name := range netcfg {
				logger.Infof("Resolving address for network: %s", name)
				addr, err := config.ResolveAddressForNetwork(name, identity.Fingerprint, netcfg)
				if err != nil {
					logger.Warnf("Skipping network %s: %v", name, err)
					continue
				}
				logger.Infof("Resolved address for %s: %s", name, addr)

				hello.Networks = append(hello.Networks, struct {
					Name    string `json:"name"`
					Address string `json:"address"`
				}{
					Name:    name,
					Address: addr,
				})
			}

			logger.Infof("Sending hello to %s", peer.Name)
			control.SendHello(conn, hello, logger)

			go control.SendKeepalive(conn, logger)

			logger.Infof(">>> Preparing to send route announcements using fingerprint: %s", identity.Fingerprint)

			for name, net := range netcfg {
				if !net.Export {
					logger.Infof("Skipping network %s (export = false)", name)
					continue
				}

				route := control.Route{
					Prefix:    net.Prefix,
					PeerID:    identity.Fingerprint,
					Metric:    1,
					ExpiresIn: 30,
				}

				logger.Infof("Announcing route for network=%s prefix=%s", name, net.Prefix)
				control.SendRouteAnnounce(conn, name, []control.Route{route}, logger)
			}
		}()
	}
}
