package peer

import (
	"context"

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

	if identity.Fingerprint == "" {
		logger.Warnf("Local identity has no fingerprint set — route announcements may fail")
	}

	for _, p := range peers {
		peer := p
		logger.Infof("Launching goroutine to connect to peer: %s", peer.Name)
		go func(peer config.Peer) {
			logger.Infof("Started goroutine for peer %s (%s)", peer.Name, peer.Address)
			logger.Infof("Connecting to %s (%s)", peer.Name, peer.Address)

			tlsConf, err := crypto.LoadPeerTLSWithTOFU(peer.Name, peer.Address)
			if err != nil {
				logger.Errorf("Failed to create TLS config for %s: %v", peer.Name, err)
				return
			}

			conn, err := quic.DialAddr(
				context.Background(),
				peer.Address,
				tlsConf,
				nil,
			)
			if err != nil {
				logger.Errorf("Failed to connect to peer %s: %v", peer.Name, err)
				return
			}

			registry.Add(peer.Fingerprint, conn)

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
				addr, err := config.ResolveAddressForNetwork(name, identity.Fingerprint, netcfg)
				if err != nil {
					logger.Warnf("Skipping network %s: %v", name, err)
					continue
				}

				hello.Networks = append(hello.Networks, struct {
					Name    string `json:"name"`
					Address string `json:"address"`
				}{
					Name:    name,
					Address: addr,
				})
			}

			control.SendHello(conn, hello, logger)
			go control.SendKeepalive(conn, logger)

			logger.Infof("Preparing to send route announcements for %d networks using fingerprint: %s", len(netcfg), identity.Fingerprint)

			for name, net := range netcfg {
				route := control.Route{
					Prefix:    net.Prefix,
					PeerID:    identity.Fingerprint,
					Metric:    1,
					ExpiresIn: 30,
				}
				logger.Infof("Announcing route for network=%s prefix=%s", name, net.Prefix)
				control.SendRouteAnnounce(conn, name, []control.Route{route}, logger)
			}
		}(p)
	}
}
