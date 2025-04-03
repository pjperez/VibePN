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

	for _, p := range peers {
		go func(peer config.Peer) {
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

			for name, net := range netcfg {
				route := control.Route{
					Prefix:    net.Prefix,
					PeerID:    identity.Fingerprint, // this peer will serve the prefix
					Metric:    1,
					ExpiresIn: 30,
				}
				control.SendRouteAnnounce(conn, name, []control.Route{route}, logger)
			}

		}(p)
	}
}
