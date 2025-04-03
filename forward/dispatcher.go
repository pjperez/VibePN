package forward

import (
	"context"
	"encoding/json"
	"net"

	"vibepn/log"
	"vibepn/netgraph"
	"vibepn/peer"
	"vibepn/tun"
)

type Dispatcher struct {
	Routes   *netgraph.RouteTable
	Ifaces   map[string]*tun.Device
	Registry *peer.Registry
	Logger   *log.Logger
}

func NewDispatcher(routes *netgraph.RouteTable, ifaces map[string]*tun.Device, registry *peer.Registry) *Dispatcher {
	return &Dispatcher{
		Routes:   routes,
		Ifaces:   ifaces,
		Registry: registry,
		Logger:   log.New("forward/dispatcher"),
	}
}

func (d *Dispatcher) Start(network string, dev *tun.Device) {
	go func() {
		buf := make([]byte, 1500)
		for {
			n, err := dev.Read(buf)
			if err != nil {
				d.Logger.Errorf("[%s] TUN read error: %v", network, err)
				return
			}

			pkt := buf[:n]
			dst := parseDstIP(pkt)
			if dst == nil {
				d.Logger.Warnf("[%s] Invalid IP packet", network)
				continue
			}

			route := d.lookupRoute(network, dst.String())
			if route == nil {
				d.Logger.Warnf("[%s] No route for %s", network, dst)
				continue
			}

			conn := d.Registry.Get(route.PeerID)
			if conn == nil {
				d.Logger.Warnf("[%s] No active connection for peer %s", network, route.PeerID)
				continue
			}

			stream, err := conn.OpenStreamSync(context.Background())
			if err != nil {
				d.Logger.Warnf("[%s] Failed to open stream to peer %s: %v", network, route.PeerID, err)
				continue
			}

			// Write stream header
			header := map[string]string{
				"type":    "raw",
				"network": network,
			}
			if err := json.NewEncoder(stream).Encode(header); err != nil {
				d.Logger.Warnf("[%s] Failed to write stream header: %v", network, err)
				stream.Close()
				continue
			}

			// Write packet
			_, err = stream.Write(pkt)
			if err != nil {
				d.Logger.Warnf("[%s] Failed to write to stream: %v", network, err)
				stream.Close()
				continue
			}

			stream.Close()
			d.Logger.Debugf("[%s] Sent %d bytes to %s", network, n, route.PeerID)
		}
	}()
}

func parseDstIP(pkt []byte) net.IP {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return nil
	}
	return net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])
}

func (d *Dispatcher) lookupRoute(network, ip string) *netgraph.Route {
	routes := d.Routes.RoutesForNetwork(network, "")
	dst := net.ParseIP(ip)
	if dst == nil {
		return nil
	}

	for _, r := range routes {
		_, subnet, err := net.ParseCIDR(r.Prefix)
		if err != nil {
			continue
		}
		if subnet.Contains(dst) {
			return &r
		}
	}
	return nil
}
