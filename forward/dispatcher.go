package forward

import (
	"context"
	"encoding/binary"
	"net"
	"time"

	"vibepn/log"
	"vibepn/metrics"
	"vibepn/netgraph"
	"vibepn/peer"
	"vibepn/tun"

	"github.com/quic-go/quic-go"
)

const (
	packetBufSize = 65535
	openTimeout   = 5 * time.Second
)

// Dispatcher reads packets from local TUN devices and forwards them to the
// peer that announced the best route for the destination.
type Dispatcher struct {
	routes   *netgraph.RouteTable
	ifaces   map[string]*tun.Device
	registry *peer.Registry
	logger   *log.Logger
}

func NewDispatcher(routes *netgraph.RouteTable, ifaces map[string]*tun.Device, registry *peer.Registry) *Dispatcher {
	return &Dispatcher{
		routes:   routes,
		ifaces:   ifaces,
		registry: registry,
		logger:   log.New("forward/dispatcher"),
	}
}

// Start launches a forwarding goroutine for one network device.
func (d *Dispatcher) Start(network string, dev *tun.Device) {
	go func() {
		buf := make([]byte, packetBufSize)
		for {
			n, err := dev.Read(buf)
			if err != nil {
				d.logger.Errorf("[%s] TUN read error: %v", network, err)
				return
			}

			pkt := buf[:n]
			dst := parseDstIP(pkt)
			if dst == nil {
				metrics.PacketsDropped.WithLabelValues("invalid_ip").Inc()
				d.logger.Warnf("[%s] Invalid IP packet (%d bytes)", network, n)
				continue
			}

			route := d.routes.Lookup(network, dst.String())
			if route == nil {
				metrics.PacketsDropped.WithLabelValues("no_route").Inc()
				d.logger.Debugf("[%s] No route for %s", network, dst)
				continue
			}

			conn := d.registry.Get(route.PeerID)
			if conn == nil {
				metrics.PacketsDropped.WithLabelValues("no_peer").Inc()
				d.logger.Warnf("[%s] No active connection for peer %s", network, route.PeerID)
				continue
			}

			if err := d.sendPacket(conn, network, pkt); err != nil {
				metrics.PacketsDropped.WithLabelValues("send_error").Inc()
				d.logger.Warnf("[%s] Failed to send packet to %s: %v", network, route.PeerID, err)
				continue
			}
			metrics.PacketsForwarded.WithLabelValues(network).Inc()
		}
	}()
}

// sendPacket opens a fresh stream and writes one framed packet.
func (d *Dispatcher) sendPacket(conn quic.Connection, network string, pkt []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), openTimeout)
	stream, err := conn.OpenStreamSync(ctx)
	cancel()
	if err != nil {
		return err
	}
	defer stream.Close()

	if len(network) == 0 || len(network) > 255 {
		return errNetworkName
	}
	if len(pkt) > 0xFFFF {
		return errPacketTooLarge
	}

	header := make([]byte, 1+len(network)+2)
	header[0] = byte(len(network))
	copy(header[1:], network)
	binary.BigEndian.PutUint16(header[1+len(network):], uint16(len(pkt)))

	if _, err := stream.Write(header); err != nil {
		return err
	}
	if _, err := stream.Write(pkt); err != nil {
		return err
	}
	return nil
}

// parseDstIP extracts the destination IPv4 address from a raw IP packet.
func parseDstIP(pkt []byte) net.IP {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return nil
	}
	return net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])
}
