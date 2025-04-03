package forward

import (
	"io"
	"net"

	"vibepn/log"
	"vibepn/tun"

	"github.com/quic-go/quic-go"
)

type Inbound struct {
	Ifaces map[string]*tun.Device // network → device
	Logger *log.Logger
}

func NewInbound(ifaces map[string]*tun.Device) *Inbound {
	return &Inbound{
		Ifaces: ifaces,
		Logger: log.New("forward/inbound"),
	}
}

func (i *Inbound) HandleRawStream(stream quic.Stream, network string) {
	dev, ok := i.Ifaces[network]
	if !ok {
		i.Logger.Warnf("No interface for network %s", network)
		stream.CancelRead(0)
		return
	}

	defer stream.Close()

	buf := make([]byte, 1500)
	for {
		n, err := stream.Read(buf)
		if err == io.EOF {
			return
		}
		if err != nil {
			i.Logger.Warnf("[%s] Stream read error: %v", network, err)
			return
		}

		pkt := buf[:n]
		if len(pkt) < 20 || pkt[0]>>4 != 4 {
			i.Logger.Warnf("[%s] Invalid IPv4 packet", network)
			continue
		}

		_, err = dev.Write(pkt)
		if err != nil {
			i.Logger.Errorf("[%s] Failed to write to TUN: %v", network, err)
			return
		}

		dst := net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])
		i.Logger.Debugf("[%s] Injected packet to %s (%d bytes)", network, dst, n)
	}
}
