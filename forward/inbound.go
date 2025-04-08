package forward

import (
	"io"
	"vibepn/log"
	"vibepn/tun"

	"github.com/quic-go/quic-go"
)

type Inbound struct {
	dev    tun.Device
	logger *log.Logger
}

// NewInbound creates a new Inbound handler.
func NewInbound(dev tun.Device) *Inbound {
	return &Inbound{
		dev:    dev,
		logger: log.New("forward/inbound"),
	}
}

// HandleRawStream pumps raw packets from the QUIC stream into the TUN device.
func (i *Inbound) HandleRawStream(stream quic.Stream, _ string) {
	i.logger.Infof("Handling raw stream %d", stream.StreamID())

	buf := make([]byte, 65535) // IP MTU max size

	for {
		n, err := stream.Read(buf)
		if err != nil {
			if err == io.EOF {
				i.logger.Infof("Raw stream closed (id=%d)", stream.StreamID())
			} else {
				i.logger.Warnf("Raw stream read error: %v", err)
			}
			return
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])

		_, err = i.dev.Write(packet)
		if err != nil {
			i.logger.Warnf("Failed to write packet to TUN: %v", err)
			return
		}
	}
}
