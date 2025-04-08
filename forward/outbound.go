package forward

import (
	"context"
	"vibepn/log"
	"vibepn/tun"

	"github.com/quic-go/quic-go"
)

type Outbound struct {
	dev    tun.Device
	logger *log.Logger
}

// NewOutbound creates a new Outbound handler.
func NewOutbound(dev tun.Device) *Outbound {
	return &Outbound{
		dev:    dev,
		logger: log.New("forward/outbound"),
	}
}

// SendPackets reads packets from TUN and sends them to the peer over QUIC.
func (o *Outbound) SendPackets(ctx context.Context, sess quic.Connection) {
	buf := make([]byte, 65535) // IP MTU max size

	stream, err := sess.OpenStream()
	if err != nil {
		o.logger.Errorf("Failed to open initial QUIC stream: %v", err)
		return
	}
	defer stream.Close()

	for {
		select {
		case <-ctx.Done():
			o.logger.Infof("Stopping outbound packet sender")
			return

		default:
			n, err := o.dev.Read(buf)
			if err != nil {
				o.logger.Warnf("Failed to read from TUN: %v", err)
				continue
			}

			packet := make([]byte, n)
			copy(packet, buf[:n])

			_, err = stream.Write(packet)
			if err != nil {
				o.logger.Warnf("Stream write failed: %v, trying to open new stream", err)

				// ❗ Close old broken stream
				stream.Close()

				// ❗ Try to open a new stream
				stream, err = sess.OpenStream()
				if err != nil {
					o.logger.Errorf("Failed to open new QUIC stream: %v", err)
					return
				}

				// ❗ Retry sending the packet
				_, err = stream.Write(packet)
				if err != nil {
					o.logger.Errorf("Failed to send packet even after stream reopen: %v", err)
					return
				}
			}
		}
	}
}
