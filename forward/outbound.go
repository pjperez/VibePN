package forward

import (
	"context"
	"encoding/binary"
	"vibepn/log"
	"vibepn/tun"

	"github.com/quic-go/quic-go"
)

type Outbound struct {
	dev    tun.Device
	logger *log.Logger
}

func NewOutbound(dev tun.Device) *Outbound {
	return &Outbound{
		dev:    dev,
		logger: log.New("forward/outbound"),
	}
}

func (o *Outbound) SendPackets(ctx context.Context, sess quic.Connection) {
	buf := make([]byte, 65535)

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

			packet := buf[:n]

			// ✍️ Write packet length first
			lengthBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(lengthBuf, uint16(len(packet)))

			_, err = stream.Write(lengthBuf)
			if err != nil {
				o.logger.Warnf("Stream write failed (length): %v", err)
				return
			}

			// ✍️ Write packet data
			_, err = stream.Write(packet)
			if err != nil {
				o.logger.Warnf("Stream write failed (data): %v", err)
				return
			}
		}
	}
}
