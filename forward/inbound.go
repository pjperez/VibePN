package forward

import (
	"encoding/binary"
	"io"
	"vibepn/log"
	"vibepn/tun"

	"github.com/quic-go/quic-go"
)

type Inbound struct {
	dev    tun.Device
	logger *log.Logger
}

func NewInbound(dev tun.Device) *Inbound {
	return &Inbound{
		dev:    dev,
		logger: log.New("forward/inbound"),
	}
}

func (i *Inbound) HandleRawStream(stream quic.Stream, _ string) {
	i.logger.Infof("Handling raw stream %d", stream.StreamID())

	for {
		// ✍️ Read 2 bytes for packet length
		lenBuf := make([]byte, 2)
		_, err := io.ReadFull(stream, lenBuf)
		if err != nil {
			if err == io.EOF {
				i.logger.Infof("Raw stream closed (id=%d)", stream.StreamID())
			} else {
				i.logger.Warnf("Failed to read packet length: %v", err)
			}
			return
		}

		packetLen := binary.BigEndian.Uint16(lenBuf)

		if packetLen == 0 || packetLen > 65535 {
			i.logger.Warnf("Invalid packet length: %d", packetLen)
			return
		}

		// ✍️ Read the actual packet
		packet := make([]byte, packetLen)
		_, err = io.ReadFull(stream, packet)
		if err != nil {
			i.logger.Warnf("Failed to read full packet: %v", err)
			return
		}

		_, err = i.dev.Write(packet)
		if err != nil {
			i.logger.Warnf("Failed to write packet to TUN: %v", err)
			return
		}
	}
}
