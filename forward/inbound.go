package forward

import (
	"encoding/binary"
	"io"
	"vibepn/log"
	"vibepn/tun"

	"github.com/quic-go/quic-go"
)

type Inbound struct {
	devices map[string]*tun.Device
	logger  *log.Logger
}

func NewInbound(devices map[string]*tun.Device) *Inbound {
	return &Inbound{
		devices: devices,
		logger:  log.New("forward/inbound"),
	}
}

func (i *Inbound) HandleRawStream(stream quic.Stream) {
	i.logger.Infof("Handling raw stream %d", stream.StreamID())

	for {
		netLenBuf := make([]byte, 1)
		_, err := io.ReadFull(stream, netLenBuf)
		if err != nil {
			if err == io.EOF {
				i.logger.Infof("Raw stream closed (id=%d)", stream.StreamID())
			} else {
				i.logger.Warnf("Failed to read packet length: %v", err)
			}
			return
		}

		networkLen := int(netLenBuf[0])
		if networkLen == 0 {
			i.logger.Warnf("Invalid network name length: %d", networkLen)
			return
		}

		networkBuf := make([]byte, networkLen)
		_, err = io.ReadFull(stream, networkBuf)
		if err != nil {
			i.logger.Warnf("Failed to read network name: %v", err)
			return
		}
		network := string(networkBuf)

		// ✍️ Read 2 bytes for packet length
		lenBuf := make([]byte, 2)
		_, err = io.ReadFull(stream, lenBuf)
		if err != nil {
			i.logger.Warnf("Failed to read packet length: %v", err)
			return
		}

		packetLen := binary.BigEndian.Uint16(lenBuf)

		if packetLen == 0 {
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

		dev, ok := i.devices[network]
		if !ok || dev == nil {
			i.logger.Warnf("No local interface for network %s", network)
			continue
		}

		_, err = dev.Write(packet)
		if err != nil {
			i.logger.Warnf("Failed to write packet to TUN for network %s: %v", network, err)
			return
		}
	}
}
