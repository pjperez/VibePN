package forward

import (
	"encoding/binary"
	"io"

	"vibepn/log"
	"vibepn/metrics"
	"vibepn/tun"
)

// Inbound decodes framed packets from raw QUIC streams and writes them into
// the TUN device for the announced network.
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

// HandleRawStream reads frames until the stream closes.
func (i *Inbound) HandleRawStream(stream io.Reader) {
	for {
		network, pkt, err := readFrame(stream)
		if err != nil {
			if err == io.EOF {
				i.logger.Infof("Raw stream closed")
			} else {
				i.logger.Warnf("Raw stream error: %v", err)
				metrics.PacketsDropped.WithLabelValues("frame_error").Inc()
			}
			return
		}

		dev, ok := i.devices[network]
		if !ok || dev == nil {
			metrics.PacketsDropped.WithLabelValues("unknown_network").Inc()
			i.logger.Warnf("No local interface for network %s", network)
			continue
		}

		if _, err := dev.Write(pkt); err != nil {
			metrics.PacketsDropped.WithLabelValues("tun_write").Inc()
			i.logger.Warnf("Failed to write packet to TUN for network %s: %v", network, err)
			return
		}
		metrics.PacketsReceived.WithLabelValues(network).Inc()
	}
}

// readFrame decodes one (network, packet) frame from r.
func readFrame(r io.Reader) (string, []byte, error) {
	var netLenBuf [1]byte
	if _, err := io.ReadFull(r, netLenBuf[:]); err != nil {
		return "", nil, err
	}
	networkLen := int(netLenBuf[0])
	if networkLen == 0 {
		return "", nil, errInvalidNetworkName
	}

	networkBuf := make([]byte, networkLen)
	if _, err := io.ReadFull(r, networkBuf); err != nil {
		return "", nil, err
	}
	network := string(networkBuf)

	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return "", nil, err
	}
	packetLen := binary.BigEndian.Uint16(lenBuf[:])
	if packetLen == 0 {
		return "", nil, errInvalidPacketLen
	}

	packet := make([]byte, packetLen)
	if _, err := io.ReadFull(r, packet); err != nil {
		return "", nil, err
	}
	return network, packet, nil
}
