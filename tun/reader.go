package tun

import (
	"io"
	"vibepn/log"
)

// PacketReader reads raw packets from the TUN device and pushes them into a channel.
func PacketReader(dev Device, outbound chan<- []byte) {
	logger := log.New("tun/reader")

	buf := make([]byte, 65535) // max IP packet size

	for {
		n, err := dev.Read(buf)
		if err != nil {
			if err == io.EOF {
				logger.Warnf("TUN device closed")
				return
			}
			logger.Warnf("TUN read error: %v", err)
			continue
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])

		outbound <- packet
	}
}
