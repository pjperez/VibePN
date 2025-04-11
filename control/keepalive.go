package control

import (
	"time"

	"vibepn/log"

	"github.com/quic-go/quic-go"
)

var (
	keepaliveInterval = 10 * time.Second // how often to send keepalive
)

func StartKeepaliveLoop(stream quic.Stream) {
	logger := log.New("control/keepalive")

	go func() {
		ticker := time.NewTicker(keepaliveInterval)
		defer ticker.Stop()

		for {
			<-ticker.C

			err := SendKeepalive(stream)
			if err != nil {
				logger.Warnf("Failed to send keepalive: %v", err)
				return // stop loop if broken
			}
			logger.Debugf("Sent Keepalive")
		}
	}()
}
