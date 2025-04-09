package control

import (
	"time"

	"vibepn/log"

	"github.com/quic-go/quic-go"
)

var (
	keepaliveInterval = 10 * time.Second // how often to send keepalive
)

func StartKeepaliveLoop(conn quic.Connection) {
	logger := log.New("control/keepalive")

	go func() {
		for {
			if conn.Context().Err() != nil {
				logger.Infof("Connection closed, stopping keepalive")
				return
			}

			stream, err := conn.OpenStream()
			if err != nil {
				logger.Warnf("Failed to open keepalive stream: %v", err)
				time.Sleep(keepaliveInterval)
				continue
			}

			err = SendKeepalive(stream)
			if err != nil {
				logger.Warnf("Failed to send keepalive: %v", err)
				stream.CancelWrite(0)
			}

			_ = stream.Close()

			time.Sleep(keepaliveInterval)
		}
	}()
}
