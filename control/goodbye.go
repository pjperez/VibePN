package control

import (
	"encoding/json"
	"vibepn/log"

	"github.com/quic-go/quic-go"
)

func SendGoodbye(conn quic.Connection, logger *log.Logger) {
	stream, err := conn.OpenStream()
	if err != nil {
		logger.Warnf("Failed to open goodbye stream: %v", err)
		return
	}
	defer stream.Close()

	header := Header{Type: "goodbye"}
	if err := json.NewEncoder(stream).Encode(header); err != nil {
		logger.Warnf("Failed to send goodbye: %v", err)
	} else {
		logger.Infof("Sent goodbye to %s", conn.RemoteAddr())
	}
}
