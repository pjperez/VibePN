package control

import (
	"encoding/json"

	"vibepn/log"

	quic "github.com/quic-go/quic-go"
)

type Header struct {
	Type string `json:"type"`
}

type HelloMessage struct {
	NodeID   string `json:"node_id"`
	Networks []struct {
		Name    string `json:"name"`
		Address string `json:"address"`
	} `json:"networks"`
	Features map[string]bool `json:"features"`
}

func SendHello(conn quic.Connection, msg HelloMessage, logger *log.Logger) error {
	stream, err := conn.OpenStream()
	if err != nil {
		return err
	}

	header := Header{Type: "hello"}
	enc := json.NewEncoder(stream)

	if err := enc.Encode(header); err != nil {
		logger.Warnf("Failed to send hello header: %v", err)
		stream.Close()
		return err
	}

	if err := enc.Encode(msg); err != nil {
		logger.Warnf("Failed to send hello body: %v", err)
		stream.Close()
		return err
	}

	logger.Infof("Sent hello to peer: %s", msg.NodeID)
	return nil
}
