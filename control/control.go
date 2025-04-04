package control

import (
	"encoding/json"
	"fmt"

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

	// 🔥 DEBUG: Dump what we're about to send
	headerBytes, _ := json.Marshal(header)
	msgBytes, _ := json.Marshal(msg)

	logger.Infof("[debug/sendhello] Header JSON: %s", string(headerBytes))
	logger.Infof("[debug/sendhello] Body JSON:   %s", string(msgBytes))

	// 🔥 DEBUG: Write manually and flush
	if _, err := fmt.Fprintf(stream, "%s\n%s\n", string(headerBytes), string(msgBytes)); err != nil {
		logger.Warnf("Failed to send hello: %v", err)
		stream.Close()
		return err
	}

	logger.Infof("Sent hello to peer: %s", msg.NodeID)
	return nil
}
