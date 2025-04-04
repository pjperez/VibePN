package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"

	"vibepn/control"
	"vibepn/forward"
	"vibepn/log"
	"vibepn/netgraph"
	"vibepn/peer"

	quic "github.com/quic-go/quic-go"
)

func Listen(addr string, tlsConf *tls.Config) (*quic.Listener, error) {
	logger := log.New("quic/listener")
	ln, err := quic.ListenAddr(addr, tlsConf, &quic.Config{
		EnableDatagrams: true,
	})
	if err != nil {
		return nil, err
	}
	logger.Infof("Listening for QUIC connections on %s", addr)
	return ln, nil
}

func AcceptLoop(
	ln quic.Listener,
	tracker *peer.LivenessTracker,
	routes *netgraph.RouteTable,
	registry *peer.Registry,
	inbound *forward.Inbound,
) {
	logger := log.New("quic/accept")

	for {
		sess, err := ln.Accept(context.Background())
		if err != nil {
			logger.Errorf("Accept error: %v", err)
			continue
		}

		logger.Infof("Accepted connection from %s", sess.RemoteAddr())

		go func(conn quic.Connection) {
			peerID, err := expectHello(conn)
			if err != nil {
				logger.Warnf("Invalid hello from %s: %v", conn.RemoteAddr(), err)
				_ = conn.CloseWithError(0, "invalid hello")
				return
			}

			registry.Add(peerID, conn)
			tracker.MarkAlive(peerID)

			// 🔥 After handshake, always enter session loop
			handleSession(conn, inbound)
		}(sess)
	}
}

func expectHello(conn quic.Connection) (string, error) {
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		return "", err
	}

	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	if err != nil {
		return "", fmt.Errorf("failed to read stream: %w", err)
	}

	rawData := buf[:n]
	logger := log.New("quic/expecthello")
	logger.Infof("[debug/expecthello] Raw data received (%d bytes): %s", len(rawData), string(rawData))

	dec := json.NewDecoder(NewReplayableStream(rawData))

	var header control.Header
	if err := dec.Decode(&header); err != nil {
		return "", fmt.Errorf("failed to decode header: %w", err)
	}
	if header.Type != "hello" {
		return "", fmt.Errorf("expected hello message, got %s", header.Type)
	}

	var msg control.HelloMessage
	if err := dec.Decode(&msg); err != nil {
		return "", fmt.Errorf("failed to decode hello message: %w", err)
	}

	// 🔥 After receiving hello, reply with our own hello
	replyHello(conn, msg.NodeID)

	return msg.NodeID, nil
}

func replyHello(conn quic.Connection, peerID string) {
	logger := log.New("quic/accept")
	logger.Infof("Replying to peer %s with Hello", peerID)

	stream, err := conn.OpenStream()
	if err != nil {
		logger.Warnf("Failed to open stream for Hello reply: %v", err)
		return
	}
	defer stream.Close()

	header := control.Header{Type: "hello"}
	body := control.HelloMessage{
		NodeID: peerID, // <-- we could send our fingerprint, depending on design
		Networks: []struct {
			Name    string `json:"name"`
			Address string `json:"address"`
		}{},
		Features: map[string]bool{
			"metrics": true,
		},
	}

	headerBytes, _ := json.Marshal(header)
	bodyBytes, _ := json.Marshal(body)

	logger.Infof("[debug/sendhello] Header JSON: %s", string(headerBytes))
	logger.Infof("[debug/sendhello] Body JSON:   %s", string(bodyBytes))

	_, err = fmt.Fprintf(stream, "%s\n%s\n", string(headerBytes), string(bodyBytes))
	if err != nil {
		logger.Warnf("Failed to send Hello reply: %v", err)
		return
	}

	logger.Infof("Sent hello to peer: %s", peerID)
}

func NewReplayableStream(data []byte) *bytes.Reader {
	return bytes.NewReader(data)
}

func handleSession(sess quic.Connection, inbound *forward.Inbound) {
	logger := log.New("quic/session")

	for {
		stream, err := sess.AcceptStream(context.Background())
		if err != nil {
			logger.Warnf("Stream error from %s: %v", sess.RemoteAddr(), err)
			return
		}

		debugStream(stream, "incoming")

		go debugAndHandleStream(stream, logger, inbound)
	}
}

func debugStream(stream quic.Stream, label string) {
	go func() {
		buf := make([]byte, 1024)
		n, err := stream.Read(buf)
		if err != nil && err != io.EOF {
			log.New("quic/debug").Warnf("[%s] Failed to read debug stream: %v", label, err)
			return
		}
		peek := buf[:n]
		log.New("quic/debug").Debugf("[%s] First %d bytes: %x", label, n, peek)
	}()
}

func debugAndHandleStream(stream quic.Stream, logger *log.Logger, inbound *forward.Inbound) {
	dec := json.NewDecoder(stream)
	var h control.Header
	if err := dec.Decode(&h); err != nil {
		logger.Warnf("Failed to decode stream header: %v", err)
		_ = stream.Close()
		return
	}

	handleDecodedStream(stream, h, logger, inbound)
}

func handleDecodedStream(stream quic.Stream, h control.Header, logger *log.Logger, inbound *forward.Inbound) {
	switch h.Type {
	case "hello":
		logger.Infof("Unexpected duplicate hello")

	case "route-announce":
		var msg map[string]interface{}
		if err := json.NewDecoder(stream).Decode(&msg); err != nil {
			logger.Warnf("Failed to decode route-announce: %v", err)
			_ = stream.Close()
			return
		}
		logger.Infof("Received route announcement for network %v", msg["network"])

	case "route-withdraw":
		var msg map[string]interface{}
		if err := json.NewDecoder(stream).Decode(&msg); err != nil {
			logger.Warnf("Failed to decode route-withdraw: %v", err)
			_ = stream.Close()
			return
		}
		logger.Infof("Received route withdrawal for network %v", msg["network"])

	case "keepalive":
		var msg control.KeepaliveMessage
		if err := json.NewDecoder(stream).Decode(&msg); err != nil {
			logger.Warnf("Failed to decode keepalive: %v", err)
			_ = stream.Close()
			return
		}
		logger.Debugf("Received keepalive: %d", msg.Timestamp)

	case "goodbye":
		logger.Infof("Received goodbye")

	case "metrics":
		logger.Infof("Received metrics stream (not yet handled)")

	case "raw":
		var rawHeader struct {
			Network string `json:"network"`
		}
		if err := json.NewDecoder(stream).Decode(&rawHeader); err != nil {
			logger.Warnf("Failed to decode raw stream metadata: %v", err)
			_ = stream.Close()
			return
		}

		logger.Infof("Raw stream for network %s", rawHeader.Network)
		if inbound != nil {
			go inbound.HandleRawStream(stream, rawHeader.Network)
		} else {
			logger.Warnf("Inbound handler not configured, discarding raw stream")
			stream.CancelRead(0)
		}

	default:
		logger.Warnf("Unknown stream type: %s", h.Type)
		stream.CancelRead(0)
	}
}
