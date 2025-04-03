package quic

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"

	"vibepn/control"
	"vibepn/forward"
	"vibepn/log"
	"vibepn/netgraph"
	"vibepn/peer"

	quic "github.com/quic-go/quic-go"
)

func Listen(addr string, tlsConf *tls.Config) (*quic.Listener, error) {
	logger := log.New("quic/listener")
	ln, err := quic.ListenAddr(addr, tlsConf, nil)
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

			logger.Infof("Received valid hello from %s → NodeID: %s", conn.RemoteAddr(), peerID)

			registry.Add(peerID, conn)
			tracker.MarkAlive(peerID)
			handleSession(conn, inbound)
		}(sess)
	}
}

func expectHello(conn quic.Connection) (string, error) {
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		return "", err
	}

	dec := json.NewDecoder(stream)
	var header control.Header
	if err := dec.Decode(&header); err != nil {
		return "", err
	}
	if header.Type != "hello" {
		return "", errors.New("expected hello message")
	}

	var msg control.HelloMessage
	if err := dec.Decode(&msg); err != nil {
		return "", err
	}

	return msg.NodeID, nil
}

func handleSession(sess quic.Connection, inbound *forward.Inbound) {
	logger := log.New("quic/session")

	for {
		stream, err := sess.AcceptStream(context.Background())
		if err != nil {
			logger.Warnf("Stream error from %s: %v", sess.RemoteAddr(), err)
			return
		}

		logger.Infof("Accepted new stream from %s", sess.RemoteAddr())
		go handleStream(stream, logger, inbound)
	}
}

func handleStream(stream quic.Stream, logger *log.Logger, inbound *forward.Inbound) {
	var h control.Header
	dec := json.NewDecoder(stream)
	if err := dec.Decode(&h); err != nil {
		logger.Warnf("Failed to decode stream header: %v", err)
		_ = stream.Close()
		return
	}

	switch h.Type {
	case "hello":
		logger.Infof("Unexpected duplicate hello")

	case "route-announce":
		var msg map[string]interface{}
		if err := dec.Decode(&msg); err != nil {
			logger.Warnf("Failed to decode route-announce: %v", err)
			_ = stream.Close()
			return
		}
		logger.Infof("Received route announcement for network %v", msg["network"])

	case "route-withdraw":
		var msg map[string]interface{}
		if err := dec.Decode(&msg); err != nil {
			logger.Warnf("Failed to decode route-withdraw: %v", err)
			_ = stream.Close()
			return
		}
		logger.Infof("Received route withdrawal for network %v", msg["network"])

	case "keepalive":
		var msg control.KeepaliveMessage
		if err := dec.Decode(&msg); err != nil {
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
		if err := dec.Decode(&rawHeader); err != nil {
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
