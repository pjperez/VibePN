package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"

	"vibepn/control"
	"vibepn/forward"
	"vibepn/log"
	"vibepn/netgraph"
	"vibepn/peer"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
)

// Minimal custom tracer so we can see handshake events in modern quic-go
func newDebugTracer(logger *log.Logger) logging.Tracer {
	return &debugTracer{logger: logger}
}

type debugTracer struct {
	logger *log.Logger
}

// quic-go calls this for each new connection
func (t *debugTracer) TracerForConnection(p logging.Perspective, odcid logging.ConnectionID) logging.ConnectionTracer {
	t.logger.Infof("[quic/tracer] New connection, perspective=%v, odcid=%v", p, odcid)
	return &debugConnTracer{logger: t.logger}
}

type debugConnTracer struct {
	logger *log.Logger
}

// The following are partial methods from logging.ConnectionTracer
// We show handshake phases. You can implement more if needed.

// Called once the QUIC handshake starts
func (c *debugConnTracer) StartedConnection(local, remote net.Addr, version logging.VersionNumber, srcConnID, destConnID logging.ConnectionID) {
	c.logger.Infof("[quic/tracer] StartedConnection local=%v remote=%v version=%v srcConnID=%v destConnID=%v",
		local, remote, version, srcConnID, destConnID)
}

func (c *debugConnTracer) NegotiatedVersion(chosen logging.VersionNumber, client logging.VersionNumber, server logging.VersionNumber) {
	c.logger.Infof("[quic/tracer] NegotiatedVersion chosen=%v client=%v server=%v", chosen, client, server)
}

func (c *debugConnTracer) TLSHandshakeStart(_ logging.MessageDirection, _ logging.MessageType) {
	c.logger.Infof("[quic/tracer] TLSHandshakeStart")
}

func (c *debugConnTracer) TLSHandshakeDone(ok bool, err error) {
	c.logger.Infof("[quic/tracer] TLSHandshakeDone ok=%v err=%v", ok, err)
}

func (c *debugConnTracer) ClosedConnection(local logging.CloseReason) {
	c.logger.Infof("[quic/tracer] ClosedConnection local=%v", local)
}

// We omit many other methods for brevity. If you need more, implement them similarly.

func Listen(addr string, tlsConf *tls.Config) (*quic.Listener, error) {
	logger := log.New("quic/listener")

	// Inserted: create a quic.Config with our custom debug tracer
	qconf := &quic.Config{
		Tracer: newDebugTracer(logger),
	}

	ln, err := quic.ListenAddr(addr, tlsConf, qconf)
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
			handleSession(conn, inbound)
		}(sess)
	}
}

func expectHello(conn quic.Connection) (string, error) {
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		return "", err
	}

	// 🔥 DEBUG: Dump raw bytes before decoding
	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	if err != nil {
		return "", fmt.Errorf("failed to read stream: %w", err)
	}

	rawData := buf[:n]
	logger := log.New("quic/expecthello")
	logger.Infof("[debug/expecthello] Raw data received (%d bytes): %s", len(rawData), string(rawData))

	// Re-create a new decoder from rawData
	dec := json.NewDecoder(NewReplayableStream(rawData))

	// Decode header
	var header control.Header
	if err := dec.Decode(&header); err != nil {
		return "", fmt.Errorf("failed to decode header: %w", err)
	}
	if header.Type != "hello" {
		return "", fmt.Errorf("expected hello message, got %s", header.Type)
	}

	// Decode body
	var msg control.HelloMessage
	if err := dec.Decode(&msg); err != nil {
		return "", fmt.Errorf("failed to decode hello message: %w", err)
	}

	return msg.NodeID, nil
}

// NewReplayableStream returns a Reader from raw bytes
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
		// Note: This reads once; normal decoding continues after
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
