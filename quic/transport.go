package quic

import (
	"context"
	"crypto/tls"
	"time"

	"vibepn/crypto"
	"vibepn/forward"
	"vibepn/log"
	"vibepn/peer"
	"vibepn/protocol"

	"github.com/quic-go/quic-go"
)

// quicConfig returns the shared QUIC configuration.
func quicConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams:       false,
		MaxIdleTimeout:        90 * time.Second,
		KeepAlivePeriod:       15 * time.Second,
		MaxIncomingStreams:    1024,
		MaxIncomingUniStreams: -1,
	}
}

// Listen starts a QUIC listener on addr.
func Listen(addr string, tlsConf *tls.Config) (*quic.Listener, error) {
	logger := log.New("quic/listener")
	ln, err := quic.ListenAddr(addr, tlsConf, quicConfig())
	if err != nil {
		return nil, err
	}
	logger.Infof("Listening for QUIC connections on %s", addr)
	return ln, nil
}

// AcceptLoop accepts connections, registers the connection, and starts a
// session handler per connection. Peer certificates are verified by the TLS
// layer (TOFU); the peer's configured name (resolved from the fingerprint) is
// used as the registry key so route policy and liveness align with config.
func AcceptLoop(
	ln quic.Listener,
	registry *peer.Registry,
	inbound *forward.Inbound,
	tofu *crypto.TOFUStore,
) {
	logger := log.New("quic/accept")

	for {
		sess, err := ln.Accept(context.Background())
		if err != nil {
			logger.Errorf("Accept error: %v", err)
			return
		}

		connState := sess.ConnectionState()
		if len(connState.TLS.PeerCertificates) == 0 {
			logger.Warnf("No peer certificate presented by %s", sess.RemoteAddr())
			_ = sess.CloseWithError(0, "missing peer cert")
			continue
		}
		peerFP := crypto.Fingerprint(connState.TLS.PeerCertificates[0].Raw)

		// Resolve the fingerprint to a configured peer name so route policy
		// and liveness tracking use the same key as the dialer.
		peerID := peerFP
		if name, ok := tofu.NameForFingerprint(peerFP); ok {
			peerID = name
		}
		logger.Infof("Accepted connection from %s (fingerprint %s, id %s)", sess.RemoteAddr(), peerFP, peerID)

		registry.Add(peerID, sess)
		go handleSession(sess, inbound, peerID)
	}
}

// handleSession drives one accepted connection: it accepts the control stream,
// performs the hello exchange, announces local routes, and then classifies
// every further stream as control or raw by peeking at its first byte.
func handleSession(sess quic.Connection, inbound *forward.Inbound, peerID string) {
	logger := log.New("quic/session")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	controlStream, err := sess.AcceptStream(ctx)
	cancel()
	if err != nil {
		logger.Warnf("Failed to accept control stream from %s: %v", peerID, err)
		return
	}
	logger.Infof("Accepted control stream (id=%d) from %s", controlStream.StreamID(), peerID)

	// Send our hello.
	if err := protocol.WriteMessage(controlStream, protocol.Hello{Nonce: uint64(time.Now().UnixNano())}); err != nil {
		logger.Errorf("Failed to send Hello to %s: %v", peerID, err)
		return
	}

	// Announce exported local routes.
	announceRoutes(controlStream)

	// Start the control reader and keepalive writer.
	stopKeepalive := peer.StartKeepaliveLoop(controlStream)
	defer stopKeepalive()
	go peer.HandleControlStream(sess, controlStream, peerID)

	// Accept further streams; classify them by peeking at the first byte.
	peer.AcceptStreams(sess, peerID, inbound.HandleRawStream)
}

// announceRoutes sends route announcements for exported networks.
func announceRoutes(stream quic.Stream) {
	logger := log.New("quic/session")
	for netName, netCfg := range netConfigSnapshot() {
		if !netCfg.Export {
			continue
		}
		if err := protocol.WriteMessage(stream, protocol.RouteAnnounce{
			Network:  netName,
			Prefixes: []string{netCfg.Prefix},
			Metric:   1,
		}); err != nil {
			logger.Warnf("Failed to announce route for network %s: %v", netName, err)
		}
	}
}
