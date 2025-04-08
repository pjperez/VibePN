package quic

import (
	"context"
	"crypto/tls"

	"vibepn/forward"
	"vibepn/log"
	"vibepn/netgraph"
	"vibepn/peer"

	"github.com/quic-go/quic-go"
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

		go handleSession(sess, inbound)
	}
}

func handleSession(sess quic.Connection, inbound *forward.Inbound) {
	logger := log.New("quic/session")

	// 📢 1. First stream must be CONTROL stream
	controlStream, err := sess.AcceptStream(context.Background())
	if err != nil {
		logger.Warnf("Failed to accept control stream from %s: %v", sess.RemoteAddr(), err)
		return
	}
	logger.Infof("Accepted control stream (id=%d)", controlStream.StreamID())

	go handleControlStream(sess, controlStream)

	// 📢 2. Next streams are RAW streams (IP traffic)
	for {
		stream, err := sess.AcceptStream(context.Background())
		if err != nil {
			logger.Warnf("Stream error from %s: %v", sess.RemoteAddr(), err)
			return
		}

		go handleRawStream(stream, inbound)
	}
}

func handleControlStream(sess quic.Connection, stream quic.Stream) {
	logger := log.New("quic/control")

	buf := make([]byte, 4096) // reasonable control buffer

	for {
		n, err := stream.Read(buf)
		if err != nil {
			if err.Error() == "EOF" {
				logger.Warnf("Control stream closed by peer %s", sess.RemoteAddr())
			} else {
				logger.Warnf("Control stream error from peer %s: %v", sess.RemoteAddr(), err)
			}

			// 🚨 Control stream died → kill session
			sess.CloseWithError(0, "control stream closed")
			return
		}

		// You can optionally parse control messages here later
		logger.Debugf("Received control data (%d bytes): %s", n, string(buf[:n]))
	}
}

func handleRawStream(stream quic.Stream, inbound *forward.Inbound) {
	logger := log.New("quic/raw")

	logger.Debugf("Raw stream accepted (id=%d)", stream.StreamID())

	if inbound != nil {
		go inbound.HandleRawStream(stream, "") // 🚀 ✅ No network name needed
	} else {
		logger.Warnf("Inbound handler not configured, dropping stream")
		stream.CancelRead(0)
	}
}
