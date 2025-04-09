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

	// Accept the first control stream
	controlStream, err := sess.AcceptStream(context.Background())
	if err != nil {
		logger.Warnf("Failed to accept control stream: %v", err)
		return
	}
	logger.Infof("Accepted control stream (id=%d)", controlStream.StreamID())

	// 🧠 Hand the control stream to peer
	go peer.HandleControlStream(sess, controlStream)

	// Keep accepting further raw streams
	for {
		stream, err := sess.AcceptStream(context.Background())
		if err != nil {
			logger.Warnf("Stream accept error: %v", err)
			return
		}

		go handleRawStream(stream, inbound)
	}
}

func handleRawStream(stream quic.Stream, inbound *forward.Inbound) {
	logger := log.New("quic/raw")
	logger.Debugf("Raw stream accepted (id=%d)", stream.StreamID())

	if inbound != nil {
		go inbound.HandleRawStream(stream, "")
	} else {
		logger.Warnf("Inbound handler not configured, dropping stream")
		stream.CancelRead(0)
	}
}
