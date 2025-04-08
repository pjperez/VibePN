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

	for {
		stream, err := sess.AcceptStream(context.Background())
		if err != nil {
			logger.Warnf("Stream error from %s: %v", sess.RemoteAddr(), err)
			return
		}

		go handleRawStream(stream, inbound)
	}
}

func handleRawStream(stream quic.Stream, inbound *forward.Inbound) {
	logger := log.New("quic/raw")

	logger.Debugf("Raw stream accepted (id=%d)", stream.StreamID())

	if inbound != nil {
		inbound.HandleRawStream(stream, "") // no network name needed anymore
	} else {
		logger.Warnf("Inbound handler not configured, dropping stream")
		stream.CancelRead(0)
	}
}
