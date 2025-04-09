package quic

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"

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

	controlStream, err := sess.AcceptStream(context.Background())
	if err != nil {
		logger.Warnf("Failed to accept control stream: %v", err)
		return
	}
	logger.Infof("Accepted control stream (id=%d)", controlStream.StreamID())

	go handleControlStream(sess, controlStream)

	for {
		stream, err := sess.AcceptStream(context.Background())
		if err != nil {
			logger.Warnf("Stream accept error: %v", err)
			return
		}

		go handleRawStream(stream, inbound)
	}
}

func handleControlStream(sess quic.Connection, stream quic.Stream) {
	logger := log.New("quic/control")

	for {
		lenBuf := make([]byte, 2)
		_, err := io.ReadFull(stream, lenBuf)
		if err != nil {
			logger.Warnf("Control stream closed or error: %v", err)
			sess.CloseWithError(0, "control stream closed")
			return
		}
		length := binary.BigEndian.Uint16(lenBuf)

		if length == 0 || length > 4096 {
			logger.Warnf("Invalid control message length: %d", length)
			sess.CloseWithError(0, "invalid control message length")
			return
		}

		msg := make([]byte, length)
		_, err = io.ReadFull(stream, msg)
		if err != nil {
			logger.Warnf("Failed to read control message: %v", err)
			sess.CloseWithError(0, "control read error")
			return
		}

		logger.Infof("Received control message: %x", msg)
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
