package peer

import (
	"context"
	"io"

	"vibepn/log"

	"github.com/quic-go/quic-go"
)

// AcceptStreams accepts and dispatches incoming streams on a connection,
// classifying each as control or raw by peeking at its first byte. It runs
// until the connection closes. Both the accept side (quic.handleSession) and
// the dial side (ConnectionManager.runSession) must call this so that
// whichever connection wins the tie-break can still serve streams.
func AcceptStreams(conn quic.Connection, peerID string, handleRaw func(io.Reader)) {
	logger := log.New("peer/session")

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			logger.Warnf("Stream accept error from %s: %v", peerID, err)
			return
		}

		bs := newBufferedStream(stream)
		if isControlStream(bs) {
			logger.Debugf("Stream %d from %s classified as control", stream.StreamID(), peerID)
			go HandleControlStream(conn, bs, peerID)
		} else {
			logger.Debugf("Stream %d from %s classified as raw", stream.StreamID(), peerID)
			go handleRaw(bs)
		}
	}
}
