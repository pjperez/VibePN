package peer

import (
	"bufio"
	"io"
)

// bufferedStream pairs a buffered reader (used for stream classification)
// with the original stream for writes.
type bufferedStream struct {
	*bufio.Reader
	io.Writer
}

// newBufferedStream wraps a stream with a buffered reader for peeking.
func newBufferedStream(stream io.ReadWriter) *bufferedStream {
	return &bufferedStream{
		Reader: bufio.NewReader(stream),
		Writer: stream,
	}
}

// isControlStream peeks at the first byte of a stream without consuming it.
//
// Control messages are framed as 2-byte big-endian length + payload, so every
// control message shorter than 256 bytes starts with 0x00 (the length high
// byte). Raw packet frames start with a 1-byte network-name length (1-255).
// A first byte of 0x00 therefore identifies a control stream.
func isControlStream(bs *bufferedStream) bool {
	b, err := bs.Peek(1)
	if err != nil {
		return false
	}
	return b[0] == 0x00
}
