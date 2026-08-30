package quic

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
