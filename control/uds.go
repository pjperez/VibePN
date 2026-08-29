// Package control: local Unix-domain-socket command server.
package control

import (
	"encoding/json"
	"net"
	"os"
	"time"

	"vibepn/log"
)

const udsTimeout = 5 * time.Second

// Server serves vpnctl commands over a Unix domain socket.
type Server struct {
	path   string
	handle func(cmd string, logger *log.Logger) CommandResponse
	logger *log.Logger
}

// CommandRequest is the JSON request sent by vpnctl.
type CommandRequest struct {
	Cmd string `json:"cmd"`
}

// CommandResponse is the JSON response returned to vpnctl.
type CommandResponse struct {
	Status string      `json:"status"`
	Output interface{} `json:"output,omitempty"`
	Error  string      `json:"error,omitempty"`
}

// NewServer creates a command server bound to path.
func NewServer(path string, handle func(cmd string, logger *log.Logger) CommandResponse) *Server {
	return &Server{
		path:   path,
		handle: handle,
		logger: log.New("control/uds"),
	}
}

// Start begins accepting connections in the background. It returns an error
// channel that receives a fatal listen error, if any.
func (s *Server) Start() <-chan error {
	errCh := make(chan error, 1)

	go func() {
		_ = os.Remove(s.path)

		l, err := net.Listen("unix", s.path)
		if err != nil {
			errCh <- err
			return
		}
		defer l.Close()

		if err := os.Chmod(s.path, 0o600); err != nil {
			s.logger.Warnf("Failed to set socket permissions: %v", err)
		}

		s.logger.Infof("Control socket listening on %s", s.path)
		errCh <- nil

		for {
			conn, err := l.Accept()
			if err != nil {
				if os.IsTimeout(err) {
					continue
				}
				s.logger.Warnf("UDS accept error: %v", err)
				continue
			}
			go s.handleConn(conn)
		}
	}()

	return errCh
}

func (s *Server) handleConn(c net.Conn) {
	defer c.Close()

	_ = c.SetDeadline(time.Now().Add(udsTimeout))

	var req CommandRequest
	dec := json.NewDecoder(c)
	if err := dec.Decode(&req); err != nil {
		s.logger.Warnf("UDS decode error: %v", err)
		return
	}

	s.logger.Infof("Received command: %s", req.Cmd)
	resp := s.handle(req.Cmd, s.logger)

	enc := json.NewEncoder(c)
	if err := enc.Encode(resp); err != nil {
		s.logger.Warnf("UDS encode error: %v", err)
	}
}
