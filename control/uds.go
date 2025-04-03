package control

import (
	"encoding/json"
	"net"
	"os"
	"time"

	"vibepn/log"
)

const udsTimeout = 2 * time.Second

func StartUDS(path string) {
	logger := log.New("control/uds")

	_ = os.Remove(path)

	l, err := net.Listen("unix", path)
	if err != nil {
		logger.Fatalf("UDS listen error: %v", err)
	}

	if err := os.Chmod(path, 0o600); err != nil {
		logger.Warnf("Failed to set socket permissions: %v", err)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			logger.Warnf("UDS accept error: %v", err)
			continue
		}

		go handleConn(conn, logger)
	}
}

func handleConn(c net.Conn, logger *log.Logger) {
	defer c.Close()

	_ = c.SetDeadline(time.Now().Add(udsTimeout))

	var req CommandRequest
	dec := json.NewDecoder(c)
	if err := dec.Decode(&req); err != nil {
		logger.Warnf("UDS decode error: %v", err)
		return
	}

	logger.Infof("Received command: %s", req.Cmd)
	resp := Handle(req.Cmd, nil, logger)

	enc := json.NewEncoder(c)
	if err := enc.Encode(resp); err != nil {
		logger.Warnf("UDS encode error: %v", err)
	}
}
