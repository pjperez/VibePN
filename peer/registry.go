package peer

import (
	"sync"

	"vibepn/control"
	"vibepn/log"

	quic "github.com/quic-go/quic-go"
)

type Registry struct {
	mu     sync.RWMutex
	conns  map[string]quic.Connection // peerID → connection
	logger *log.Logger
}

func NewRegistry() *Registry {
	return &Registry{
		conns:  make(map[string]quic.Connection),
		logger: log.New("peer/registry"),
	}
}

func (r *Registry) Add(peerID string, conn quic.Connection) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.conns[peerID] = conn
	r.logger.Infof("Registered connection for peer %s", peerID)
}

func (r *Registry) Remove(peerID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.conns, peerID)
	r.logger.Infof("Removed connection for peer %s", peerID)
}

func (r *Registry) Get(peerID string) quic.Connection {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.conns[peerID]
}

func (r *Registry) All() map[string]quic.Connection {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make(map[string]quic.Connection, len(r.conns))
	for k, v := range r.conns {
		out[k] = v
	}
	return out
}

func (r *Registry) DisconnectAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for peerID, conn := range r.conns {
		control.SendGoodbye(conn, r.logger)
		_ = conn.CloseWithError(0, "shutdown")
		r.logger.Infof("Disconnected from peer %s", peerID)
	}
	r.conns = map[string]quic.Connection{}
}
