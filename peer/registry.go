package peer

import (
	"context"
	"sync"

	"vibepn/config"
	"vibepn/control"
	"vibepn/log"

	gquic "github.com/quic-go/quic-go" // alias to avoid conflict
)

type Registry struct {
	mu        sync.RWMutex
	conns     map[string]gquic.Connection // peerID → connection
	logger    *log.Logger
	identity  config.Identity
	netcfg    map[string]config.NetworkConfig
	onConnect func(peerID string, conn gquic.Connection) // 🧠 NEW: callback
}

func NewRegistry(identity config.Identity, netcfg map[string]config.NetworkConfig) *Registry {
	return &Registry{
		conns:    make(map[string]gquic.Connection),
		logger:   log.New("peer/registry"),
		identity: identity,
		netcfg:   netcfg,
	}
}

func (r *Registry) Add(peerID string, conn gquic.Connection) {
	r.mu.Lock()
	defer r.mu.Unlock()
	existing := r.conns[peerID]
	if existing != nil {
		r.logger.Warnf("Duplicate connection for peer %s, closing old one", peerID)
		existing.CloseWithError(0, "duplicate connection")
	}
	r.conns[peerID] = conn
	r.logger.Infof("Registered connection for peer %s", peerID)

	if r.onConnect != nil {
		r.onConnect(peerID, conn)
	}

	// 🧠 NEW: Watch for session death
	go func() {
		<-conn.Context().Done()
		r.logger.Infof("Connection to %s closed (session ended)", peerID)
		r.Remove(peerID)
	}()
}

func (r *Registry) Remove(peerID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.conns, peerID)
	r.logger.Infof("Removed connection for peer %s", peerID)
}

func (r *Registry) Get(peerID string) gquic.Connection {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.conns[peerID]
}

func (r *Registry) All() map[string]gquic.Connection {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make(map[string]gquic.Connection, len(r.conns))
	for k, v := range r.conns {
		out[k] = v
	}
	return out
}

func (r *Registry) DisconnectAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for peerID, conn := range r.conns {
		// 🔥 FIX: Open a stream for sending Goodbye
		stream, err := conn.OpenStreamSync(context.Background())
		if err == nil {
			_ = control.SendGoodbye(stream)
			_ = stream.Close()
		} else {
			r.logger.Warnf("Failed to open stream to peer %s for goodbye: %v", peerID, err)
		}

		_ = conn.CloseWithError(0, "shutdown")
		r.logger.Infof("Disconnected from peer %s", peerID)
	}
	r.conns = map[string]gquic.Connection{}
}

func (r *Registry) Identity() config.Identity {
	return r.identity
}

func (r *Registry) NetConfig() map[string]config.NetworkConfig {
	return r.netcfg
}

// 🧠 NEW: set callback to trigger when a peer connects
func (r *Registry) SetOnConnect(cb func(peerID string, conn gquic.Connection)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onConnect = cb
}
