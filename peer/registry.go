package peer

import (
	"context"
	"sync"
	"time"
	"vibepn/netgraph"

	"vibepn/config"
	"vibepn/control"
	"vibepn/log"
	"vibepn/protocol"
	"vibepn/shared"

	gquic "github.com/quic-go/quic-go"
)

// Registry tracks active peer connections.
type Registry struct {
	mu           sync.RWMutex
	conns        map[string]gquic.Connection // peerID → connection
	logger       *log.Logger
	identity     config.Identity
	onConnect    func(peerID string, conn gquic.Connection)
	onDisconnect func(peerID string)
}

func NewRegistry(identity config.Identity) *Registry {
	return &Registry{
		conns:    make(map[string]gquic.Connection),
		logger:   log.New("peer/registry"),
		identity: identity,
	}
}

// Add registers a connection for peerID. If a connection already exists, the
// caller must have already resolved the tie-break; this method simply replaces
// the old connection.
func (r *Registry) Add(peerID string, conn gquic.Connection) {
	r.mu.Lock()
	existing := r.conns[peerID]
	r.conns[peerID] = conn
	r.mu.Unlock()

	if existing != nil && existing != conn {
		r.logger.Infof("Replacing connection for peer %s", peerID)
		_ = existing.CloseWithError(0, "superseded by new connection")
	}

	r.logger.Infof("Registered connection for peer %s", peerID)

	if r.onConnect != nil {
		r.onConnect(peerID, conn)
	}

	go func() {
		<-conn.Context().Done()
		r.logger.Infof("Connection to %s closed (session ended)", peerID)
		r.removeConnection(peerID, conn)
	}()
}

// removeConnection removes a connection only if it is still the active one.
func (r *Registry) removeConnection(peerID string, closedConn gquic.Connection) {
	r.mu.Lock()
	existing := r.conns[peerID]
	if existing == closedConn {
		delete(r.conns, peerID)
	}
	r.mu.Unlock()

	if existing == closedConn && r.onDisconnect != nil {
		r.onDisconnect(peerID)
	}
}

// Get returns the active connection for peerID, if any.
func (r *Registry) Get(peerID string) gquic.Connection {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.conns[peerID]
}

// All returns a snapshot of all active connections.
func (r *Registry) All() map[string]gquic.Connection {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make(map[string]gquic.Connection, len(r.conns))
	for k, v := range r.conns {
		out[k] = v
	}
	return out
}

// ListPeers returns the IDs of all active connections as peer states.
func (r *Registry) ListPeers() []shared.PeerState {
	conns := r.All()
	out := make([]shared.PeerState, 0, len(conns))
	for id := range conns {
		out = append(out, shared.PeerState{ID: id, LastSeen: time.Now()})
	}
	return out
}

// UpdatePeer is a no-op for the registry (liveness is tracked separately).
func (r *Registry) UpdatePeer(peerID string) {}

// SendRoute sends a route announcement to a peer over a fresh stream.
func (r *Registry) SendRoute(peerID, network string, route netgraph.Route) error {
	conn := r.Get(peerID)
	if conn == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	stream, err := conn.OpenStreamSync(ctx)
	cancel()
	if err != nil {
		return err
	}
	defer stream.Close()

	return protocol.WriteMessage(stream, protocol.RouteAnnounce{
		Network:  network,
		Prefixes: []string{route.Prefix},
		Metric:   uint16(route.Metric),
	})
}

// DisconnectAll sends a goodbye to every peer and closes the connections.
func (r *Registry) DisconnectAll() {
	r.mu.Lock()
	conns := r.conns
	r.conns = make(map[string]gquic.Connection)
	r.mu.Unlock()

	for peerID, conn := range conns {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		stream, err := conn.OpenStreamSync(ctx)
		cancel()
		if err == nil {
			_ = protocol.WriteMessage(stream, protocol.Goodbye{})
			_ = stream.Close()
		} else {
			r.logger.Warnf("Failed to open stream to peer %s for goodbye: %v", peerID, err)
		}
		_ = conn.CloseWithError(0, "shutdown")
		r.logger.Infof("Disconnected from peer %s", peerID)
	}
}

// Identity returns the local identity.
func (r *Registry) Identity() config.Identity {
	return r.identity
}

// SetOnConnect registers a callback invoked when a connection is registered.
func (r *Registry) SetOnConnect(cb func(peerID string, conn gquic.Connection)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onConnect = cb
}

// SetOnDisconnect registers a callback invoked when the last connection to a
// peer is removed.
func (r *Registry) SetOnDisconnect(cb func(peerID string)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onDisconnect = cb
}

// ReconcilePeers is a no-op hook for the control server; the connection
// manager owns dialing.
func (r *Registry) ReconcilePeers(cfg *config.Config) error {
	return nil
}

var _ control.PeerManager = (*Registry)(nil)
