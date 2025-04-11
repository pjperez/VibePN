package peer

import (
	"sync"
	"time"

	"vibepn/log"
	"vibepn/netgraph"
	"vibepn/shared"
)

type LivenessTracker struct {
	mu    sync.Mutex
	peers map[string]shared.PeerState // ✅ Always shared.PeerState
}

func NewLivenessTracker(timeout time.Duration) *LivenessTracker {
	return &LivenessTracker{
		peers: make(map[string]shared.PeerState), // ✅ Always shared.PeerState
	}
}

func (t *LivenessTracker) MarkAlive(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.peers[id] = shared.PeerState{
		ID:       id,
		LastSeen: time.Now(),
	}
}

func (t *LivenessTracker) UpdatePeer(peerID string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.peers[peerID] = shared.PeerState{
		ID:       peerID,
		LastSeen: time.Now(),
	}
}

func (t *LivenessTracker) ListPeers() []shared.PeerState {
	t.mu.Lock()
	defer t.mu.Unlock()

	var out []shared.PeerState
	for _, p := range t.peers {
		out = append(out, p)
	}
	return out
}

func (t *LivenessTracker) StartWatcher(rt *netgraph.RouteTable) {
	logger := log.New("peer/watcher")

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			<-ticker.C

			t.mu.Lock()
			now := time.Now()
			expired := []string{}

			for id, peer := range t.peers {
				if now.Sub(peer.LastSeen) > 30*time.Second {
					expired = append(expired, id)
				}
			}

			for _, id := range expired {
				logger.Warnf("Peer %s considered dead (timeout)", id)
				delete(t.peers, id)
				rt.RemoveRoutesForPeer(id)
			}
			t.mu.Unlock()
		}
	}()
}
