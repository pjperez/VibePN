package peer

import (
	"sync"
	"time"

	"vibepn/log"
	"vibepn/netgraph"
	"vibepn/shared"
)

// LivenessTracker tracks the last-seen time of peers.
type LivenessTracker struct {
	mu      sync.Mutex
	peers   map[string]shared.PeerState
	timeout time.Duration
}

// NewLivenessTracker creates a tracker with the given timeout.
func NewLivenessTracker(timeout time.Duration) *LivenessTracker {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &LivenessTracker{
		peers:   make(map[string]shared.PeerState),
		timeout: timeout,
	}
}

// MarkAlive records that a peer was seen now. Empty peer IDs are ignored
// (they are transient artifacts of connection churn before identity
// resolution completes).
func (t *LivenessTracker) MarkAlive(id string) {
	if id == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.peers[id] = shared.PeerState{ID: id, LastSeen: time.Now()}
}

// UpdatePeer records that a peer was seen now.
func (t *LivenessTracker) UpdatePeer(peerID string) {
	t.MarkAlive(peerID)
}

// Remove drops a peer from the tracker immediately (e.g. on disconnect).
func (t *LivenessTracker) Remove(peerID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.peers, peerID)
}

// ListPeers returns a snapshot of tracked peers.
func (t *LivenessTracker) ListPeers() []shared.PeerState {
	t.mu.Lock()
	defer t.mu.Unlock()

	out := make([]shared.PeerState, 0, len(t.peers))
	for _, p := range t.peers {
		if p.ID == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// StartWatcher periodically removes peers that have not been seen within the
// timeout and drops their routes. The sweep interval scales with the timeout
// so small timeouts (tests) are observed promptly.
func (t *LivenessTracker) StartWatcher(rt *netgraph.RouteTable) {
	logger := log.New("peer/watcher")

	interval := 10 * time.Second
	if t.timeout < interval {
		interval = t.timeout / 3
	}
	if interval < 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			t.mu.Lock()
			now := time.Now()
			var expired []string
			for id, peer := range t.peers {
				if id == "" {
					continue
				}
				if now.Sub(peer.LastSeen) > t.timeout {
					expired = append(expired, id)
				}
			}
			for _, id := range expired {
				delete(t.peers, id)
			}
			t.mu.Unlock()

			for _, id := range expired {
				logger.Warnf("Peer %s considered dead (timeout)", id)
				rt.RemoveByPeer(id)
			}
		}
	}()
}
