package peer

import (
	"sync"
	"time"

	"vibepn/shared"
)

type LivenessTracker struct {
	mu    sync.Mutex
	peers map[string]shared.PeerState
}

func NewLivenessTracker(timeout time.Duration) *LivenessTracker {
	return &LivenessTracker{
		peers: make(map[string]shared.PeerState),
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

func (t *LivenessTracker) ListPeers() []shared.PeerState {
	t.mu.Lock()
	defer t.mu.Unlock()

	var out []shared.PeerState
	for _, p := range t.peers {
		out = append(out, p)
	}
	return out
}

func (t *LivenessTracker) StartWatcher(rt interface{}) {
	// Placeholder for background peer expiry tracking
}
