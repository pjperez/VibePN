package peer

import (
	"testing"
	"time"

	"vibepn/config"
	"vibepn/netgraph"
	"vibepn/protocol"
	"vibepn/shared"
)

func TestConfigRoutePolicy(t *testing.T) {
	netcfg := func() map[string]config.NetworkConfig {
		return map[string]config.NetworkConfig{
			"corp": {Prefix: "10.42.0.0/24", Export: true},
			"dmz":  {Prefix: "10.99.0.0/24", Export: true},
		}
	}
	peers := func() map[string][]string {
		return map[string][]string{
			"node-b": {"corp"},
		}
	}

	p := NewConfigRoutePolicy(netcfg, peers)

	// Allowed: node-b announcing corp.
	if err := p.Allow("node-b", "corp", "10.42.0.0/24"); err != nil {
		t.Fatalf("expected allowed, got %v", err)
	}

	// Denied: node-b announcing dmz (not assigned).
	if err := p.Allow("node-b", "dmz", "10.99.0.0/24"); err == nil {
		t.Fatalf("expected denial for unassigned network")
	}

	// Denied: unknown network.
	if err := p.Allow("node-b", "nope", "10.0.0.0/8"); err == nil {
		t.Fatalf("expected denial for unknown network")
	}

	// Denied: invalid prefix.
	if err := p.Allow("node-b", "corp", "not-a-cidr"); err == nil {
		t.Fatalf("expected denial for invalid prefix")
	}

	// Open policy: a peer with no assignments may announce any configured net.
	if err := p.Allow("node-c", "dmz", "10.99.0.0/24"); err != nil {
		t.Fatalf("expected open policy to allow, got %v", err)
	}
}

func TestLivenessTracker(t *testing.T) {
	tracker := NewLivenessTracker(50 * time.Millisecond)
	tracker.MarkAlive("peer-a")

	if len(tracker.ListPeers()) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(tracker.ListPeers()))
	}

	time.Sleep(80 * time.Millisecond)
	// The watcher is not running here; ListPeers still shows the peer.
	if len(tracker.ListPeers()) != 1 {
		t.Fatalf("expected peer still listed without watcher")
	}
}

func TestLivenessWatcherExpiresPeers(t *testing.T) {
	rt := netgraph.NewRouteTable()
	rt.AddRoute(netgraph.Route{Network: "corp", Prefix: "10.0.0.0/24", PeerID: "peer-a"})

	tracker := NewLivenessTracker(30 * time.Millisecond)
	tracker.MarkAlive("peer-a")
	tracker.StartWatcher(rt)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(tracker.ListPeers()) == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if len(tracker.ListPeers()) != 0 {
		t.Fatalf("expected peer to expire, still listed")
	}
	if len(rt.AllRoutes()) != 0 {
		t.Fatalf("expected routes removed for expired peer, got %d", len(rt.AllRoutes()))
	}
}

func TestBackoffGrowsAndStaysBounded(t *testing.T) {
	prev := initialBackoff
	for i := 0; i < 8; i++ {
		base := nextBackoff(prev)
		if base <= prev && base != maxBackoff {
			t.Fatalf("backoff %v did not grow from %v", base, prev)
		}
		if base > maxBackoff {
			t.Fatalf("backoff %v exceeds cap %v", base, maxBackoff)
		}
		prev = base
	}
	if prev != maxBackoff {
		t.Fatalf("expected backoff to reach cap %v, got %v", maxBackoff, prev)
	}

	// Jittered values must stay within bounds.
	for i := 0; i < 100; i++ {
		j := jittered(maxBackoff)
		if j < initialBackoff || j > maxBackoff {
			t.Fatalf("jittered backoff %v out of bounds", j)
		}
	}
}

var _ = protocol.Hello{}
var _ = shared.PeerState{}
