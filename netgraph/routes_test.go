package netgraph

import (
	"testing"
	"time"
)

func TestAddRouteDeduplicates(t *testing.T) {
	rt := NewRouteTable()
	rt.AddRoute(Route{Network: "corp", Prefix: "10.0.0.0/24", PeerID: "a", Metric: 1})
	rt.AddRoute(Route{Network: "corp", Prefix: "10.0.0.0/24", PeerID: "a", Metric: 5})

	routes := rt.RoutesForNetwork("corp", "")
	if len(routes) != 1 {
		t.Fatalf("expected 1 route after dedup, got %d", len(routes))
	}
	if routes[0].Metric != 5 {
		t.Fatalf("expected updated metric 5, got %d", routes[0].Metric)
	}
}

func TestLookupLongestPrefix(t *testing.T) {
	rt := NewRouteTable()
	rt.AddRoute(Route{Network: "corp", Prefix: "10.0.0.0/8", PeerID: "wide", Metric: 1})
	rt.AddRoute(Route{Network: "corp", Prefix: "10.42.0.0/16", PeerID: "mid", Metric: 1})
	rt.AddRoute(Route{Network: "corp", Prefix: "10.42.1.0/24", PeerID: "narrow", Metric: 1})

	r := rt.Lookup("corp", "10.42.1.55")
	if r == nil || r.PeerID != "narrow" {
		t.Fatalf("expected narrow route, got %+v", r)
	}

	r = rt.Lookup("corp", "10.42.2.55")
	if r == nil || r.PeerID != "mid" {
		t.Fatalf("expected mid route, got %+v", r)
	}

	r = rt.Lookup("corp", "10.99.1.1")
	if r == nil || r.PeerID != "wide" {
		t.Fatalf("expected wide route, got %+v", r)
	}

	if r := rt.Lookup("corp", "11.0.0.1"); r != nil {
		t.Fatalf("expected no route for 11.0.0.1, got %+v", r)
	}

	if r := rt.Lookup("other", "10.42.1.55"); r != nil {
		t.Fatalf("expected no route for other network, got %+v", r)
	}
}

func TestLookupPrefersLowerMetric(t *testing.T) {
	rt := NewRouteTable()
	rt.AddRoute(Route{Network: "corp", Prefix: "10.0.0.0/8", PeerID: "slow", Metric: 10})
	rt.AddRoute(Route{Network: "corp", Prefix: "10.0.0.0/8", PeerID: "fast", Metric: 1})

	r := rt.Lookup("corp", "10.1.2.3")
	if r == nil || r.PeerID != "fast" {
		t.Fatalf("expected fast route, got %+v", r)
	}
}

func TestExpiry(t *testing.T) {
	rt := NewRouteTable()
	rt.AddRoute(Route{Network: "corp", Prefix: "10.0.0.0/24", PeerID: "a", ExpiresAt: time.Now().Add(-time.Second)})
	rt.AddRoute(Route{Network: "corp", Prefix: "10.1.0.0/24", PeerID: "b"})

	if r := rt.Lookup("corp", "10.0.0.5"); r != nil {
		t.Fatalf("expected expired route to be invisible, got %+v", r)
	}
	if r := rt.Lookup("corp", "10.1.0.5"); r == nil {
		t.Fatalf("expected non-expired route to be visible")
	}

	if removed := rt.ReapExpired(); removed != 1 {
		t.Fatalf("expected 1 expired route reaped, got %d", removed)
	}
	if len(rt.AllRoutes()) != 1 {
		t.Fatalf("expected 1 route after reap, got %d", len(rt.AllRoutes()))
	}
}

func TestRemoveByPeerAndRemoveRoute(t *testing.T) {
	rt := NewRouteTable()
	rt.AddRoute(Route{Network: "corp", Prefix: "10.0.0.0/24", PeerID: "a"})
	rt.AddRoute(Route{Network: "corp", Prefix: "10.1.0.0/24", PeerID: "b"})
	rt.AddRoute(Route{Network: "dmz", Prefix: "10.2.0.0/24", PeerID: "a"})

	rt.RemoveByPeer("a")
	if len(rt.AllRoutes()) != 1 {
		t.Fatalf("expected 1 route after RemoveByPeer, got %d", len(rt.AllRoutes()))
	}

	rt.RemoveRoute("corp", "10.1.0.0/24")
	if len(rt.AllRoutes()) != 0 {
		t.Fatalf("expected 0 routes after RemoveRoute, got %d", len(rt.AllRoutes()))
	}
}

func TestRoutesForNetworkExcludesPeer(t *testing.T) {
	rt := NewRouteTable()
	rt.AddRoute(Route{Network: "corp", Prefix: "10.0.0.0/24", PeerID: "a"})
	rt.AddRoute(Route{Network: "corp", Prefix: "10.1.0.0/24", PeerID: "b"})

	routes := rt.RoutesForNetwork("corp", "a")
	if len(routes) != 1 || routes[0].PeerID != "b" {
		t.Fatalf("expected only peer b route, got %+v", routes)
	}
}
