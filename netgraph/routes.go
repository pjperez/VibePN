package netgraph

import (
	"sync"
	"time"
)

type Route struct {
	Network   string
	Prefix    string
	PeerID    string // was "Via"
	Metric    int
	ExpiresAt time.Time
}

type RouteTable struct {
	mu     sync.Mutex
	routes map[string][]Route // network → []Route
}

func NewRouteTable() *RouteTable {
	return &RouteTable{
		routes: make(map[string][]Route),
	}
}

func (rt *RouteTable) AddRoute(r Route) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	list := rt.routes[r.Network]
	for i, existing := range list {
		if existing.Prefix == r.Prefix && existing.PeerID == r.PeerID {
			list[i] = r
			rt.routes[r.Network] = list
			return
		}
	}

	rt.routes[r.Network] = append(list, r)
}

func (rt *RouteTable) RemoveRoutesForPeer(peerID string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	for net, list := range rt.routes {
		var updated []Route
		for _, r := range list {
			if r.PeerID != peerID {
				updated = append(updated, r)
			}
		}
		rt.routes[net] = updated
	}
}

func (rt *RouteTable) RoutesForNetwork(network, excludePeer string) []Route {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	var out []Route
	for _, r := range rt.routes[network] {
		if excludePeer != "" && r.PeerID == excludePeer {
			continue
		}
		out = append(out, r)
	}
	return out
}

func (rt *RouteTable) AllRoutes() []Route {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	var all []Route
	for net, list := range rt.routes {
		for _, r := range list {
			r.Network = net
			all = append(all, r)
		}
	}
	return all
}
