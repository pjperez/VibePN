// Package netgraph: in-memory route table keyed by network.
package netgraph

import (
	"net"
	"sync"
	"time"
)

// Route is a learned or local route announcement.
type Route struct {
	Network   string
	Prefix    string
	PeerID    string
	Metric    int
	ExpiresAt time.Time // zero means no expiry
}

// Expired reports whether the route has passed its expiry.
func (r Route) Expired(now time.Time) bool {
	return !r.ExpiresAt.IsZero() && now.After(r.ExpiresAt)
}

// RouteTable stores routes per network with mutex protection.
type RouteTable struct {
	mu     sync.Mutex
	routes map[string][]Route // network → []Route
}

func NewRouteTable() *RouteTable {
	return &RouteTable{
		routes: make(map[string][]Route),
	}
}

// AddRoute inserts or replaces a route, deduplicating on
// (network, prefix, peerID).
func (rt *RouteTable) AddRoute(r Route) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.addRouteLocked(r)
}

func (rt *RouteTable) addRouteLocked(r Route) {
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

// RemoveByPeer removes every route announced by peerID.
func (rt *RouteTable) RemoveByPeer(peerID string) {
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

// RemoveRoute removes a single route for a network and prefix.
func (rt *RouteTable) RemoveRoute(network, prefix string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	list, ok := rt.routes[network]
	if !ok {
		return
	}

	var updated []Route
	for _, r := range list {
		if r.Prefix != prefix {
			updated = append(updated, r)
		}
	}
	rt.routes[network] = updated
}

// RoutesForNetwork returns a copy of the routes for a network, optionally
// excluding one peer. Expired routes are dropped.
func (rt *RouteTable) RoutesForNetwork(network, excludePeer string) []Route {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	now := time.Now()
	var out []Route
	for _, r := range rt.routes[network] {
		if r.Expired(now) {
			continue
		}
		if excludePeer != "" && r.PeerID == excludePeer {
			continue
		}
		out = append(out, r)
	}
	return out
}

// Lookup returns the best route for an IP in a network using longest-prefix
// matching, preferring lower metrics on ties. Returns nil if no route matches.
func (rt *RouteTable) Lookup(network, ip string) *Route {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	dst := net.ParseIP(ip)
	if dst == nil {
		return nil
	}

	now := time.Now()
	var best *Route
	bestOnes := -1
	for _, r := range rt.routes[network] {
		if r.Expired(now) {
			continue
		}
		_, subnet, err := net.ParseCIDR(r.Prefix)
		if err != nil {
			continue
		}
		if !subnet.Contains(dst) {
			continue
		}
		ones, _ := subnet.Mask.Size()
		if best == nil || ones > bestOnes || (ones == bestOnes && r.Metric < best.Metric) {
			best = &r
			bestOnes = ones
		}
	}
	return best
}

// AllRoutes returns a flattened copy of all routes.
func (rt *RouteTable) AllRoutes() []Route {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	now := time.Now()
	var all []Route
	for net, list := range rt.routes {
		for _, r := range list {
			if r.Expired(now) {
				continue
			}
			r.Network = net
			all = append(all, r)
		}
	}
	return all
}

// ReapExpired removes all expired routes and returns how many were removed.
func (rt *RouteTable) ReapExpired() int {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	now := time.Now()
	removed := 0
	for net, list := range rt.routes {
		var updated []Route
		for _, r := range list {
			if r.Expired(now) {
				removed++
				continue
			}
			updated = append(updated, r)
		}
		rt.routes[net] = updated
	}
	return removed
}
