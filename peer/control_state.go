package peer

import (
	"sync"

	"vibepn/control"
	"vibepn/netgraph"
)

// Global control-plane wiring. The daemon registers these once at startup.
var (
	ctrlMu      sync.RWMutex
	ctrlRoutes  *netgraph.RouteTable
	ctrlTracker control.PeerLister
	ctrlPolicy  RoutePolicy
)

// RegisterControl wires the peer package to the control-plane singletons.
func RegisterControl(
	routeTable *netgraph.RouteTable,
	tracker control.PeerLister,
	policy RoutePolicy,
) {
	ctrlMu.Lock()
	defer ctrlMu.Unlock()
	ctrlRoutes = routeTable
	ctrlTracker = tracker
	ctrlPolicy = policy
}

// GetRouteTable returns the registered route table.
func GetRouteTable() *netgraph.RouteTable {
	ctrlMu.RLock()
	defer ctrlMu.RUnlock()
	return ctrlRoutes
}

// GetPeerTracker returns the registered liveness tracker.
func GetPeerTracker() control.PeerLister {
	ctrlMu.RLock()
	defer ctrlMu.RUnlock()
	return ctrlTracker
}

// GetRoutePolicy returns the registered route policy.
func GetRoutePolicy() RoutePolicy {
	ctrlMu.RLock()
	defer ctrlMu.RUnlock()
	if ctrlPolicy == nil {
		return allowAllPolicy{}
	}
	return ctrlPolicy
}

type allowAllPolicy struct{}

func (allowAllPolicy) Allow(peerID, network, prefix string) error { return nil }
