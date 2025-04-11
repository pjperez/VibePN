package control

import (
	"time"

	"vibepn/netgraph"
	"vibepn/shared"
)

type PeerLister interface {
	ListPeers() []shared.PeerState
	UpdatePeer(peerID string)
}

type PeerSendFunc func(peerID, network string, route netgraph.Route)
type GoodbyeFunc func()

var (
	routeTable  *netgraph.RouteTable
	peerTracker PeerLister
	sendRoute   PeerSendFunc
	goodbyeFunc GoodbyeFunc
	startupTime = time.Now()
)

func Register(rt *netgraph.RouteTable, pt PeerLister, sr PeerSendFunc) {
	routeTable = rt
	peerTracker = pt
	sendRoute = sr
}

func RegisterGoodbyeCallback(f GoodbyeFunc) {
	goodbyeFunc = f
}

func TriggerGoodbye() {
	if goodbyeFunc != nil {
		goodbyeFunc()
	}
}

func GetRouteTable() *netgraph.RouteTable {
	return routeTable
}

func GetPeerTracker() PeerLister {
	return peerTracker
}

func SendRouteToPeer(peerID, network string, route netgraph.Route) {
	if sendRoute != nil {
		sendRoute(peerID, network, route)
	}
}

func Uptime() string {
	return time.Since(startupTime).Round(time.Second).String()
}
