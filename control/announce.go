package control

import (
	"encoding/json"
	"time"

	"vibepn/log"
	"vibepn/netgraph"

	"github.com/quic-go/quic-go"
)

type Route struct {
	Prefix    string `json:"prefix"`
	PeerID    string `json:"via"` // remains "via" in JSON for compatibility
	Metric    int    `json:"metric"`
	ExpiresIn int    `json:"expires_in"`
}

func SendRouteAnnounce(conn quic.Connection, network string, routes []Route, logger *log.Logger) {
	logger.Infof(">>> Sending route-announce to peer for network=%s, routes=%v", network, routes)

	stream, err := conn.OpenStream()
	if err != nil {
		logger.Errorf("Failed to open stream for route-announce: %v", err)
		return
	}
	defer stream.Close()

	enc := json.NewEncoder(stream)

	header := Header{Type: "route-announce"}
	if err := enc.Encode(header); err != nil {
		logger.Errorf("Failed to encode route-announce header: %v", err)
		return
	}

	payload := map[string]interface{}{
		"network": network,
		"routes":  routes,
	}
	if err := enc.Encode(payload); err != nil {
		logger.Errorf("Failed to encode route-announce payload: %v", err)
		return
	}

	logger.Infof("[debug/sendroute] Header JSON: %s", ToJson(header))
	logger.Infof("[debug/sendroute] Body JSON:   %s", ToJson(payload))

	logger.Infof("<<< Sent route-announce for %s (%d entries)", network, len(routes))
}

func ParseRouteAnnounce(dec *json.Decoder, logger *log.Logger) {
	var payload struct {
		Network string  `json:"network"`
		Routes  []Route `json:"routes"`
	}

	if err := dec.Decode(&payload); err != nil {
		logger.Warnf("Failed to decode route-announce payload: %v", err)
		return
	}

	logger.Infof("Parsed route-announce: network=%s, routes=%d", payload.Network, len(payload.Routes))

	rt := GetRouteTable()
	if rt == nil {
		logger.Warnf("RouteTable not initialized, ignoring route-announce")
		return
	}

	for _, r := range payload.Routes {
		rt.AddRoute(netgraph.Route{
			Network:   payload.Network,
			Prefix:    r.Prefix,
			PeerID:    r.PeerID,
			Metric:    r.Metric,
			ExpiresAt: time.Now().Add(time.Duration(r.ExpiresIn) * time.Second),
		})
	}

	logger.Infof("Applied %d routes for network %s", len(payload.Routes), payload.Network)
}

func ParseRouteWithdraw(dec *json.Decoder, logger *log.Logger) {
	var payload map[string]interface{}
	if err := dec.Decode(&payload); err != nil {
		logger.Warnf("Failed to decode route-withdraw payload: %v", err)
		return
	}
	logger.Infof("Received route withdrawal for network %v", payload["network"])
}

func HandleRouteAnnounce(network string, routes []Route, rt *netgraph.RouteTable, logger *log.Logger) {
	for _, r := range routes {
		rt.AddRoute(netgraph.Route{
			Network:   network,
			Prefix:    r.Prefix,
			PeerID:    r.PeerID,
			Metric:    r.Metric,
			ExpiresAt: time.Now().Add(time.Duration(r.ExpiresIn) * time.Second),
		})
	}
	logger.Infof("Handled route-announce for %s (%d routes)", network, len(routes))
}
