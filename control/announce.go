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
	PeerID    string `json:"via"` // "via" in JSON
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

	logger.Infof("<<< Sent route-announce for %s (%d entries)", network, len(routes))
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

func ParseRouteAnnounce(dec *json.Decoder, logger *log.Logger) {
	var payload struct {
		Network string  `json:"network"`
		Routes  []Route `json:"routes"`
	}
	if err := dec.Decode(&payload); err != nil {
		logger.Warnf("Failed to decode route-announce payload: %v", err)
		return
	}
	logger.Infof("Received route announcement for network=%s", payload.Network)
	HandleRouteAnnounce(payload.Network, payload.Routes, GetRouteTable(), logger)
}
