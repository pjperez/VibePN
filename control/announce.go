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
	stream, err := conn.OpenStream()
	if err != nil {
		logger.Warnf("Failed to open route-announce stream: %v", err)
		return
	}
	defer stream.Close()

	enc := json.NewEncoder(stream)
	_ = enc.Encode(Header{Type: "route-announce"})
	payload := map[string]interface{}{
		"network": network,
		"routes":  routes,
	}
	_ = enc.Encode(payload)

	logger.Infof("Sent route-announce for %s (%d entries)", network, len(routes))
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
