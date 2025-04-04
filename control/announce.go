package control

import (
	"encoding/json"
	"fmt"
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

	header := Header{Type: "route-announce"}
	payload := map[string]interface{}{
		"network": network,
		"routes":  routes,
	}

	headerBytes, _ := json.Marshal(header)
	payloadBytes, _ := json.Marshal(payload)

	logger.Infof("[debug/sendroute] Header JSON: %s", string(headerBytes))
	logger.Infof("[debug/sendroute] Body JSON:   %s", string(payloadBytes))

	_, err = fmt.Fprintf(stream, "%s\n%s\n", string(headerBytes), string(payloadBytes))
	if err != nil {
		logger.Warnf("Failed to send route-announce: %v", err)
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

func ParseRouteAnnounce(stream quic.Stream, logger *log.Logger) {
	defer stream.Close()

	var payload struct {
		Network string  `json:"network"`
		Routes  []Route `json:"routes"`
	}

	dec := json.NewDecoder(stream)
	if err := dec.Decode(&payload); err != nil {
		logger.Warnf("Failed to decode route-announce payload: %v", err)
		return
	}

	logger.Infof("✅ Parsed route-announce for network %s (%d routes)", payload.Network, len(payload.Routes))

	rt := GetRouteTable()
	if rt != nil {
		HandleRouteAnnounce(payload.Network, payload.Routes, rt, logger)
	} else {
		logger.Warnf("No route table available, ignoring route-announce")
	}
}
