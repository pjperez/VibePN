package metrics

import (
	"net/http"
	"time"

	"vibepn/log"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// PacketsForwarded counts packets sent to peers per network.
	PacketsForwarded = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "vibepn_packets_forwarded_total",
			Help: "Total packets forwarded to peers, by network.",
		},
		[]string{"network"},
	)
	// PacketsReceived counts packets received from peers per network.
	PacketsReceived = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "vibepn_packets_received_total",
			Help: "Total packets received from peers, by network.",
		},
		[]string{"network"},
	)
	// PacketsDropped counts packets dropped due to routing or framing errors.
	PacketsDropped = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "vibepn_packets_dropped_total",
			Help: "Total packets dropped, by reason.",
		},
		[]string{"reason"},
	)
	// ActivePeers tracks the number of connected peers.
	ActivePeers = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "vibepn_active_peers",
			Help: "Number of currently connected peers.",
		},
	)
	// RouteCount tracks the number of known routes.
	RouteCount = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "vibepn_routes",
			Help: "Number of routes in the route table.",
		},
	)
	// UptimeSeconds tracks daemon uptime.
	UptimeSeconds = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "vibepn_uptime_seconds",
			Help: "Daemon uptime in seconds.",
		},
	)
)

func init() {
	prometheus.MustRegister(
		PacketsForwarded,
		PacketsReceived,
		PacketsDropped,
		ActivePeers,
		RouteCount,
		UptimeSeconds,
	)
}

// Serve starts the Prometheus metrics HTTP server on addr.
func Serve(addr string) {
	logger := log.New("metrics/http")

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	// Track uptime.
	start := time.Now()
	go func() {
		for {
			UptimeSeconds.Set(time.Since(start).Seconds())
			time.Sleep(5 * time.Second)
		}
	}()

	logger.Infof("Serving Prometheus metrics on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		logger.Errorf("Metrics server failed: %v", err)
	}
}
