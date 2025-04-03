package metrics

import (
	"net/http"

	"vibepn/log"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func Serve(addr string) {
	logger := log.New("metrics/http")

	http.Handle("/metrics", promhttp.Handler())

	logger.Infof("Serving Prometheus metrics on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		logger.Errorf("Metrics server failed: %v", err)
	}
}
