package server

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	PathMetrics = "/metrics"
)

// handleMetrics registers prometheus handler on '/metrics'.
func handleMetrics(mux *http.ServeMux) {
	mux.Handle(PathMetrics, promhttp.Handler())
}
