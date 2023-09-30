package server

import (
	"fmt"
	"net/http"

	"go.uber.org/zap"
)

func RunServer(log *zap.SugaredLogger, debug bool, port int) error {
	mux := http.NewServeMux()
	log.Info("register metrics handler")
	handleMetrics(mux)
	if debug {
		log.Info("register debug handler")
		handleDebug(mux)
	}

	addr := fmt.Sprintf(":%d", port)
	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	log.Infow("serve http server", "addr", addr)
	return srv.ListenAndServe()
}
