package server

import (
	"net/http"

	"github.com/KumKeeHyun/perisco/pkg/debugutil"
)

// handleDebug registers debug handler on '/debug'.
func handleDebug(mux *http.ServeMux) {
	// /debug/pprof
	for p, h := range debugutil.PProfHandlers() {
		mux.Handle(p, h)
	}
}
