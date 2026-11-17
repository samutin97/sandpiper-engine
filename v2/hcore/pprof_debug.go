//go:build with_pprof

package hcore

import (
	"net/http"
	"net/http/pprof"
)

// startDebugPprof serves pprof on 127.0.0.1:6060 in a debug build of the core (build tag
// with_pprof) set up with debug. Release builds have no pprof at all (pprof_release.go).
func startDebugPprof(debug bool) {
	if !debug {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	go http.ListenAndServe("127.0.0.1:6060", mux)
}
