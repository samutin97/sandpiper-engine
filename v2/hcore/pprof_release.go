//go:build !with_pprof

package hcore

// startDebugPprof does nothing in a release build: no pprof listener, whatever the app's
// settings or log level (HC-07). Build with the tag with_pprof for one.
func startDebugPprof(bool) {}
