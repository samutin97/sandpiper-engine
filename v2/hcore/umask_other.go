//go:build !linux && !android && !darwin

package hcore

// restrictUmask: no umask here.
func restrictUmask() {}
