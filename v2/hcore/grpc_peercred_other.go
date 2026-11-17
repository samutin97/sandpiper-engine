//go:build !linux && !android

package hcore

import "net"

// peerCheckedListener: no peer credentials to check here; a socket file is protected by its
// directory (0700) and its mode (0600).
func peerCheckedListener(l net.Listener) net.Listener {
	return l
}
