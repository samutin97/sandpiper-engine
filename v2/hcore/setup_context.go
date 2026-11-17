package hcore

import (
	"context"

	"github.com/sagernet/sing-box/experimental/libbox"
)

// SetupContext is the context to build the core in for a start that does not come through the gRPC
// API (Mobile.Start: Android's Always-on VPN, a restart of the service after its process was
// killed, its watchdog): the one Setup made with the platform interface, as for a start over gRPC.
//
// Mobile.Start used libbox.BaseContext(nil): without the platform interface the "local" DNS server
// is Go's resolver, which on Android has no /etc/resolv.conf and asks 127.0.0.1 and [::1], which
// refuse. In a tunnel brought back without the app, the direct resolver (the sites that go direct,
// and the lookups of the tests of an AmneziaWG endpoint) failed until the user connected again.
func SetupContext() context.Context {
	if ctx := static.BaseContext; ctx != nil {
		return ctx
	}
	return libbox.BaseContext(nil)
}
