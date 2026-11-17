package hcore

import (
	"context"

	E "github.com/sagernet/sing/common/exceptions"
)

// denySecurityPolicy refuses every feature sing-box guards with adapter.CheckSecurityFeature: a
// Tor outbound (it runs a program), the OpenConnect wrapper scripts, NTP writing the system clock,
// the Tailscale SSH server. hiddify-core never needs them, and a profile must not get them (HC-03).
// Without a registered policy the check let everything through.
type denySecurityPolicy struct{}

func (denySecurityPolicy) CheckFeature(_ context.Context, feature string) error {
	return E.New(feature, " is not allowed in this build")
}
