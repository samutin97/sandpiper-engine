package config

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// H-02: the core's sockets are protected around its TUN on Android too (auto_detect_interface), so
// the app may stay inside its own VPN; not in proxy mode, nor on iOS.
func TestAutoDetectInterfaceProtectsAndroidSockets(t *testing.T) {
	tun := chainTestOptions(t, `{"enable-tun":true}`)
	proxy := chainTestOptions(t, `{"enable-tun":false}`)
	cases := []struct {
		name         string
		hopt         *HiddifyOptions
		android, ios bool
		want         bool
	}{
		{"android tun", tun, true, false, true},
		{"android proxy", proxy, true, false, false},
		{"ios tun", tun, false, true, false},
		{"desktop tun", tun, false, false, true},
	}
	for _, c := range cases {
		if got := autoDetectInterface(c.hopt, c.android, c.ios); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
	// and the config of this build
	options := buildPerApp(t, `{"enable-tun":true}`)
	if options.Route.AutoDetectInterface != !C.IsIos {
		t.Fatalf("auto_detect_interface %v", options.Route.AutoDetectInterface)
	}
}

// The tunnel to the server goes out of the TUN: nothing routes a server's address into the tunnel.
// The direct outbound (Russian sites) and the direct DNS servers dial with the protected default
// dialer (no detour); the app's own requests reach the router through the TUN like any app's.
func TestDirectOutboundsDialAroundTheTunnel(t *testing.T) {
	options := buildPerApp(t, `{"enable-tun":true,"region":"ru"}`)
	for _, out := range options.Outbounds {
		if out.Tag == OutboundDirectTag {
			if out.Type != C.TypeDirect {
				t.Fatalf("direct is %s", out.Type)
			}
		}
	}
	for _, server := range options.DNS.Servers {
		if server.Tag == DNSDirectTag {
			if detour := dnsServerDetour(server.Options); detour != "" {
				t.Fatalf("the direct DNS server goes through %q", detour)
			}
		}
	}
	if options.Route.Final != OutboundSelectTag {
		t.Fatalf("final %q", options.Route.Final)
	}
}

func dnsServerDetour(options any) string {
	switch o := options.(type) {
	case *option.RemoteHTTPSDNSServerOptions:
		return o.Detour
	case *option.RemoteTLSDNSServerOptions:
		return o.Detour
	case *option.RemoteDNSServerOptions:
		return o.Detour
	}
	return ""
}
