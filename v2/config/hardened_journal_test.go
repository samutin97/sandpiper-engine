package config

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// The block journal names each proxy's server, protocol and transport as built; the groups and the
// outbounds that reach no server of their own are not proxies.
func TestJournalProxies(t *testing.T) {
	options := buildPanelProfile(t, panelSubscription, tierSettings(t, panelPolicy))
	proxies := JournalProxies(options)
	for tag, want := range map[string]JournalProxy{
		"2 gRPC B":        {Server: "192.0.2.10/32", Protocol: "vless", Transport: "grpc+tls", ServerName: "vpn.example.net"},
		"3 XHTTP":         {Server: "192.0.2.10/32", Protocol: "vless", Transport: "xhttp+tls", ServerName: "vpn.example.net"},
		"5 Naive":         {Server: "192.0.2.10/32", Protocol: "naive", Transport: "h2+tls", ServerName: "vpn.example.net"},
		"6 Reality gRPC":  {Server: "192.0.2.11/32", Protocol: "vless", Transport: "grpc+reality", ServerName: "www.example.org"},
		"7 Reality XHTTP": {Server: "192.0.2.11/32", Protocol: "vless", Transport: "xhttp+reality", ServerName: "www.example.org"},
		"8 UDP Hysteria2": {Server: "192.0.2.10/32", Protocol: "hysteria2", Transport: "quic", ServerName: "vpn.example.net"},
		"9 UDP HTTP3":     {Server: "192.0.2.10/32", Protocol: "vless", Transport: "xhttp-h3+tls", ServerName: "vpn.example.net"},
	} {
		if got := proxies[tag]; got != want {
			t.Errorf("%s: %+v, want %+v", tag, got, want)
		}
	}
	for _, tag := range []string{OutboundSelectTag, OutboundURLTestTag, OutboundTieredTag, OutboundTieredWaitTag, OutboundDirectTag} {
		if _, ok := proxies[tag]; ok {
			t.Errorf("%s is in the journal's proxies", tag)
		}
	}
	if got := JournalProxies(nil); len(got) != 0 {
		t.Errorf("nil options: %+v", got)
	}
}

func TestJournalTransport(t *testing.T) {
	for _, c := range []struct {
		typ     string
		options any
		want    string
	}{
		{C.TypeAwg, &option.AwgEndpointOptions{}, "udp"},
		{C.TypeWireGuard, &option.WireGuardEndpointOptions{}, "udp"},
		{C.TypeTUIC, &option.TUICOutboundOptions{}, "quic"},
		{C.TypeNaive, &option.NaiveOutboundOptions{QUIC: true}, "quic"},
		{C.TypeVLESS, &option.VLESSOutboundOptions{}, "tcp"},
		{C.TypeVLESS, &option.VLESSOutboundOptions{OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
			Enabled: true, Reality: &option.OutboundRealityOptions{Enabled: true},
		}}}, "tcp+reality"},
		{C.TypeTrojan, &option.TrojanOutboundOptions{Transport: &option.V2RayTransportOptions{Type: C.V2RayTransportTypeWebsocket}}, "ws"},
		{C.TypeVMess, &option.VMessOutboundOptions{Transport: &option.V2RayTransportOptions{Type: C.V2RayTransportTypeHTTP}}, "h2"},
		{C.TypeShadowsocks, &option.ShadowsocksOutboundOptions{}, "tcp"},
	} {
		if got := journalTransport(c.typ, c.options); got != c.want {
			t.Errorf("%s %T: %q, want %q", c.typ, c.options, got, c.want)
		}
	}
}
