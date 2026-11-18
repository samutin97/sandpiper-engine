package config

import (
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// JournalProxy is what the core's block journal says of a proxy: the server it connects to, as the
// handshake gate and the tiered controller count it (an address as address/bits, a domain in lower
// case), its protocol and how it gets there. Nothing of what goes through it.
type JournalProxy struct {
	Server   string
	Protocol string // the outbound's type: vless, trojan, vmess, hysteria2, tuic, naive, awg, wireguard, ...
	// Transport is how it reaches the server: tcp, grpc, xhttp, xhttp-h3 (XHTTP over HTTP/3), ws,
	// httpupgrade, h2, quic, udp (a tunnel's datagrams), with +reality or +tls when the transport
	// runs in it
	Transport string
	// ServerName is the name in its TLS (a REALITY proxy's is another site's), "" without TLS
	ServerName string
}

// JournalProxies are the outbounds and endpoints of options that connect to a server, by tag.
func JournalProxies(options *option.Options) map[string]JournalProxy {
	proxies := map[string]JournalProxy{}
	if options == nil {
		return proxies
	}
	for _, out := range options.Outbounds {
		if server := tierServerOf(out.Options); server != "" {
			proxies[out.Tag] = JournalProxy{
				Server: tierServer(server), Protocol: out.Type, Transport: journalTransport(out.Type, out.Options),
				ServerName: journalServerName(out.Options),
			}
		}
	}
	for _, end := range options.Endpoints {
		if server := tierServerOf(end.Options); server != "" {
			proxies[end.Tag] = JournalProxy{Server: tierServer(server), Protocol: end.Type, Transport: journalTransport(end.Type, end.Options)}
		}
	}
	return proxies
}

// journalServerName is the name in the TLS of options, "" without TLS.
func journalServerName(options any) string {
	wrapper, ok := options.(option.OutboundTLSOptionsWrapper)
	if !ok {
		return ""
	}
	if tls := wrapper.TakeOutboundTLSOptions(); tls != nil && tls.Enabled {
		return tls.ServerName
	}
	return ""
}

// journalTransport names how a proxy of type typ with options reaches its server (JournalProxy).
func journalTransport(typ string, options any) string {
	switch typ {
	case C.TypeHysteria, C.TypeHysteria2, C.TypeTUIC:
		return "quic"
	}
	if udpEndpointTypes[typ] {
		return "udp"
	}
	base := "tcp"
	switch opts := options.(type) {
	case *option.NaiveOutboundOptions:
		base = "h2"
		if opts.QUIC {
			base = "quic"
		}
	case *option.VLESSOutboundOptions:
		base = transportName(opts.Transport, options)
	case *option.TrojanOutboundOptions:
		base = transportName(opts.Transport, options)
	case *option.VMessOutboundOptions:
		base = transportName(opts.Transport, options)
	}
	wrapper, ok := options.(option.OutboundTLSOptionsWrapper)
	if !ok {
		return base
	}
	tls := wrapper.TakeOutboundTLSOptions()
	switch {
	case tls == nil || !tls.Enabled || base == "quic":
		return base
	case tls.Reality != nil && tls.Reality.Enabled:
		return base + "+reality"
	}
	return base + "+tls"
}

// transportName is the V2Ray transport's name, tcp without one; XHTTP over HTTP/3 is xhttp-h3 (as
// udpProxy tells it), the HTTP transport h2.
func transportName(transport *option.V2RayTransportOptions, options any) string {
	if transport == nil || transport.Type == "" {
		return "tcp"
	}
	switch transport.Type {
	case C.V2RayTransportTypeHTTP:
		return "h2"
	case C.V2RayTransportTypeXHTTP:
		if udpProxy(C.TypeVLESS, options) {
			return "xhttp-h3"
		}
	}
	return transport.Type
}
