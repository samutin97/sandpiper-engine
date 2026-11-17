package config

import (
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// The automatic groups (lowest, balance) and what the monitoring tests in its cycles.
//
// A subscription in the sing-box format of a panel (Hiddify Manager) has a urltest group of its
// own ("Auto") with the server's main proxies; the others are reserves, other protocols, UDP. The
// builder dropped the profile's groups and made lowest and balance of every proxy, so the
// automatic choice went to a reserve REALITY, an HTTPUpgrade or a UDP proxy, and the monitoring
// tested every proxy at each start and cycle (D-05 of the emulator report). Now:
//   - with a urltest group in the profile, the automatic groups take its members (nested groups
//     opened up), those left after the sanitizing; without one, every proxy, as before;
//   - the UDP proxies (QUIC: hysteria, hysteria2, tuic, a V2Ray QUIC transport, XHTTP over
//     HTTP/3, naive over QUIC; WireGuard: awg, wireguard) stay out of them unless
//     udp-endpoints-in-auto: UDP is the first thing a filtering network slows or drops, and a
//     QUIC handshake at every test is plain to see;
//   - the proxies outside the automatic groups are tested only when selected or asked for
//     (monitoring on_demand_tags), never in the cycles; the select group keeps every proxy.

// profileURLTestMembers are the proxies the profile's urltest groups choose among, nested groups
// opened up; nil when the profile has no urltest group.
func profileURLTestMembers(outbounds []option.Outbound) map[string]bool {
	groups := map[string][]string{}
	var roots []string
	for _, out := range outbounds {
		switch opts := out.Options.(type) {
		case *option.URLTestOutboundOptions:
			groups[out.Tag] = opts.Outbounds
			roots = append(roots, out.Tag)
		case *option.SelectorOutboundOptions:
			groups[out.Tag] = opts.Outbounds
		}
	}
	if len(roots) == 0 {
		return nil
	}
	members := map[string]bool{}
	seen := map[string]bool{}
	var walk func(tag string)
	walk = func(tag string) {
		if seen[tag] {
			return
		}
		seen[tag] = true
		if list, isGroup := groups[tag]; isGroup {
			for _, member := range list {
				walk(member)
			}
			return
		}
		members[tag] = true
	}
	for _, root := range roots {
		walk(root)
	}
	return members
}

// udpProxy says whether the proxy carries its traffic over UDP: QUIC or WireGuard.
func udpProxy(typ string, options any) bool {
	switch typ {
	case C.TypeHysteria, C.TypeHysteria2, C.TypeTUIC:
		return true
	}
	if udpEndpointTypes[typ] {
		return true
	}
	var transport *option.V2RayTransportOptions
	switch opts := options.(type) {
	case *option.NaiveOutboundOptions:
		return opts.QUIC
	case *option.VLESSOutboundOptions:
		transport = opts.Transport
	case *option.TrojanOutboundOptions:
		transport = opts.Transport
	case *option.VMessOutboundOptions:
		transport = opts.Transport
	}
	if transport == nil {
		return false
	}
	switch transport.Type {
	case C.V2RayTransportTypeQUIC:
		return true
	case C.V2RayTransportTypeXHTTP:
		// HTTP/3 when the first ALPN is h3, as the XHTTP client decides (decideHTTPVersion); never
		// over REALITY, which always speaks HTTP/2
		wrapper, ok := options.(option.OutboundTLSOptionsWrapper)
		if !ok {
			return false
		}
		tls := wrapper.TakeOutboundTLSOptions()
		if tls == nil || !tls.Enabled || (tls.Reality != nil && tls.Reality.Enabled) {
			return false
		}
		return len(tls.ALPN) > 0 && tls.ALPN[0] == "h3"
	}
	return false
}

// autoGroupTags are the members of lowest and balance among tags (the profile's proxies in their
// order): the profile's urltest members when it has any left, without the UDP proxies (manualOnly);
// when that leaves nothing, the profile's other proxies without the UDP ones, then the UDP ones
// themselves (a profile of UDP proxies only).
func autoGroupTags(tags []string, profileAuto, manualOnly map[string]bool) []string {
	pick := func(from []string, keep func(string) bool) []string {
		var picked []string
		for _, tag := range from {
			if keep(tag) {
				picked = append(picked, tag)
			}
		}
		return picked
	}
	pool := tags
	if len(profileAuto) > 0 {
		if members := pick(tags, func(tag string) bool { return profileAuto[tag] }); len(members) > 0 {
			pool = members
		}
	}
	notUDP := func(tag string) bool { return !manualOnly[tag] }
	if auto := pick(pool, notUDP); len(auto) > 0 {
		return auto
	}
	if auto := pick(tags, notUDP); len(auto) > 0 {
		return auto
	}
	return pool
}

// onDemandProxyTags are the proxies the automatic groups leave out: tested only when selected or
// asked for. None while there are no automatic groups (one proxy).
func onDemandProxyTags(tags, autoTags []string) []string {
	if len(tags) < 2 {
		return nil
	}
	auto := map[string]bool{}
	for _, tag := range autoTags {
		auto[tag] = true
	}
	var onDemand []string
	for _, tag := range tags {
		if !auto[tag] {
			onDemand = append(onDemand, tag)
		}
	}
	return onDemand
}
