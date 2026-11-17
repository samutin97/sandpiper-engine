package config

import (
	"net/netip"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// ruleCovers says whether a default rule's ip_cidr contains address.
func ruleCovers(rule option.Rule, address netip.Addr) bool {
	for _, item := range rule.DefaultOptions.IPCIDR {
		if item != nil && item.Build(netip.Prefix{}).Contains(address) {
			return true
		}
	}
	return false
}

// SP3-06: the system's DNS-over-TLS probe of the TUN's DNS server (<gw>:853) and a probe to the TUN's
// own subnet left on the physical network by the LAN bypass. Now DNS there is the core's, the rest
// is refused, before the LAN rule; the LAN itself still goes direct.
func TestTunSubnetStaysOnTheDevice(t *testing.T) {
	for _, settings := range []string{
		`{"enable-tun":true,"bypass-lan":true,"tun-address-seed":"install-a"}`,
		`{"enable-tun":true,"bypass-lan":true}`,
		`{"enable-tun":true,"bypass-lan":false,"tun-address-seed":"install-b"}`,
	} {
		options := buildPerApp(t, settings)
		tun := tunInboundOptions(options)
		if tun == nil {
			t.Fatalf("%s: no TUN", settings)
		}
		rules := options.Route.Rules
		find := func(match func(option.Rule) bool) int {
			for i, rule := range rules {
				if rule.Type == C.RuleTypeDefault && match(rule) {
					return i
				}
			}
			return -1
		}
		for _, prefix := range tun.Address {
			gateway := prefix.Addr().Next() // the TUN's DNS server
			hijack := find(func(rule option.Rule) bool {
				return ruleCovers(rule, gateway) && rule.DefaultOptions.Action == C.RuleActionTypeHijackDNS &&
					len(rule.DefaultOptions.Port) == 1 && rule.DefaultOptions.Port[0] == 53
			})
			reject := find(func(rule option.Rule) bool {
				return ruleCovers(rule, gateway) && rule.DefaultOptions.Action == C.RuleActionTypeReject && len(rule.DefaultOptions.Port) == 0
			})
			private := find(func(rule option.Rule) bool {
				return rule.DefaultOptions.IPIsPrivate && rule.DefaultOptions.RouteOptions.Outbound == OutboundDirectTag
			})
			sniff := find(func(rule option.Rule) bool { return rule.DefaultOptions.Action == C.RuleActionTypeSniff })
			if hijack < 0 || reject < 0 || hijack > reject {
				t.Fatalf("%s %v: DNS hijack %d, reject %d", settings, prefix, hijack, reject)
			}
			if private >= 0 && reject > private {
				t.Fatalf("%s %v: the TUN subnet rule %d after the LAN rule %d", settings, prefix, reject, private)
			}
			if reject > sniff {
				t.Fatalf("%s %v: refused only after the sniff (%d > %d)", settings, prefix, reject, sniff)
			}
			// a LAN address is not the TUN's
			lan := netip.MustParseAddr("192.168.1.10")
			if ruleCovers(rules[reject], lan) {
				t.Fatalf("%s: the LAN is refused too", settings)
			}
		}
		if settings == `{"enable-tun":true,"bypass-lan":true,"tun-address-seed":"install-a"}` &&
			find(func(rule option.Rule) bool {
				return rule.DefaultOptions.IPIsPrivate && rule.DefaultOptions.RouteOptions.Outbound == OutboundDirectTag
			}) < 0 {
			t.Fatal("the LAN bypass is gone")
		}
	}
	// no TUN (proxy mode): no such rules
	options := buildPerApp(t, `{"enable-tun":false,"bypass-lan":true}`)
	if tunInboundOptions(options) != nil {
		t.Fatal("a TUN in proxy mode")
	}
}
