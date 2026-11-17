package config

import (
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// tunSubnetRules keep what is sent to the TUN's own subnets (the /30 and /126 of its addresses, or
// the defaults) on the device. The system sends there its DNS (the TUN's DNS server, the address
// after the TUN's) and its probes of that server (private DNS on port 853, pings). With the LAN
// bypassed such a flow matched the private-address rule and left by the direct outbound on the
// physical network, to an address that is nobody's there; without it, it went to the proxy server.
// DNS (port 53) to them is answered by the core, as any DNS caught in the TUN; the rest is refused
// at once, so a probe fails fast instead of timing out. Other private addresses (the LAN) are not
// touched.
func tunSubnetRules(tun *option.TunInboundOptions) []option.Rule {
	var subnets []string
	for _, address := range tun.Address {
		subnets = append(subnets, address.Masked().String())
	}
	if len(subnets) == 0 {
		return nil
	}
	return []option.Rule{
		{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{IPCIDR: prefixables(subnets), Port: []uint16{53}},
				RuleAction:     option.RuleAction{Action: C.RuleActionTypeHijackDNS},
			},
		},
		{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{IPCIDR: prefixables(subnets)},
				RuleAction: option.RuleAction{
					Action:        C.RuleActionTypeReject,
					RejectOptions: option.RejectActionOptions{Method: C.RuleActionRejectMethodDefault},
				},
			},
		},
	}
}
