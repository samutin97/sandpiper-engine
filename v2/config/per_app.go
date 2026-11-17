package config

import (
	"net/netip"
	"os"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/hiddify/hiddify-core/v2/hutils"
)

// Per-app split tunneling (Android) and the strict filter by connection owner ("leak B").
//
// The app decides which apps the VPN covers (VpnService.Builder addAllowedApplication /
// addDisallowedApplication). An app the VPN does not cover can still send into the tunnel: it
// binds a socket to the TUN interface (SO_BINDTODEVICE needs no privilege since Linux 5.7) and
// learns the VPN server's exit address, or reaches what the user meant to keep away from it.
// Android's getConnectionOwnerUid answers INVALID_UID for such a socket (the VPN does not apply
// to its uid), so the core rejects, before anything else is decided, every flow from the TUN
// whose owner is unknown, and in the per-app modes every flow of an app on the wrong side of the
// list. The owner is looked up (through the app, PlatformInterface.findConnectionOwner) at the
// first packet of a flow: a TCP SYN, a UDP datagram; ICMP has no owner and is rejected.

const (
	PerAppModeOff     = "off"
	PerAppModeInclude = "include"
	PerAppModeExclude = "exclude"
)

// ownUID is the uid of the app the core runs in (on Android, the app's); a variable for tests.
var ownUID = os.Getuid

// minOwnerLookupSDK is Android 10, where ConnectivityManager.getConnectionOwnerUid came.
const minOwnerLookupSDK = 29

// ownerLookupAvailable says whether the platform can tell who owns a TUN flow; a variable for tests.
var ownerLookupAvailable = func() bool {
	return C.IsAndroid && hutils.AndroidSDKInt() >= minOwnerLookupSDK
}

// perAppMode is the per-app mode of the settings, "off" when unset or unknown.
func perAppMode(hopt *HiddifyOptions) string {
	switch hopt.PerAppProxyMode {
	case PerAppModeInclude, PerAppModeExclude:
		return hopt.PerAppProxyMode
	}
	return PerAppModeOff
}

// strictOwnerFilter says whether the owner filter rules go in: Android with the owner lookup, VPN
// mode, unless the user turned it off (per-app-strict false).
func strictOwnerFilter(hopt *HiddifyOptions) bool {
	return hopt.EnableTun && (hopt.PerAppStrict == nil || *hopt.PerAppStrict) && ownerLookupAvailable()
}

// applyPerAppTun puts the per-app list in the TUN, where the Android app reads it
// (TunOptions.includePackage / excludePackage) for VpnService.Builder: one list for both.
func applyPerAppTun(tun *option.TunInboundOptions, hopt *HiddifyOptions) {
	if len(hopt.PerAppProxyList) == 0 {
		return
	}
	switch perAppMode(hopt) {
	case PerAppModeInclude:
		tun.IncludePackage = append(badoption.Listable[string]{}, hopt.PerAppProxyList...)
	case PerAppModeExclude:
		tun.ExcludePackage = append(badoption.Listable[string]{}, hopt.PerAppProxyList...)
	}
}

// tunDNSAddresses are the DNS servers the TUN gives the system: each TUN address + 1, as sing-tun
// computes them.
func tunDNSAddresses(tun *option.TunInboundOptions) []string {
	var addresses []string
	for _, prefix := range tun.Address {
		if next := prefix.Addr().Next(); next.IsValid() && prefix.Contains(next) {
			addresses = append(addresses, netip.PrefixFrom(next, next.BitLen()).String())
		}
	}
	return addresses
}

// ownerFilterRules are the route rules of the strict filter, to go first. tun is the TUN inbound.
func ownerFilterRules(hopt *HiddifyOptions, tun *option.TunInboundOptions) []option.Rule {
	mode := perAppMode(hopt)
	reject := option.RuleAction{
		Action:        C.RuleActionTypeReject,
		RejectOptions: option.RejectActionOptions{Method: C.RuleActionRejectMethodDefault},
	}
	fromTun := option.Rule{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{
		RawDefaultRule: option.RawDefaultRule{Inbound: badoption.Listable[string]{InboundTUNTag}},
	}}
	ownerUnknown := option.Rule{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{
		RawDefaultRule: option.RawDefaultRule{UserIDRange: badoption.Listable[string]{"0:2147483647"}, Invert: true},
	}}
	ownerKnown := option.Rule{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{
		RawDefaultRule: option.RawDefaultRule{UserIDRange: badoption.Listable[string]{"0:2147483647"}},
	}}
	and := func(rules ...option.Rule) option.Rule {
		return option.Rule{Type: C.RuleTypeLogical, LogicalOptions: option.LogicalRule{
			RawLogicalRule: option.RawLogicalRule{Mode: C.LogicalTypeAnd, Rules: rules},
			RuleAction:     reject,
		}}
	}

	// In the include mode the system resolver (netd, uid 0 or 1051) is not of the VPN, and asks
	// the TUN's DNS server for the apps that are: not its DNS queries. Elsewhere it is of the VPN,
	// found, and needs no exception.
	var notTunDNS []option.Rule
	if mode == PerAppModeInclude {
		if dns := tunDNSAddresses(tun); len(dns) > 0 {
			notTunDNS = append(notTunDNS, option.Rule{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{IPCIDR: prefixables(dns), Port: badoption.Listable[uint16]{53}, Invert: true},
			}})
		}
	}

	rules := []option.Rule{and(append([]option.Rule{fromTun, ownerUnknown}, notTunDNS...)...)}
	list := badoption.Listable[string](hopt.PerAppProxyList)
	switch {
	case mode == PerAppModeInclude && len(list) > 0:
		notListed := option.Rule{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{PackageName: list, Invert: true},
		}}
		conditions := []option.Rule{fromTun, ownerKnown, notListed}
		// the app itself is inside its VPN now (it protects the sockets that carry the tunnel,
		// H-02) and adds itself to the allowed apps; its own requests are not "unlisted"
		if uid := ownUID(); uid >= 0 {
			conditions = append(conditions, option.Rule{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{UserID: badoption.Listable[int32]{int32(uid)}, Invert: true},
			}})
		}
		rules = append(rules, and(append(conditions, notTunDNS...)...))
	case mode == PerAppModeExclude && len(list) > 0:
		listed := option.Rule{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{PackageName: list},
		}}
		rules = append(rules, and(fromTun, listed))
	}
	return rules
}

// tunInboundOptions is the TUN inbound of options, nil without one.
func tunInboundOptions(options *option.Options) *option.TunInboundOptions {
	for _, inbound := range options.Inbounds {
		if inbound.Type == C.TypeTun {
			if tun, ok := inbound.Options.(*option.TunInboundOptions); ok {
				return tun
			}
		}
	}
	return nil
}
