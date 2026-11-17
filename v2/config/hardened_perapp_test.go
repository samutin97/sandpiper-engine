package config

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route/rule"
	M "github.com/sagernet/sing/common/metadata"
)

// withOwnerLookup builds as on Android 10+.
func withOwnerLookup(t *testing.T) {
	t.Helper()
	old := ownerLookupAvailable
	ownerLookupAvailable = func() bool { return true }
	t.Cleanup(func() { ownerLookupAvailable = old })
}

func buildPerApp(t *testing.T, settings string) *option.Options {
	t.Helper()
	options, err := BuildConfig(libbox.BaseContext(nil), chainTestOptions(t, settings), &ReadOptions{Content: oneProxyProfile})
	if err != nil {
		t.Fatal(err)
	}
	return options
}

// rejectRules are the first route rules that reject, as the router runs them.
func rejectRules(t *testing.T, options *option.Options) []adapter.Rule {
	t.Helper()
	var rules []adapter.Rule
	for _, r := range options.Route.Rules {
		if r.Type != C.RuleTypeLogical || r.LogicalOptions.Action != C.RuleActionTypeReject {
			break
		}
		built, err := rule.NewRule(libbox.BaseContext(nil), log.NewNOPFactory().NewLogger("test"), r, false)
		if err != nil {
			t.Fatal(err)
		}
		rules = append(rules, built)
	}
	return rules
}

type flow struct {
	name    string
	inbound string
	owner   *adapter.ConnectionOwner
	dst     string
	reject  bool
}

func checkFlows(t *testing.T, rules []adapter.Rule, flows []flow) {
	t.Helper()
	for _, f := range flows {
		md := &adapter.InboundContext{Inbound: f.inbound, ProcessInfo: f.owner, Network: "udp"}
		dst := netip.MustParseAddrPort(f.dst)
		md.Destination = M.SocksaddrFromNetIP(dst)
		rejected := false
		for _, r := range rules {
			md.ResetRuleCache()
			if r.Match(md) {
				rejected = true
				break
			}
		}
		if rejected != f.reject {
			t.Errorf("%s: rejected=%v, want %v", f.name, rejected, f.reject)
		}
	}
}

var (
	unknownOwner = &adapter.ConnectionOwner{UserId: -1}
	netd         = &adapter.ConnectionOwner{UserId: 1051}
	browser      = &adapter.ConnectionOwner{UserId: 10100, PackageNames: []string{"org.mozilla.firefox"}}
	bank         = &adapter.ConnectionOwner{UserId: 10200, PackageNames: []string{"ru.bank.app"}}
)

// The default (no per-app list, the settings of an older app): only an unknown owner is rejected.
func TestOwnerFilterRejectsUnknownOwners(t *testing.T) {
	withOwnerLookup(t)
	options := buildPerApp(t, `{"enable-tun":true}`)
	if err := libbox.CheckConfigOptions(options); err != nil {
		t.Fatalf("sing-box rejected the config: %v", err)
	}
	rules := rejectRules(t, options)
	if len(rules) != 1 {
		t.Fatalf("%d reject rules", len(rules))
	}
	checkFlows(t, rules, []flow{
		{"excluded app bound to tun0", InboundTUNTag, unknownOwner, "203.0.113.1:443", true},
		{"no lookup / ICMP", InboundTUNTag, nil, "203.0.113.1:443", true},
		{"netd DNS", InboundTUNTag, netd, "172.19.0.2:53", false},
		{"an app in the VPN", InboundTUNTag, browser, "203.0.113.1:443", false},
		{"LAN sharing client (not the TUN)", InboundLanSharingTag + "::", nil, "203.0.113.1:443", false},
	})
}

func TestOwnerFilterIncludeMode(t *testing.T) {
	withOwnerLookup(t)
	oldUID := ownUID
	ownUID = func() int { return 10300 }
	t.Cleanup(func() { ownUID = oldUID })
	options := buildPerApp(t, `{"enable-tun":true,"per-app-proxy-mode":"include","per-app-proxy-list":["org.mozilla.firefox"]}`)
	tun := tunInboundOptions(options)
	if len(tun.IncludePackage) != 1 || tun.IncludePackage[0] != "org.mozilla.firefox" || len(tun.ExcludePackage) != 0 {
		t.Fatalf("TUN lists %v %v", tun.IncludePackage, tun.ExcludePackage)
	}
	rules := rejectRules(t, options)
	if len(rules) != 2 {
		t.Fatalf("%d reject rules", len(rules))
	}
	checkFlows(t, rules, []flow{
		{"listed app", InboundTUNTag, browser, "203.0.113.1:443", false},
		{"unlisted app bound to tun0 (INVALID_UID)", InboundTUNTag, unknownOwner, "203.0.113.1:443", true},
		{"unlisted app found anyway", InboundTUNTag, bank, "203.0.113.1:443", true},
		{"netd asking the TUN DNS for a listed app", InboundTUNTag, unknownOwner, "172.19.0.2:53", false},
		{"netd, IPv6 TUN DNS", InboundTUNTag, unknownOwner, "[fdfe:dcba:9876::2]:53", false},
		{"unknown owner to another DNS server", InboundTUNTag, unknownOwner, "8.8.8.8:53", true},
		{"the app itself, inside its VPN (H-02)", InboundTUNTag, &adapter.ConnectionOwner{UserId: 10300, PackageNames: []string{"app.sandpiperbird"}}, "203.0.113.1:443", false},
	})
}

func TestOwnerFilterExcludeMode(t *testing.T) {
	withOwnerLookup(t)
	options := buildPerApp(t, `{"enable-tun":true,"per-app-proxy-mode":"exclude","per-app-proxy-list":["ru.bank.app"]}`)
	tun := tunInboundOptions(options)
	if len(tun.ExcludePackage) != 1 || len(tun.IncludePackage) != 0 {
		t.Fatalf("TUN lists %v %v", tun.IncludePackage, tun.ExcludePackage)
	}
	checkFlows(t, rejectRules(t, options), []flow{
		{"excluded app bound to tun0", InboundTUNTag, unknownOwner, "203.0.113.1:443", true},
		{"excluded app found anyway", InboundTUNTag, bank, "203.0.113.1:443", true},
		{"other app", InboundTUNTag, browser, "203.0.113.1:443", false},
		{"netd DNS", InboundTUNTag, netd, "172.19.0.2:53", false},
		{"root daemon", InboundTUNTag, &adapter.ConnectionOwner{UserId: 0}, "203.0.113.1:123", false},
	})
}

func TestOwnerFilterOffCases(t *testing.T) {
	withOwnerLookup(t)
	for _, settings := range []string{
		`{"enable-tun":true,"per-app-strict":false}`,
		`{"enable-tun":false}`,
	} {
		if rules := rejectRules(t, buildPerApp(t, settings)); len(rules) != 0 {
			t.Fatalf("%s: %d reject rules", settings, len(rules))
		}
	}
	ownerLookupAvailable = func() bool { return false } // Android 9 or older, the desktop
	if rules := rejectRules(t, buildPerApp(t, `{"enable-tun":true}`)); len(rules) != 0 {
		t.Fatalf("without the owner lookup: %d reject rules", len(rules))
	}
}
