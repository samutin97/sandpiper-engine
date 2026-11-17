package config

import (
	"slices"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

func groupMembers(options *option.Options, tag string) []string {
	for _, out := range options.Outbounds {
		if out.Tag == tag {
			if b, ok := out.Options.(*option.BalancerOutboundOptions); ok {
				return b.Outbounds
			}
		}
	}
	return nil
}

// The settings of v5.9.8 (10 minutes, no workers) still give the quiet monitoring.
func TestMonitoringIsQuiet(t *testing.T) {
	options := buildPerApp(t, `{"enable-tun":true,"url-test-interval":600}`)
	m := options.Experimental.Monitoring
	if m.Workers != 2 || time.Duration(m.Interval) != 10*time.Minute || !m.DisableIPInfo || m.RetestOnNetworkChange != "selected" {
		t.Fatalf("monitoring %+v", m)
	}
	if !slices.Contains(m.ExcludeTypes, C.TypeDirect) || !slices.Contains(m.OnDemandTypes, C.TypeAwg) {
		t.Fatalf("types %v %v", m.ExcludeTypes, m.OnDemandTypes)
	}
	defaults := buildPerApp(t, `{}`).Experimental.Monitoring
	if time.Duration(defaults.Interval) != 30*time.Minute {
		t.Fatalf("default interval %v", defaults.Interval)
	}
	if time.Duration(buildPerApp(t, `{"url-test-interval":30}`).Experimental.Monitoring.Interval) != 5*time.Minute {
		t.Fatal("interval under 5 minutes")
	}
	asked := buildPerApp(t, `{"ipinfo":true,"monitoring-workers":9,"retest-on-network-change":"all"}`).Experimental.Monitoring
	if asked.DisableIPInfo || asked.Workers != 4 || asked.RetestOnNetworkChange != "all" {
		t.Fatalf("asked %+v", asked)
	}
}

// An AmneziaWG endpoint among TCP proxies: in select, not in the automatic groups, quiet until used.
func TestAwgEndpointIsManualAndQuiet(t *testing.T) {
	profile := `{"outbounds":[
	 {"type":"vless","tag":"v1","server":"192.0.2.10","server_port":443,"uuid":"00000000-0000-4000-8000-000000000001","tls":{"enabled":true,"server_name":"example.com"}},
	 {"type":"vless","tag":"v2","server":"192.0.2.11","server_port":443,"uuid":"00000000-0000-4000-8000-000000000002","tls":{"enabled":true,"server_name":"example.com"}}],
	 "endpoints":[` + awgEndpointJSON + `]}`
	options, err := BuildConfig(libbox.BaseContext(nil), chainTestOptions(t, `{"enable-tun":true}`), &ReadOptions{Content: profile})
	if err != nil {
		t.Fatal(err)
	}
	if err := libbox.CheckConfigOptions(options); err != nil {
		t.Fatalf("sing-box rejected the config: %v", err)
	}
	if !slices.Contains(selectorItems(options), "AWG 990") {
		t.Fatalf("select %v", selectorItems(options))
	}
	for _, group := range []string{OutboundURLTestTag, OutboundRoundRobinTag} {
		if members := groupMembers(options, group); slices.Contains(members, "AWG 990") || len(members) != 2 {
			t.Fatalf("%s: %v", group, members)
		}
	}
	for _, out := range options.Outbounds {
		if out.Tag == OutboundSelectTag && out.Options.(*option.SelectorOutboundOptions).Default != OutboundURLTestTag {
			t.Fatalf("default %q, want lowest", out.Options.(*option.SelectorOutboundOptions).Default)
		}
	}
	awg := options.Endpoints[0].Options.(*option.AwgEndpointOptions)
	if !awg.KeepaliveOnUse || awg.MTUDiscovery == nil || *awg.MTUDiscovery {
		t.Fatalf("keepalive_on_use %v mtu_discovery %v", awg.KeepaliveOnUse, awg.MTUDiscovery)
	}
	// asked for: in the automatic groups
	options, _ = BuildConfig(libbox.BaseContext(nil), chainTestOptions(t, `{"udp-endpoints-in-auto":true}`), &ReadOptions{Content: profile})
	if !slices.Contains(groupMembers(options, OutboundURLTestTag), "AWG 990") || len(options.Experimental.Monitoring.OnDemandTypes) != 0 {
		t.Fatal("udp-endpoints-in-auto")
	}
}
