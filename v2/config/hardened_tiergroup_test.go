package config

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

// tierSettings are the app's settings with a policy for the panel subscription (made up).
func tierSettings(t *testing.T, policy string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"enable-tun": true,
		"tier-policy": map[string]string{
			"policy": policy, "probe-host": "sub.example.net", "probe-path": "/files/sample.bin",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const panelPolicy = "v=1;n=2:545:main;n=3:545:main;n=1:544:compact;n=4:444:compact;n=9:335:udp;" +
	"t=auto:2,3;t=auto:1,4;t=fallback:5,6,7;t=last-resort,confirm:9;t=manual:8"

func TestTierGroupFollowsThePolicy(t *testing.T) {
	options := buildPanelProfile(t, panelSubscription, tierSettings(t, panelPolicy))
	members := tieredMembers(options)
	want := []string{"2 gRPC B", "3 XHTTP", "1 gRPC A", "4 XHTTP B", "5 Naive", "6 Reality gRPC", "7 Reality XHTTP", "9 UDP HTTP3"}
	if !slices.Equal(members, want) {
		t.Fatalf("tiered = %q, want %q", members, want)
	}
	selector := selectorItems(options)
	if selector[0] != OutboundTieredTag || !slices.Contains(selector, OutboundURLTestTag) || !slices.Contains(selector, "8 UDP Hysteria2") {
		t.Fatalf("select = %q", selector)
	}
	for _, out := range options.Outbounds {
		if out.Tag == OutboundSelectTag && out.Options.(*option.SelectorOutboundOptions).Default != OutboundTieredTag {
			t.Fatalf("select starts on %q", out.Options.(*option.SelectorOutboundOptions).Default)
		}
		if out.Tag == OutboundTieredTag && !out.Options.(*option.SelectorOutboundOptions).InterruptExistConnections {
			t.Fatal("the tiered group keeps the connections of a proxy it left")
		}
	}
	// the automatic groups are as before
	if got := groupMembers(options, OutboundURLTestTag); !slices.Equal(got, []string{"1 gRPC A", "2 gRPC B", "3 XHTTP", "4 XHTTP B"}) {
		t.Fatalf("lowest = %q", got)
	}
	hopts := chainTestOptions(t, tierSettings(t, panelPolicy))
	plan := TierPlan(options, hopts)
	if plan == nil || !slices.Equal(plan.Tags(), want) || !plan.Candidates[7].UDP || plan.Candidates[0].UDP {
		t.Fatalf("plan %+v", plan)
	}
}

// No policy, garbage, an empty one, or one that names no proxy of the profile: as in sp.4.
func TestNoTierGroupWithoutAUsablePolicy(t *testing.T) {
	for _, settings := range []string{
		`{"enable-tun":true}`,
		tierSettings(t, "v=1;t=auto:2,3;garbage"),
		tierSettings(t, "v=1"),
		tierSettings(t, "v=1;t=auto:77,78"),
		tierSettings(t, "v=2;t=auto:2"),
	} {
		options := buildPanelProfile(t, panelSubscription, settings)
		if members := tieredMembers(options); members != nil {
			t.Fatalf("%s: tiered group %q", settings, members)
		}
		selector := selectorItems(options)
		if selector[0] != OutboundURLTestTag {
			t.Fatalf("%s: select = %q", settings, selector)
		}
		for _, out := range options.Outbounds {
			if out.Tag == OutboundSelectTag && out.Options.(*option.SelectorOutboundOptions).Default != OutboundURLTestTag {
				t.Fatalf("%s: select starts on %q", settings, out.Options.(*option.SelectorOutboundOptions).Default)
			}
		}
	}
}

// A profile's own outbound called "tiered" can not take the group's place.
func TestTheTieredTagIsReserved(t *testing.T) {
	profile := strings.Replace(panelSubscription, `"tag":"5 Naive"`, `"tag":"tiered"`, 1)
	profile = strings.Replace(profile, `"5 Naive",`, `"tiered",`, 1)
	options := buildPanelProfile(t, profile, tierSettings(t, panelPolicy))
	count := 0
	for _, out := range options.Outbounds {
		if out.Tag == OutboundTieredTag {
			count++
			if out.Type != "selector" {
				t.Fatalf("the profile's %s outbound took the tag", out.Type)
			}
		}
	}
	if count != 1 {
		t.Fatalf("%d outbounds tagged tiered", count)
	}
}

func TestProbeHostAndPath(t *testing.T) {
	for host, ok := range map[string]bool{
		"sub.example.net": true, "192.0.2.1": true, "2001:db8::1": true, "a-b.example": true,
		"": false, "sub.example.net:443": false, "https://sub.example.net": false, "a..b": false,
		"-a.example": false, "a_b.example": false, "sub.example.net/x": false, "user@sub.example.net": false,
	} {
		if ValidProbeHost(host) != ok {
			t.Errorf("host %q: %v", host, !ok)
		}
	}
	for path, ok := range map[string]bool{
		"/files/sample.bin": true, "/a/b%20c": true, "/": true,
		"": false, "files": false, "//x": false, "/a/../b": false, "/a/./b": false, "/a?b": false,
		"/a#b": false, "/a b": false, "/a\\b": false, "/a%2": false, "/" + strings.Repeat("a", 256): false,
	} {
		if ValidProbePath(path) != ok {
			t.Errorf("path %q: %v", path, !ok)
		}
	}
}

func tieredMembers(options *option.Options) []string {
	for _, out := range options.Outbounds {
		if out.Tag == OutboundTieredTag {
			if s, ok := out.Options.(*option.SelectorOutboundOptions); ok {
				return s.Outbounds
			}
		}
	}
	return nil
}

// SP5-02: an AmneziaWG endpoint outside the automatic groups (a reserve, the last resort) is lazy:
// nothing talks to its server until a connection or a test goes through it, and it closes again when
// idle. In the automatic groups (asked for), it runs as before.
func TestQuietTunnelsAreLazy(t *testing.T) {
	profile := `{"outbounds":[
	 {"type":"vless","tag":"1 v","server":"192.0.2.10","server_port":443,"uuid":"00000000-0000-4000-8000-000000000001","tls":{"enabled":true,"server_name":"example.com"}},
	 {"type":"vless","tag":"2 v","server":"192.0.2.11","server_port":443,"uuid":"00000000-0000-4000-8000-000000000002","tls":{"enabled":true,"server_name":"example.com"}}],
	 "endpoints":[` + strings.Replace(awgEndpointJSON, `"tag":"AWG 990"`, `"tag":"10 AWG"`, 1) + `]}`
	for _, settings := range []string{`{"enable-tun":true}`, tierSettings(t, "v=1;t=auto:1,2;t=last-resort,confirm:10")} {
		options := buildPanelProfile(t, profile, settings)
		if len(options.Endpoints) != 1 || !options.Endpoints[0].Lazy {
			t.Fatalf("%s: the AWG endpoint is not lazy", settings)
		}
	}
	options := buildPanelProfile(t, profile, `{"enable-tun":true,"udp-endpoints-in-auto":true}`)
	if options.Endpoints[0].Lazy {
		t.Fatal("an AWG endpoint in the automatic groups is lazy")
	}
}
