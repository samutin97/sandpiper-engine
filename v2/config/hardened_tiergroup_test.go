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
	if !slices.Equal(members, append(slices.Clone(want), OutboundTieredWaitTag)) {
		t.Fatalf("tiered = %q, want %q and the wait", members, want)
	}
	if got := tieredDefault(options); got != "2 gRPC B" {
		t.Fatalf("the tiered group starts on %q", got)
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

func tieredDefault(options *option.Options) string {
	for _, out := range options.Outbounds {
		if out.Tag == OutboundTieredTag {
			return out.Options.(*option.SelectorOutboundOptions).Default
		}
	}
	return ""
}

func onDemandTags(options *option.Options) []string {
	if options.Experimental == nil || options.Experimental.Monitoring == nil {
		return nil
	}
	return options.Experimental.Monitoring.OnDemandTags
}

// The group never starts on a last resort that waits for the user's agreement: on the first proxy
// that needs none, on the wait (a block outbound, hidden) when there is none, whatever the order of
// the tiers or the proxies the policy names that are gone. The wait carries nothing.
func TestTierGroupNeverStartsOnALastResort(t *testing.T) {
	for policy, start := range map[string]string{
		"v=1;t=auto:77;t=last-resort,confirm:9":               OutboundTieredWaitTag, // the proxies above are gone
		"v=1;t=last-resort,confirm:9;t=auto:2,3":              "2 gRPC B",            // the last resort listed first
		"v=1;t=last-resort,confirm:9;t=last-resort:5":         "5 Naive",             // a last resort without confirm
		"v=1;t=auto:@9%20UDP%20HTTP3;t=last-resort,confirm:9": OutboundTieredWaitTag, // an alias
	} {
		options := buildPanelProfile(t, panelSubscription, tierSettings(t, policy))
		if got := tieredDefault(options); got != start {
			t.Fatalf("%s: starts on %q, want %q", policy, got, start)
		}
		found := false
		for _, out := range options.Outbounds {
			if out.Tag == OutboundTieredWaitTag {
				found = out.Type == "block"
			}
		}
		if !found {
			t.Fatalf("%s: no block outbound for the wait", policy)
		}
		if plan := TierPlan(options, chainTestOptions(t, tierSettings(t, policy))); plan == nil || !slices.Contains(plan.Reserves(), "9 UDP HTTP3") {
			t.Fatalf("%s: plan %+v", policy, plan)
		}
	}
}

// A last resort that waits for the agreement is in no automatic group and is not in the monitoring's
// cycles, whatever the settings: a TCP one, and a UDP one with UDP endpoints in the automatic groups.
func TestTierReserveOutOfTheAutomaticGroups(t *testing.T) {
	for _, c := range []struct{ settings, reserve string }{
		{tierSettings(t, "v=1;t=auto:2,3;t=last-resort,confirm:1"), "1 gRPC A"},
		{strings.Replace(tierSettings(t, "v=1;t=auto:2,3;t=last-resort,confirm:9"), "{", `{"udp-endpoints-in-auto":true,`, 1), "9 UDP HTTP3"},
	} {
		options := buildPanelProfile(t, panelSubscription, c.settings)
		for _, group := range []string{OutboundURLTestTag, OutboundRoundRobinTag} {
			if members := groupMembers(options, group); slices.Contains(members, c.reserve) || len(members) == 0 {
				t.Fatalf("%s: %s = %q", c.reserve, group, members)
			}
		}
		if !slices.Contains(onDemandTags(options), c.reserve) {
			t.Fatalf("%s: on demand %q", c.reserve, onDemandTags(options))
		}
	}
	// the same proxy without confirm stays where it was
	options := buildPanelProfile(t, panelSubscription, tierSettings(t, "v=1;t=auto:2,3;t=last-resort:1"))
	if !slices.Contains(groupMembers(options, OutboundURLTestTag), "1 gRPC A") {
		t.Fatalf("lowest = %q", groupMembers(options, OutboundURLTestTag))
	}
}

// The core's plan is the group's own: bound once, to the profile's proxies. A number two proxies
// start with names none, among the profile's proxies as among the group's members (where it named
// one), so a last resort named by its full name stays one that waits for the agreement.
func TestTierPlanIsTheGroups(t *testing.T) {
	profile := strings.ReplaceAll(panelSubscription, `"5 Naive"`, `"10 Juliet"`)
	profile = strings.ReplaceAll(profile, `"6 Reality gRPC"`, `"10 Kilo"`)
	policy := "v=1;t=auto:2,3;t=fallback:7,10;t=last-resort,confirm:@10%20Juliet"
	options := buildPanelProfile(t, profile, tierSettings(t, policy))
	plan := TierPlan(options, chainTestOptions(t, tierSettings(t, policy)))
	if plan == nil {
		t.Fatal("no plan")
	}
	if !slices.Equal(append(plan.Tags(), OutboundTieredWaitTag), tieredMembers(options)) {
		t.Fatalf("plan %q, group %q", plan.Tags(), tieredMembers(options))
	}
	if !slices.Equal(plan.Reserves(), []string{"10 Juliet"}) {
		t.Fatalf("reserves %q in %+v", plan.Reserves(), plan.Candidates)
	}
	for _, c := range plan.Candidates {
		if c.Tag == "10 Juliet" && (c.Mode != "last-resort" || !c.Confirm) {
			t.Fatalf("10 Juliet: %+v", c)
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
	// a last resort that waits for the agreement is never in them, so it stays lazy
	settings := strings.Replace(tierSettings(t, "v=1;t=auto:1,2;t=last-resort,confirm:10"), "{", `{"udp-endpoints-in-auto":true,`, 1)
	if options := buildPanelProfile(t, profile, settings); !options.Endpoints[0].Lazy {
		t.Fatal("the last resort's AWG endpoint is not lazy with UDP endpoints in the automatic groups")
	}
}
