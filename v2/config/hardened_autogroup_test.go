package config

import (
	"slices"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

// panelSubscription is a subscription in the sing-box format of the panel (Hiddify Manager), the
// way the server gives its nine variants: a selector of everything, its own urltest group of the
// main ones (here with the HTTP/3 one in it too), and the direct/block/dns outbounds. Made-up
// UUIDs, keys and hosts (RFC 5737 addresses, example.* names).
const panelSubscription = `{"outbounds":[
 {"type":"selector","tag":"Select","outbounds":["Auto","1 gRPC A","2 gRPC B","3 XHTTP","4 XHTTP B","5 Naive","6 Reality gRPC","7 Reality XHTTP","8 UDP Hysteria2","9 UDP HTTP3"],"default":"Auto"},
 {"type":"urltest","tag":"Auto","outbounds":["1 gRPC A","2 gRPC B","3 XHTTP","4 XHTTP B","9 UDP HTTP3"],"url":"https://www.gstatic.com/generate_204","interval":"10m","tolerance":200},
 {"type":"vless","tag":"1 gRPC A","server":"192.0.2.10","server_port":443,"uuid":"00000000-0000-4000-8000-000000000001",
  "tls":{"enabled":true,"server_name":"vpn.example.net","alpn":["h2"]},"transport":{"type":"grpc","service_name":"svc-a"}},
 {"type":"vless","tag":"2 gRPC B","server":"192.0.2.10","server_port":443,"uuid":"00000000-0000-4000-8000-000000000001",
  "tls":{"enabled":true,"server_name":"vpn.example.net","alpn":["h2"]},"transport":{"type":"grpc","service_name":"svc-b"}},
 {"type":"vless","tag":"3 XHTTP","server":"192.0.2.10","server_port":443,"uuid":"00000000-0000-4000-8000-000000000001",
  "tls":{"enabled":true,"server_name":"vpn.example.net","alpn":["h2"]},
  "transport":{"type":"xhttp","mode":"auto","path":"/x3","host":"vpn.example.net","xmux":{"max_concurrency":"16-32","h_max_reusable_secs":"1800-3000","h_keep_alive_period":0}}},
 {"type":"vless","tag":"4 XHTTP B","server":"192.0.2.10","server_port":443,"uuid":"00000000-0000-4000-8000-000000000001",
  "tls":{"enabled":true,"server_name":"vpn.example.net","alpn":["h2"]},
  "transport":{"type":"xhttp","mode":"packet-up","path":"/x4","host":"vpn.example.net","xmux":{"max_concurrency":"16-32"}}},
 {"type":"naive","tag":"5 Naive","server":"192.0.2.10","server_port":443,"username":"user","password":"not-a-real-password",
  "tls":{"enabled":true,"server_name":"vpn.example.net"}},
 {"type":"vless","tag":"6 Reality gRPC","server":"192.0.2.11","server_port":443,"uuid":"00000000-0000-4000-8000-000000000002",
  "tls":{"enabled":true,"server_name":"www.example.org","utls":{"enabled":true,"fingerprint":"chrome"},
   "reality":{"enabled":true,"public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123abcd"}},
  "transport":{"type":"grpc","service_name":"svc-r"}},
 {"type":"vless","tag":"7 Reality XHTTP","server":"192.0.2.11","server_port":443,"uuid":"00000000-0000-4000-8000-000000000002",
  "tls":{"enabled":true,"server_name":"www.example.org","utls":{"enabled":true,"fingerprint":"chrome"},
   "reality":{"enabled":true,"public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123abcd"}},
  "transport":{"type":"xhttp","mode":"auto","path":"/r7"}},
 {"type":"hysteria2","tag":"8 UDP Hysteria2","server":"192.0.2.10","server_port":8443,"password":"not-a-real-password",
  "tls":{"enabled":true,"server_name":"vpn.example.net","alpn":["h3"]}},
 {"type":"vless","tag":"9 UDP HTTP3","server":"192.0.2.10","server_port":443,"uuid":"00000000-0000-4000-8000-000000000001",
  "tls":{"enabled":true,"server_name":"vpn.example.net","alpn":["h3"]},
  "transport":{"type":"xhttp","mode":"auto","path":"/h3","host":"vpn.example.net"}},
 {"type":"direct","tag":"direct"},
 {"type":"block","tag":"block"},
 {"type":"dns","tag":"dns-out"}
]}`

var panelVariants = []string{"1 gRPC A", "2 gRPC B", "3 XHTTP", "4 XHTTP B", "5 Naive",
	"6 Reality gRPC", "7 Reality XHTTP", "8 UDP Hysteria2", "9 UDP HTTP3"}

// buildPanelProfile imports the subscription as the app does (Parse: sanitizing, the profile kept)
// and builds the config with the settings.
func buildPanelProfile(t *testing.T, profile, settings string) *option.Options {
	t.Helper()
	ctx := libbox.BaseContext(nil)
	hopts := chainTestOptions(t, settings)
	parsed, err := ParseConfig(ctx, &ReadOptions{Content: profile}, false, hopts, false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	options, err := BuildConfig(ctx, hopts, &ReadOptions{Options: parsed})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := libbox.CheckConfigOptions(options); err != nil {
		t.Fatalf("sing-box rejected the config: %v", err)
	}
	return options
}

// D-05: lowest and balance take the subscription's own urltest group, without its UDP proxies; the
// monitoring tests the others only when they are selected or asked for; select keeps every proxy.
func TestAutoGroupsFollowTheSubscription(t *testing.T) {
	options := buildPanelProfile(t, panelSubscription, `{"enable-tun":true}`)
	wantAuto := []string{"1 gRPC A", "2 gRPC B", "3 XHTTP", "4 XHTTP B"}
	for _, group := range []string{OutboundURLTestTag, OutboundRoundRobinTag} {
		if members := groupMembers(options, group); !slices.Equal(members, wantAuto) {
			t.Fatalf("%s = %q, want the profile's Auto without UDP %q", group, members, wantAuto)
		}
	}
	selector := selectorItems(options)
	for _, tag := range append([]string{OutboundURLTestTag, OutboundRoundRobinTag}, panelVariants...) {
		if !slices.Contains(selector, tag) {
			t.Fatalf("select lacks %q: %q", tag, selector)
		}
	}
	for _, tag := range selector {
		if tag == "Auto" || tag == "Select" || tag == "direct" || tag == "block" {
			t.Fatalf("the profile's group or a direct outbound %q in select", tag)
		}
	}
	monitoring := options.Experimental.Monitoring
	wantOnDemand := []string{"5 Naive", "6 Reality gRPC", "7 Reality XHTTP", "8 UDP Hysteria2", "9 UDP HTTP3"}
	if !slices.Equal(monitoring.OnDemandTags, wantOnDemand) {
		t.Fatalf("on_demand_tags = %q, want %q", monitoring.OnDemandTags, wantOnDemand)
	}

	// UDP asked for in auto: the group's HTTP/3 proxy joins; the Hysteria2 one, outside the
	// group, does not
	options = buildPanelProfile(t, panelSubscription, `{"enable-tun":true,"udp-endpoints-in-auto":true}`)
	wantAuto = append(wantAuto, "9 UDP HTTP3")
	if members := groupMembers(options, OutboundURLTestTag); !slices.Equal(members, wantAuto) {
		t.Fatalf("udp-endpoints-in-auto: lowest = %q, want %q", members, wantAuto)
	}
	if got := options.Experimental.Monitoring.OnDemandTags; slices.Contains(got, "9 UDP HTTP3") || !slices.Contains(got, "8 UDP Hysteria2") {
		t.Fatalf("udp-endpoints-in-auto: on_demand_tags = %q", got)
	}
}

// Without a urltest group in the profile: every proxy but the UDP ones, as before for the
// AmneziaWG endpoints, now also for hysteria2 and XHTTP over HTTP/3.
func TestAutoGroupsWithoutAProfileGroup(t *testing.T) {
	profile := strings.Replace(panelSubscription,
		`{"type":"urltest","tag":"Auto","outbounds":["1 gRPC A","2 gRPC B","3 XHTTP","4 XHTTP B","9 UDP HTTP3"],"url":"https://www.gstatic.com/generate_204","interval":"10m","tolerance":200},`, "", 1)
	profile = strings.Replace(profile, `"outbounds":["Auto",`, `"outbounds":[`, 1)
	profile = strings.Replace(profile, `"default":"Auto"`, `"default":"1 gRPC A"`, 1)
	if strings.Contains(profile, `"urltest"`) {
		t.Fatal("the urltest group is still in the profile")
	}
	options := buildPanelProfile(t, profile, `{"enable-tun":true}`)
	want := panelVariants[:7]
	for _, group := range []string{OutboundURLTestTag, OutboundRoundRobinTag} {
		if members := groupMembers(options, group); !slices.Equal(members, want) {
			t.Fatalf("%s = %q, want %q", group, members, want)
		}
	}
	if got := options.Experimental.Monitoring.OnDemandTags; !slices.Equal(got, []string{"8 UDP Hysteria2", "9 UDP HTTP3"}) {
		t.Fatalf("on_demand_tags = %q", got)
	}
	if len(selectorItems(options)) != 2+len(panelVariants) {
		t.Fatalf("select %q", selectorItems(options))
	}
}

// The edges: a urltest group whose members were all dropped (insecure TLS) gives every proxy; a
// group of UDP proxies only gives the other proxies; a profile of UDP proxies only keeps them.
func TestAutoGroupTags(t *testing.T) {
	tags := []string{"a", "b", "h2", "h3"}
	udp := map[string]bool{"h2": true, "h3": true}
	cases := []struct {
		name    string
		profile map[string]bool
		manual  map[string]bool
		want    []string
	}{
		{"no group", nil, udp, []string{"a", "b"}},
		{"group", map[string]bool{"b": true, "h3": true}, udp, []string{"b"}},
		{"group members dropped", map[string]bool{"gone": true}, udp, []string{"a", "b"}},
		{"group of UDP only", map[string]bool{"h2": true, "h3": true}, udp, []string{"a", "b"}},
		{"UDP only", nil, map[string]bool{"a": true, "b": true, "h2": true, "h3": true}, tags},
	}
	for _, c := range cases {
		if got := autoGroupTags(tags, c.profile, c.manual); !slices.Equal(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	nested := profileURLTestMembers([]option.Outbound{
		{Type: "urltest", Tag: "Auto", Options: &option.URLTestOutboundOptions{Outbounds: []string{"a", "Inner"}}},
		{Type: "selector", Tag: "Inner", Options: &option.SelectorOutboundOptions{Outbounds: []string{"b", "Auto"}}},
		{Type: "selector", Tag: "Select", Options: &option.SelectorOutboundOptions{Outbounds: []string{"Auto", "c"}}},
	})
	if len(nested) != 2 || !nested["a"] || !nested["b"] {
		t.Fatalf("nested groups: %v", nested)
	}
	if profileURLTestMembers([]option.Outbound{{Type: "selector", Tag: "Select", Options: &option.SelectorOutboundOptions{Outbounds: []string{"a"}}}}) != nil {
		t.Fatal("a selector alone is not an automatic choice")
	}
	if onDemandProxyTags([]string{"a"}, []string{"a"}) != nil {
		t.Fatal("one proxy: no automatic groups, nothing on demand")
	}
}
