package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

func dnsServer(options *option.Options, tag string) *option.DNSServerOptions {
	for i := range options.DNS.Servers {
		if options.DNS.Servers[i].Tag == tag {
			return &options.DNS.Servers[i]
		}
	}
	return nil
}

// No direct-dns-address from the app: DoH (Yandex's in Russia), then DoT of the same host, then the
// system resolver; never plain DNS to a public resolver, never through the TLS fragment.
func TestDirectDNSIsEncryptedByDefault(t *testing.T) {
	options := buildPerApp(t, `{"region":"ru","enable-tun":true}`)
	if err := libbox.CheckConfigOptions(options); err != nil {
		t.Fatalf("sing-box rejected the config: %v", err)
	}
	direct := dnsServer(options, DNSDirectTag)
	if direct == nil || direct.Type != C.DNSTypeHTTPS {
		t.Fatalf("direct %+v", direct)
	}
	https := direct.Options.(*option.RemoteHTTPSDNSServerOptions)
	if https.Server != "common.dot.dns.yandex.net" || https.Detour != "" {
		t.Fatalf("direct DoH %+v", https)
	}
	group := dnsServer(options, DNSMultiDirectTag).Options.(*option.GroupDNSServerOptions)
	if len(group.Servers) != 3 {
		t.Fatalf("direct group %v", group.Servers)
	}
	for _, tag := range group.Servers[1:] {
		server := dnsServer(options, tag)
		if server.Type == C.DNSTypeUDP || server.Type == C.DNSTypeTCP {
			t.Fatalf("plain DNS member %s: %+v", tag, server)
		}
	}
	if options.DNS.DisableExpire {
		t.Fatal("DNS cache never expires")
	}
	if other := dnsServer(buildPerApp(t, `{}`), DNSDirectTag); other.Type != C.DNSTypeHTTPS || other.Options.(*option.RemoteHTTPSDNSServerOptions).Server != "1.1.1.1" {
		t.Fatalf("other region %+v", other)
	}
	// the user's own choice stays
	if plain := dnsServer(buildPerApp(t, `{"direct-dns-address":"udp://1.1.1.1"}`), DNSDirectTag); plain.Type != C.DNSTypeUDP {
		t.Fatalf("explicit udp: %+v", plain)
	}
}

func TestRussiaDirectFromTheStart(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "geosite-ru.srs"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	options := buildPerApp(t, `{"region":"ru","enable-tun":true,"rule-set-initial-dir":"`+filepath.ToSlash(dir)+`"}`)
	var suffixes []string
	for _, rule := range options.Route.Rules {
		if rule.Type == C.RuleTypeDefault && len(rule.DefaultOptions.DomainSuffix) > 0 {
			suffixes = rule.DefaultOptions.DomainSuffix
		}
	}
	for _, want := range []string{".ru", ".su", ".xn--p1ai", ".moscow"} {
		if !slices.Contains(suffixes, want) {
			t.Fatalf("%s missing from %v", want, suffixes)
		}
	}
	for _, rs := range options.Route.RuleSet {
		if rs.RemoteOptions.DownloadDetour != OutboundSelectTag {
			t.Fatalf("rule-set %v downloads around the VPN", rs.Tag)
		}
		if rs.Tag[0] == "geosite-ru" && rs.RemoteOptions.InitialPath == "" {
			t.Fatal("no initial path for geosite-ru")
		}
		if rs.Tag[0] == "geoip-ru" && rs.RemoteOptions.InitialPath != "" {
			t.Fatal("initial path of a missing file")
		}
	}
}
