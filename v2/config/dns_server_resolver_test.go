package config

import (
	"slices"
	"testing"
)

func TestServerDNSAddresses(t *testing.T) {
	cases := map[string][]string{
		"": nil,
		"https://1.1.1.1/dns-query,https://9.9.9.9/dns-query, https://8.8.8.8/dns-query": {
			"https://1.1.1.1/dns-query", "https://9.9.9.9/dns-query", "https://8.8.8.8/dns-query", "local",
		},
		"local":   {"local"},
		"1.1.1.1": {"udp://1.1.1.1", "local"},
		"https://1.1.1.1/dns-query,local,https://1.1.1.1/dns-query": {"https://1.1.1.1/dns-query", "local"},
	}
	for value, want := range cases {
		if got := serverDNSAddresses(value); !slices.Equal(got, want) {
			t.Errorf("serverDNSAddresses(%q) = %v, want %v", value, got, want)
		}
	}
}

func TestServerNamesResolver(t *testing.T) {
	if got := serverNamesResolver(&HiddifyOptions{}); got != DNSMultiDirectTag {
		t.Errorf("without server-dns-address: %s", got)
	}
	opt := &HiddifyOptions{}
	opt.ServerDnsAddress = "https://1.1.1.1/dns-query"
	if got := serverNamesResolver(opt); got != DNSServerNamesTag {
		t.Errorf("with server-dns-address: %s", got)
	}
}
