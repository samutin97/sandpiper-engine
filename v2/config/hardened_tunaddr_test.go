package config

import (
	"testing"
)

func TestTunAddressSeed(t *testing.T) {
	def := tunInboundOptions(buildPerApp(t, `{"enable-tun":true}`))
	if def.Address[0].String() != "172.19.0.1/28" {
		t.Fatalf("default %v", def.Address)
	}
	a := tunInboundOptions(buildPerApp(t, `{"enable-tun":true,"tun-address-seed":"install-a"}`))
	b := tunInboundOptions(buildPerApp(t, `{"enable-tun":true,"tun-address-seed":"install-b"}`))
	again := tunInboundOptions(buildPerApp(t, `{"enable-tun":true,"tun-address-seed":"install-a"}`))
	if a.Address[0] == b.Address[0] || a.Address[0] != again.Address[0] || a.Address[1] != again.Address[1] {
		t.Fatalf("a %v b %v again %v", a.Address, b.Address, again.Address)
	}
	v4, v6 := a.Address[0], a.Address[1]
	if !seededTunIPv4Range.Contains(v4.Addr()) || v4.Bits() != 30 || !v4.Contains(v4.Addr().Next()) {
		t.Fatalf("v4 %v", v4)
	}
	if v6.Bits() != 126 || v6.Addr().As16()[0] != 0xfd || !v6.Contains(v6.Addr().Next()) {
		t.Fatalf("v6 %v", v6)
	}
	// the owner filter's DNS exception follows the TUN
	if dns := tunDNSAddresses(a); len(dns) != 2 || dns[0] != v4.Addr().Next().String()+"/32" {
		t.Fatalf("dns %v", dns)
	}
}
