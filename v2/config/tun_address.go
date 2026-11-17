package config

import (
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
)

// The TUN's addresses. 172.19.0.1/28 and fdfe:dcba:9876::1/126 are the same on every device that
// runs sing-box or Hiddify: any app reads them (NetworkInterface, no permission) and knows the
// client, not only that a VPN runs (HC-32). With tun-address-seed (made once per installation by
// the app) the addresses are a /30 in 10.64.0.0/10 and a /126 in fd00::/8 derived from it: the
// same on every start of one installation, different between installations.

var (
	defaultTunIPv4     = netip.MustParsePrefix("172.19.0.1/28")
	defaultTunIPv6     = netip.MustParsePrefix("fdfe:dcba:9876::1/126")
	seededTunIPv4Range = netip.MustParsePrefix("10.64.0.0/10")
)

// tunAddresses are the TUN's IPv4 and IPv6 addresses (the interface address of each prefix; the
// next one is its DNS server).
func tunAddresses(hopt *HiddifyOptions) []netip.Prefix {
	if hopt.TunAddressSeed == "" {
		return []netip.Prefix{defaultTunIPv4, defaultTunIPv6}
	}
	sum := sha256.Sum256([]byte("hiddify-tun-address|" + hopt.TunAddressSeed))
	// 10.64.0.0/10 has 2^20 blocks of 4 addresses; skip the first and the last block
	block := binary.BigEndian.Uint32(sum[:4])%(1<<20-2) + 1
	base := binary.BigEndian.Uint32(seededTunIPv4Range.Addr().AsSlice()) + block<<2
	var v4 [4]byte
	binary.BigEndian.PutUint32(v4[:], base+1)
	var v6 [16]byte
	copy(v6[:], sum[4:20])
	v6[0] = 0xfd
	v6[15] = v6[15]&^0x03 | 0x01 // the first address of the /126
	return []netip.Prefix{
		netip.PrefixFrom(netip.AddrFrom4(v4), 30),
		netip.PrefixFrom(netip.AddrFrom16(v6), 126),
	}
}

// isTunIPv4 says whether an address is one of the TUN's (by default or seeded).
func isTunIPv4(ip netip.Addr) bool {
	return tunIPv4Network.Contains(ip) || seededTunIPv4Range.Contains(ip)
}
