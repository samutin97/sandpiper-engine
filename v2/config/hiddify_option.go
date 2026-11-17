package config

import (
	"fmt"
	reflect "reflect"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// The values of HiddifyOptions.DefaultProxy besides the balancer, its default.
const (
	DefaultProxyLowest = "lowest"
	DefaultProxyFirst  = "first"
)

type HiddifyOptions struct {
	EnableFullConfig bool   `json:"enable-full-config,omitempty" overridable:"true"`
	LogLevel         string `json:"log-level,omitempty"`
	LogFile          string `json:"log-file,omitempty"`
	// EnableClashApi: the core's own services (traffic statistics, cache file, monitoring) run;
	// it no longer opens any port, and the app's value is ignored (hcore.ChangeHiddifySettings
	// sets it). Only independent instances turn it off.
	EnableClashApi bool   `json:"enable-clash-api,omitempty"`
	ClashApiPort   uint16 `json:"clash-api-port,omitempty"`
	ClashApiSecret string `json:"web-secret,omitempty"`
	// ClashApiListen opens the Clash API on a loopback TCP port, on the desktop only (never on
	// Android or iOS), with a random port unless ClashApiPort names another than 16756, and a
	// random 32-byte secret unless ClashApiSecret is 32 characters or more. Off by default.
	ClashApiListen          bool   `json:"clash-api-listen,omitempty"`
	Region                  string `json:"region,omitempty"`
	BlockAds                bool   `json:"block-ads,omitempty" overridable:"true"`
	UseXrayCoreWhenPossible bool   `json:"use-xray-core-when-possible,omitempty" overridable:"true"`
	BalancerStrategy        string `json:"balancer-strategy,omitempty" overridable:"true"`
	// DefaultProxy is what the select group starts on while the user has picked nothing in it yet:
	// DefaultProxyLowest (the fastest proxy), DefaultProxyFirst (the profile's first proxy, or its
	// §default§ one) or, unset, the balancer.
	DefaultProxy string `json:"default-proxy,omitempty" overridable:"true"`
	// KeepTop, when above 0, runs only that many of a profile's proxies, the fastest by their first
	// pings, once the profile has more (see hcore's keep top); KeepTopAnswering runs the ones that
	// answer their first ping; 0 or -1 runs them all. The profile sets it, from its `keep-top`
	// header or the user's choice.
	KeepTop int `json:"keep-top,omitempty" overridable:"true"`
	// KeepTopQuick lets keep top pick before every proxy has its first ping: once the proxies
	// still to test were slower in their last ping, and every one without a ping of the last day
	// has been tested (see hcore's pickTopEarly).
	KeepTopQuick bool `json:"keep-top-quick,omitempty" overridable:"true"`
	// KeepTopBatch is how many proxies keep top tests at a time, beside the best found so far: 0
	// for the core's default (10), below 0 for all of them at once.
	KeepTopBatch int `json:"keep-top-batch,omitempty" overridable:"true"`
	// KeepTopCountries, when set, keeps only proxies of these countries (two-letter codes), by
	// where their IP is, else by the flag in their name; with keep-top 0 or -1, all of them.
	KeepTopCountries []string `json:"keep-top-countries,omitempty"`
	// KeepTopPinned are the tags of the profile's proxies keep top always uses, whatever their
	// ping, beside the fastest: the ones the user asked to keep loaded.
	KeepTopPinned []string `json:"keep-top-pinned,omitempty"`
	// KeepTags are the tags of the profile's proxies the user chose to run: while any of them is in
	// the profile, only those run, whatever KeepTop says; none of them left, KeepTop decides again.
	KeepTags []string `json:"keep-tags,omitempty"`
	// GeoIPPath        string      `json:"geoip-path"`
	// GeoSitePath      string      `json:"geosite-path"`
	Rules []Rule `json:"rules,omitempty" overridable:"true"`
	// the app's rule list; when set it replaces block-ads, bypass-lan and the region rules
	RouteRule *RouteRuleOptions `json:"route-rule,omitempty"`
	Warp      WarpOptions       `json:"warp,omitempty"`
	Warp2     WarpOptions       `json:"warp2,omitempty"`
	Mux       MuxOptions        `json:"mux,omitempty" overridable:"true"`
	TLSTricks TLSTricks         `json:"tls-tricks,omitempty"`
	EnableNTP bool              `json:"enable-ntp,omitempty"`
	// UseSystemTLSEngine lets a TLS client without a fingerprint use the system's TLS (Apple, Windows) when it
	// passed its check on this device; else it gets Chrome's uTLS. On unless false.
	UseSystemTLSEngine *bool `json:"use-system-tls-engine,omitempty"`
	// ExpandSubscriptionLinks lets the core fetch the subscription URLs a profile lists (https
	// only, public addresses only). Off by default: they are left out; the app fetches
	// subscriptions itself, through the VPN.
	ExpandSubscriptionLinks bool `json:"expand-subscription-links,omitempty"`
	// TLSFingerprint is the uTLS fingerprint of a TLS client whose profile names none (and that
	// does not use the system's TLS): "firefox" by default.
	TLSFingerprint string `json:"tls-fingerprint,omitempty"`
	// TLSKeyShare is the key share of the uTLS clients that are not REALITY, unless the profile
	// set one: the fingerprint's own (hybrid) by default, or "classical" (no X25519MLKEM768).
	TLSKeyShare string `json:"tls-key-share,omitempty"`
	// HandshakeGate paces the TLS handshakes to one server (on unless false): at most
	// HandshakeGateMax at a time (1), at least HandshakeGateGapMs between their starts (700, drawn
	// up to 400 ms more), at most 4 in 5 s (builder.go, handshakeGate).
	HandshakeGate      *bool `json:"handshake-gate,omitempty"`
	HandshakeGateMax   int   `json:"handshake-gate-max,omitempty"`
	HandshakeGateGapMs int   `json:"handshake-gate-gap-ms,omitempty"`
	// AllowInsecure keeps the proxies whose TLS checks no certificate (insecure, allowInsecure,
	// without a pinSHA256 / pcs pin). Off by default: such a proxy is left out of the config, as
	// anyone on the path can read its password and traffic.
	AllowInsecure bool `json:"allow-insecure,omitempty"`
	// TierPolicy is the subscription server's ranking of its proxies (its profile-policy header)
	// with the host and path the checks use: the core then builds the tiered group and chooses in
	// it (tier_group.go, hcore's tiered controller). The app sends it for the active profile only.
	TierPolicy *TierPolicyOptions `json:"tier-policy,omitempty"`

	DNSOptions
	InboundOptions
	URLTestOptions
	RouteOptions
	ChainOptions
}

type DNSOptions struct {
	RemoteDnsAddress        string                `json:"remote-dns-address,omitempty" overridable:"true"`
	RemoteDnsDomainStrategy option.DomainStrategy `json:"remote-dns-domain-strategy,omitempty" overridable:"true"`
	DirectDnsAddress        string                `json:"direct-dns-address,omitempty" overridable:"true"`
	DirectDnsDomainStrategy option.DomainStrategy `json:"direct-dns-domain-strategy,omitempty" overridable:"true"`
	// ServerDnsAddress: the resolvers of the names of the VPN servers only (the route's default
	// domain resolver), tried in order, comma-separated, the system resolver last. Empty: the direct
	// resolver, as before. The app sends DNS over HTTPS by IP address (no plain query before it),
	// while the direct domains keep direct-dns-address (the system resolver, no third party).
	ServerDnsAddress    string `json:"server-dns-address,omitempty"`
	IndependentDNSCache bool   `json:"independent-dns-cache,omitempty"`
	EnableFakeDNS       bool   `json:"enable-fake-dns,omitempty"`
	// EnableDNSRouting        bool                  `json:"enable-dns-routing,omitempty"`
}

type InboundOptions struct {
	EnableTun        bool `json:"enable-tun,omitempty"`
	EnableTunService bool `json:"enable-tun-service,omitempty"`
	SetSystemProxy   bool `json:"set-system-proxy,omitempty"`
	// DelegateSystemProxy is set by a core that runs as root for a user (the admin_bgservice on
	// Windows and Linux). It cannot reach the user's desktop session, so no inbound sets the system
	// proxy itself: the address is reported, and the user's own core sets it (SetSystemProxyEnabled).
	DelegateSystemProxy bool   `json:"delegate-system-proxy,omitempty"`
	MixedPort           uint16 `json:"mixed-port,omitempty"`
	TProxyPort          uint16 `json:"tproxy-port,omitempty"`
	RedirectPort        uint16 `json:"redirect-port,omitempty"`
	DirectPort          uint16 `json:"direct-port,omitempty"`
	// Each local port opens only while its switch is on; unset is on for the mixed port, off for the
	// transparent ones, which serve setups made by hand (see portEnabled).
	EnableMixedPort    *bool `json:"enable-mixed-port,omitempty"`
	EnableTProxyPort   *bool `json:"enable-tproxy-port,omitempty"`
	EnableRedirectPort *bool `json:"enable-redirect-port,omitempty"`
	EnableDirectPort   *bool `json:"enable-direct-port,omitempty"`
	// LanSharingPort is the port the local network uses while the VPN is shared with it, apart from
	// this device's own (MixedPort), and asking for ProxySecret (see proxyListeners).
	LanSharingPort uint16 `json:"lan-sharing-port,omitempty"`
	// ProxySecret is the password (of the user "hiddify") of the LAN sharing port, and of the local
	// port too while LocalProxyAuth is on.
	ProxySecret string `json:"lan-sharing-password,omitempty"`
	// LocalProxyAuth no longer has any effect (hardened): the local port always asks for a user and
	// password (LocalProxyUsername, LocalProxyPassword), but for the system proxy's own listener on
	// the desktop, which can not pass one.
	LocalProxyAuth bool `json:"local-proxy-auth,omitempty"`
	// LocalProxyUsername and LocalProxyPassword are the credentials of the local port; with no
	// password of 16 characters or more, the core makes random ones for the session (see
	// GetLocalProxyInfo). LocalProxyUsername is also the user of the LAN sharing port ("hiddify"
	// when unset).
	LocalProxyUsername string `json:"local-proxy-username,omitempty"`
	LocalProxyPassword string `json:"local-proxy-password,omitempty"`
	// LocalProxyUDP allows SOCKS5 UDP ASSOCIATE on the local and LAN ports: off by default, the
	// password does not cover the UDP relay.
	LocalProxyUDP bool `json:"local-proxy-udp,omitempty"`
	// LocalProxyInVpn keeps the local port open in VPN mode, where every app already goes through the
	// TUN: on the desktop only, never on Android and iOS. Off by default.
	LocalProxyInVpn bool   `json:"local-proxy-in-vpn,omitempty"`
	MTU             uint32 `json:"mtu,omitempty"`
	StrictRoute     bool   `json:"strict-route,omitempty"`
	// TUNStack is the TUN's TCP/IP stack: "sing15" (or empty) for sing-tun's own, the default; the
	// legacy "system", "gvisor" and "mixed" are accepted until sing-box 1.17 (see TunStack).
	TUNStack string `json:"tun-implementation,omitempty"`
	// AutoRedirect lets a Linux TUN use nftables routing (sing-box auto_redirect) where the process
	// can; on by default, off only to force the plain TUN. Nothing elsewhere (see AutoRedirectAvailable).
	AutoRedirect bool `json:"auto-redirect"`
	// RouterMode makes a Linux router or gateway a transparent proxy for its whole network: the
	// TUN with auto_redirect takes the TCP, UDP and ICMP the router forwards and its own, and lets
	// connections from outside (to the router, or port forwarded) and their replies pass. It turns
	// the TUN on (see forRouterMode).
	RouterMode bool `json:"router-mode,omitempty"`
}

type URLTestOptions struct {
	ConnectionTestUrl  string            `json:"connection-test-url,omitempty" overridable:"true"`
	ConnectionTestUrls []string          `json:"connection-test-urls,omitempty" overridable:"true"`
	URLTestInterval    DurationInSeconds `json:"url-test-interval,omitempty" overridable:"true"`
	// Custom IP geolocation endpoint (subscription `ipinfo-url`); ipapi.co-compatible JSON.
	IpInfoUrl string `json:"ipinfo-url,omitempty" overridable:"true"`
	// IpInfo looks the exit's country and address up after each proxy test (through the proxy).
	// Off by default: every lookup is a request to a geolocation service.
	IpInfo bool `json:"ipinfo,omitempty"`
	// MonitoringWorkers is how many proxies are tested at a time: 2 by default, 1 to 4.
	MonitoringWorkers int `json:"monitoring-workers,omitempty"`
	// RetestOnNetworkChange: "selected" (default: only the proxies in use), "all" or "none".
	RetestOnNetworkChange string `json:"retest-on-network-change,omitempty"`
	// UDPEndpointsInAuto puts the AmneziaWG and WireGuard endpoints in the automatic groups
	// (lowest, balance) and the regular tests too. Off by default: they are chosen by hand and
	// tested when selected or asked for.
	UDPEndpointsInAuto bool `json:"udp-endpoints-in-auto,omitempty"`
	// URLTestIdleTimeout DurationInSeconds `json:"url-test-idle-timeout"`
}

type RouteOptions struct {
	ResolveDestination     bool                  `json:"resolve-destination,omitempty"`
	IPv6Mode               option.DomainStrategy `json:"ipv6-mode,omitempty"`
	BypassLAN              bool                  `json:"bypass-lan,omitempty"`
	AllowConnectionFromLAN bool                  `json:"allow-connection-from-lan,omitempty"`
	BlockQuic              bool                  `json:"block-quic,omitempty"`
	// TunAddressSeed, made once per installation by the app, gives the TUN addresses of its own
	// instead of the 172.19.0.1/28 and fdfe:dcba:9876::1/126 every sing-box client has.
	TunAddressSeed string `json:"tun-address-seed,omitempty"`
	// RuleSetInitialDir holds the region's rule-sets (geoip-<region>.srs, geosite-<region>.srs) the
	// app ships, used until the first download through the VPN.
	RuleSetInitialDir string `json:"rule-set-initial-dir,omitempty"`
	// PerAppProxyMode is the per-app split tunneling of Android: "include" (only the listed apps
	// go through the VPN), "exclude" (all but the listed ones), "off" or unset (all apps). The
	// list goes into the TUN (TunOptions.includePackage / excludePackage), where the app reads it
	// for VpnService.Builder.
	PerAppProxyMode string   `json:"per-app-proxy-mode,omitempty"`
	PerAppProxyList []string `json:"per-app-proxy-list,omitempty"`
	// PerAppStrict rejects, on Android 10+ in VPN mode, the TUN flows whose owner is unknown (an
	// app outside the VPN that bound a socket to the TUN, another user or profile, ICMP) and, in
	// the per-app modes, those of an app on the wrong side of the list. On unless false.
	PerAppStrict *bool `json:"per-app-strict,omitempty"`
}

type TLSTricks struct {
	EnableFragment bool   `json:"enable-fragment,omitempty" overridable:"true"`
	FragmentSize   string `json:"fragment-size,omitempty" overridable:"true"`
	FragmentSleep  string `json:"fragment-sleep,omitempty" overridable:"true"`
	MixedSNICase   bool   `json:"mixed-sni-case,omitempty" overridable:"true"`
	EnablePadding  bool   `json:"enable-padding,omitempty" overridable:"true"`
	PaddingSize    string `json:"padding-size,omitempty" overridable:"true"`
}

type MuxOptions struct {
	Enable     bool   `json:"enable,omitempty" overridable:"true"`
	Padding    bool   `json:"padding,omitempty" overridable:"true"`
	MaxStreams int    `json:"max-streams,omitempty" overridable:"true"`
	Protocol   string `json:"protocol,omitempty" overridable:"true"`
}

type WarpOptions struct {
	Id                 string              `json:"id,omitempty"`
	EnableWarp         bool                `json:"enable,omitempty"`
	Mode               string              `json:"mode,omitempty"`
	WireguardConfigStr string              `json:"wireguard-config,omitempty"`
	WireguardConfig    WarpWireguardConfig `json:"wireguardConfig,omitempty"` // TODO check
	FakePackets        string              `json:"noise,omitempty"`
	FakePacketSize     string              `json:"noise-size,omitempty"`
	FakePacketDelay    string              `json:"noise-delay,omitempty"`
	FakePacketMode     string              `json:"noise-mode,omitempty"`
	CleanIP            string              `json:"clean-ip,omitempty"`
	CleanPort          uint16              `json:"clean-port,omitempty"`
	Account            WarpAccount
}

func DefaultHiddifyOptions() *HiddifyOptions {
	return &HiddifyOptions{
		EnableNTP: true,
		DNSOptions: DNSOptions{
			RemoteDnsAddress:        "1.1.1.1",
			RemoteDnsDomainStrategy: option.DomainStrategy(C.DomainStrategyAsIS),
			DirectDnsAddress:        "", // DoH by region, see directDNSAddress
			DirectDnsDomainStrategy: option.DomainStrategy(C.DomainStrategyAsIS),
			IndependentDNSCache:     false,
			EnableFakeDNS:           false,
			// EnableDNSRouting:        false,
		},
		InboundOptions: InboundOptions{
			EnableTun:      false,
			SetSystemProxy: false,
			MixedPort:      12334,
			TProxyPort:     12335,
			RedirectPort:   12336,
			DirectPort:     12337,
			LanSharingPort: 12338,
			MTU:            9000,
			StrictRoute:    true,
			TUNStack:       "sing15",
			AutoRedirect:   true,
		},
		URLTestOptions: URLTestOptions{
			ConnectionTestUrl: "http://cp.cloudflare.com/",
			URLTestInterval:   DurationInSeconds(defaultURLTestInterval),
			// URLTestIdleTimeout: DurationInSeconds(6000),
		},
		RouteOptions: RouteOptions{
			ResolveDestination:     false,
			IPv6Mode:               option.DomainStrategy(C.DomainStrategyAsIS),
			BypassLAN:              false,
			AllowConnectionFromLAN: false,
		},
		LogLevel: "warn",
		// LogFile:        "/dev/null",
		LogFile:        "data/box.log",
		Region:         "other",
		EnableClashApi: true,

		ClashApiPort:   16756,
		ClashApiSecret: "",
		// GeoIPPath:      "geoip.db",
		// GeoSitePath:    "geosite.db",
		Rules: []Rule{},
		Mux: MuxOptions{
			Enable:     false,
			Padding:    true,
			MaxStreams: 8,
			Protocol:   "h2mux",
		},
		TLSTricks: TLSTricks{
			EnableFragment: false,
			FragmentSize:   "10-100",
			FragmentSleep:  "50-200",
			MixedSNICase:   false,
			EnablePadding:  false,
			PaddingSize:    "1200-1500",
		},
		UseXrayCoreWhenPossible: false,
	}
}

// Recursively set the fields marked as overridable
func setOverridableFields(v reflect.Value, t reflect.Type, overrides map[string]interface{}) {
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)

		// Check if the field has an "overridable" tag set to "true"
		overridableTag := fieldType.Tag.Get("overridable")
		if overridableTag == "true" {
			// Get the field's JSON tag name
			jsonTag := strings.Split(fieldType.Tag.Get("json"), ",")[0]
			if jsonTag == "" {
				continue
			}

			// Check if an override exists for this field
			if overrideValue, ok := overrides[jsonTag]; ok {
				// Ensure the override value can be set to the field type
				var parsedValue reflect.Value
				switch field.Kind() {
				case reflect.Bool:
					if boolVal, err := parseBool(overrideValue); err == nil {
						parsedValue = reflect.ValueOf(boolVal)
					}
				case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
					if intVal, err := parseInt(overrideValue); err == nil {
						parsedValue = reflect.ValueOf(intVal)
					}
				case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
					if uintVal, err := parseUint(overrideValue); err == nil {
						parsedValue = reflect.ValueOf(uintVal)
					}
				case reflect.String:
					parsedValue = reflect.ValueOf(overrideValue.(string))
					// Add more cases for other types as needed
				}

				// Set the field if we have a parsed value
				if parsedValue.IsValid() && parsedValue.Type().AssignableTo(field.Type()) {
					field.Set(parsedValue)
				}
			}
		}

		// If the field is a nested struct, recurse into it
		if field.Kind() == reflect.Struct {
			jsonTag := strings.Split(fieldType.Tag.Get("json"), ",")[0]

			data := overrides
			if jsonTag != "" {
				data1 := overrides[jsonTag]
				if data1 == nil {
					continue
				}
				data = data1.(map[string]interface{})
			}
			neastedType := fieldType.Type
			if data != nil {
				setOverridableFields(field, neastedType, data)
			}

		}
	}
}

// Helper functions for parsing
func parseBool(value interface{}) (bool, error) {
	switch v := value.(type) {
	case string:
		return strconv.ParseBool(v)
	case bool:
		return v, nil
	}
	return false, fmt.Errorf("invalid bool value")
}

func parseInt(value interface{}) (int64, error) {
	switch v := value.(type) {
	case string:
		return strconv.ParseInt(v, 10, 64)
	case int, int8, int16, int32, int64:
		return reflect.ValueOf(v).Int(), nil
	}
	return 0, fmt.Errorf("invalid int value")
}

func parseUint(value interface{}) (uint64, error) {
	switch v := value.(type) {
	case string:
		return strconv.ParseUint(v, 10, 64)
	case uint, uint8, uint16, uint32, uint64:
		return reflect.ValueOf(v).Uint(), nil
	}
	return 0, fmt.Errorf("invalid uint value")
}

func GetOverridableHiddifyOptions(overrides map[string][]string) *HiddifyOptions {
	overrideHiddify := HiddifyOptions{}

	// Convert flat overrides to nested structure
	nestedOverrides := convertFlatToNested(overrides)

	// Use reflection to iterate over the fields of HiddifyOptions
	v := reflect.ValueOf(&overrideHiddify).Elem()
	t := reflect.TypeOf(overrideHiddify)

	// Recursively set the fields that are marked as overridable
	setOverridableFields(v, t, nestedOverrides)

	return &overrideHiddify
}

// Converts the flat overrides map to a nested structure without removing underscores
func convertFlatToNested(overrides map[string][]string) map[string]interface{} {
	nested := make(map[string]interface{})
	for key, value := range overrides {
		keys := strings.Split(key, ".")
		current := nested

		for i, k := range keys {
			if i == len(keys)-1 {
				// Set the final value with underscores preserved
				current[k] = value[0]
			} else {
				// Create nested maps if they do not exist
				if _, exists := current[k]; !exists {
					current[k] = make(map[string]interface{})
				}
				current = current[k].(map[string]interface{})
			}
		}
	}
	return nested
}
