package config

import (
	context "context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	sync "sync"
	"time"

	C "github.com/sagernet/sing-box/constant"
	sdns "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/hiddify/hiddify-core/v2/tiered"
)

// A balancer's member takes the selection when faster by more than the larger of the two: a
// share of the selected member's delay (100 ms is left for 60 ms, not for 90 ms), with a floor
// against the jitter of close pings (25 ms is not left for 22 ms). An absolute 100 ms kept a
// 59 ms member over a 25 ms one.
const (
	BalancerTolerance      uint16 = 30
	BalancerToleranceRatio        = 0.2
)

const (
	DNSRemoteTag         = "dns-remote"
	DNSRemoteTagFallback = "dns-remote-fallback"
	DNSLocalTag          = "dns-local"
	DNSStaticTag         = "dns-static"
	DNSDirectTag         = "dns-direct"
	DNSRemoteNoWarpTag   = "dns-remote-no-warp"
	// DNSBlockTag        = "dns-block"
	DNSFakeTag         = "dns-fake"
	DNSTricksDirectTag = "dns-trick-direct"
	// DNSMultiDirectTag  = "dns-multi-direct"
	// DNSMultiRemoteTag  = "dns-multi-remote"
	// sequential groups (selected server, its TCP/TLS variants, then a fallback resolver);
	// all DNS rules and the DNS final use these
	DNSMultiDirectTag = "dns-direct-group"
	// DNSServerNamesTag resolves the names of the VPN servers when server-dns-address is set
	DNSServerNamesTag = "dns-server-names"
	DNSMultiRemoteTag = "dns-remote-group"
	// DoH through the profile alone, past the extra security hop: the remote group's last resort
	DNSRemoteViaProfileTag = "dns-remote-via-profile"

	OutboundDirectTag = "direct §hide§"
	OutboundBypassTag = "bypass §hide§"
	// OutboundBlockTag          = "block §hide§"
	OutboundSelectTag         = "select"
	OutboundURLTestTag        = "lowest"
	OutboundRoundRobinTag     = "balance"
	OutboundDirectFragmentTag = "direct-fragment §hide§"

	InboundTUNTag   = "tun-in"
	InboundMixedTag = "mixed-in"
	// the LAN sharing port, apart from this device's own (proxyListeners)
	InboundLanSharingTag = "lan-sharing-in"
	InboundTProxy        = "tproxy-in"
	InboundRedirect      = "redirect-in"
	InboundDirectTag     = "dns-in"
)

var (
	OutboundMainDetour       = OutboundSelectTag
	OutboundWARPConfigDetour = OutboundDirectFragmentTag
	PredefinedOutboundTags   = []string{OutboundDirectTag, OutboundBypassTag, OutboundSelectTag, OutboundURLTestTag, OutboundDirectFragmentTag, ChainExtraSecurityTag, ChainUnblockerTag, OutboundTieredTag, OutboundTieredWaitTag}
)

// TODO include selectors
func BuildConfig(ctx context.Context, hopts *HiddifyOptions, inputOpt *ReadOptions) (*option.Options, error) {
	ipv6Only := !hostHasIPv4()
	hopts = forIPv6OnlyHost(hopts, ipv6Only)
	hopts, err := forRouterMode(hopts)
	if err != nil {
		return nil, err
	}

	input, err := ReadSingOptions(ctx, inputOpt)
	if err != nil {
		return nil, err
	}
	// the profile's outbounds and endpoints, whatever parser made them, are checked (HC-03, HC-19)
	input, warnings, err := sanitizeOptions(ctx, input, profilePolicy{allowInsecure: hopts.AllowInsecure})
	if err != nil {
		return nil, err
	}
	for _, warning := range warnings {
		fmt.Println("profile: dropped", warning)
	}
	// the profile's inbounds, DNS and route are never taken on Android and iOS (HC-03)
	if isMobile {
		hopts.EnableFullConfig = false
	}

	var options option.Options
	if hopts.EnableFullConfig {
		options.Inbounds = input.Inbounds
		options.DNS = input.DNS
		options.Route = input.Route
	}

	setExperimental(&options, hopts)
	declareIPv6FromInput(&options, input)

	setLog(&options, hopts)
	if err := setInbound(&options, hopts); err != nil {
		return nil, err
	}
	staticIPs := make(map[string][]string)
	// staticIPs["api.cloudflareclient.com"] = []string{"104.16.192.82", "2606:4700::6810:1854", getRandomWarpIP()}
	// setNTP(&options)
	if err := setOutbounds(&options, input, hopts, &staticIPs); err != nil {
		return nil, err
	}
	if err := setDns(&options, hopts, &staticIPs); err != nil {
		return nil, err
	}

	if err := setRoutingOptions(&options, hopts); err != nil {
		return nil, err
	}
	if ipv6Only {
		useIPv6Resolvers(&options)
	}

	return &options, nil
}

// declareIPv6FromInput passes the links' IPv6 declarations (ray2sing, a link's ipv6=1 or ipv6=0)
// to the monitoring, which takes them as known from the start.
func declareIPv6FromInput(options *option.Options, input *option.Options) {
	if input == nil || input.Experimental == nil || input.Experimental.Monitoring == nil || len(input.Experimental.Monitoring.IPv6Declared) == 0 {
		return
	}
	if options.Experimental == nil || options.Experimental.Monitoring == nil {
		return
	}
	options.Experimental.Monitoring.IPv6Declared = input.Experimental.Monitoring.IPv6Declared
}

// dialDetour maps the built-in empty direct outbounds to "" (dial directly),
// since sing-box rejects a detour to an empty direct outbound.
func dialDetour(tag string) string {
	if tag == OutboundDirectTag || tag == OutboundDirectFragmentTag {
		return ""
	}
	return tag
}

func setNTP(options *option.Options) {
	options.NTP = &option.NTPOptions{
		Enabled:       true,
		ServerOptions: option.ServerOptions{ServerPort: 123, Server: "time.apple.com"},
		Interval:      badoption.Duration(12 * time.Hour),
		DialerOptions: option.DialerOptions{
			Detour: dialDetour(OutboundDirectTag),
		},
	}
}

func getHostnameIfNotIP(inp string) (string, error) {
	if inp == "" {
		return "", fmt.Errorf("empty hostname: %s", inp)
	}
	if net.ParseIP(strings.Trim(inp, "[]")) == nil {
		inp2 := inp
		if !strings.Contains(inp, "://") {
			inp2 = "http://" + inp
		}
		u, err := url.Parse(inp2)
		if err != nil {
			return inp, nil
		}
		if net.ParseIP(strings.Trim(u.Host, "[]")) == nil {
			return u.Host, nil
		}
	}
	return "", fmt.Errorf("not a hostname: %s", inp)
}

func isDNSOutbound(out option.Outbound) bool {
	if out.Type == C.TypeDNS {
		return true
	}
	invalid, ok := out.Options.(*option.HInvalidOptions)
	return ok && invalid.OriginalType == C.TypeDNS
}

func setOutbounds(options *option.Options, input *option.Options, opt *HiddifyOptions, staticIPs *map[string][]string) error {
	var outbounds []option.Outbound
	var endpoints []option.Endpoint
	var tags []string
	// manualOnly are the proxies kept out of the automatic groups (UDP, see auto_group.go)
	manualOnly := map[string]bool{}
	// the proxies that carry their traffic over UDP, for the tiered group's checks
	udpTags := map[string]bool{}
	// the subscription's own automatic choice (a panel's urltest "Auto"), nil without one
	profileAuto := profileURLTestMembers(input.Outbounds)
	// OutboundMainProxyTag = OutboundSelectTag
	// inbound==warp over proxies
	// outbound==proxies over warp
	OutboundMainDetour = OutboundSelectTag
	OutboundWARPConfigDetour = OutboundDirectFragmentTag
	chainPsiphon := chainUsesPsiphon(opt)
	keptPsiphon := ""
	removedPsiphon := map[string]bool{}
	for _, out := range input.Outbounds {

		if contains(PredefinedOutboundTags, out.Tag) {
			continue
		}
		// dns outbounds were removed in sing-box 1.13; the parser turns them into hinvalid
		// placeholders, which must not end up as selectable proxies
		if isDNSOutbound(out) {
			continue
		}
		outbound, err := patchOutbound(out, *opt, staticIPs)
		if err != nil {
			return err
		}
		out = *outbound

		switch out.Type {
		case C.TypeBlock:
			continue
		case C.TypeSelector, C.TypeURLTest:
			continue
		case C.TypeCustom:
			continue
		default:

			if contains([]string{"direct", "bypass", "block"}, out.Tag) {
				continue
			}
			// Psiphon runs as one instance per process: a Psiphon chain hop replaces every
			// Psiphon of the profile, otherwise only the first one is kept
			if out.Type == C.TypePsiphon {
				if chainPsiphon || keptPsiphon != "" {
					removedPsiphon[out.Tag] = true
					continue
				}
				keptPsiphon = out.Tag
			}
			if !strings.Contains(out.Tag, "§hide§") {
				tags = append(tags, out.Tag)
				udpTags[out.Tag] = udpProxy(out.Type, out.Options)
				if udpTags[out.Tag] && !opt.UDPEndpointsInAuto {
					manualOnly[out.Tag] = true
				}
			}
			outbounds = append(outbounds, out)
		}
	}

	for _, end := range input.Endpoints {
		if contains(PredefinedOutboundTags, end.Tag) {
			continue
		}
		out, err := patchEndpoint(&end, *opt, staticIPs)
		if err != nil {
			return err
		}

		if !strings.Contains(out.Tag, "§hide§") {
			tags = append(tags, out.Tag)
			udpTags[out.Tag] = udpProxy(out.Type, out.Options)
			if udpTags[out.Tag] && !opt.UDPEndpointsInAuto {
				manualOnly[out.Tag] = true
			}
		}
		quietUDPEndpoint(out)

		endpoints = append(endpoints, *out)
	}
	redirectRemovedPsiphon(outbounds, endpoints, removedPsiphon, keptPsiphon)
	if err := setChainHop(opt, &outbounds, &endpoints); err != nil {
		return err
	}
	fitWireGuardInWireGuard(endpoints)
	warpBehindDetour(outbounds, endpoints)
	systemEngine := ""
	if opt.UseSystemTLSEngine == nil || *opt.UseSystemTLSEngine {
		systemEngine = usableTLSEngine()
	}
	fingerprint, keyShare := tlsDefaults(opt)
	chooseTLSEnginesWith(outbounds, systemEngine, fingerprint)
	applyKeyShare(outbounds, keyShare)
	if len(opt.ConnectionTestUrls) == 0 {
		opt.ConnectionTestUrls = []string{opt.ConnectionTestUrl, "https://www.google.com/generate_204", "http://captive.apple.com/generate_204", "https://cp.cloudflare.com"}
	}
	// urlTest := option.Outbound{
	// 	Type: C.TypeURLTest,
	// 	Tag:  OutboundURLTestTag,
	// 	Options: &option.URLTestOutboundOptions{
	// 		Outbounds: tags,
	// 		URL:       opt.ConnectionTestUrl,
	// 		URLs:      opt.ConnectionTestUrls,
	// 		Interval:  badoption.Duration(opt.URLTestInterval.Duration()),
	// 		// IdleTimeout: badoption.Duration(opt.URLTestIdleTimeout.Duration()),
	// 		Tolerance:                 1,
	// 		IdleTimeout:               badoption.Duration(opt.URLTestInterval.Duration().Nanoseconds() * 3),
	// 		InterruptExistConnections: true,
	// 	},
	// }
	// the subscription server's ranking (with two proxies or more, as the other groups)
	var tierPlan *tiered.Plan
	if len(tags) > 1 {
		tierPlan = tierPlanOf(opt, tags, udpTags)
	}
	// a last resort that waits for the user's agreement is in no automatic group, whatever the
	// settings (a TCP one, or UDP endpoints in the automatic groups): lowest and balance would use
	// and test it without that agreement. It is tested only when selected or asked for.
	autoTags := withoutTags(autoGroupTags(tags, profileAuto, manualOnly), tierPlan.Reserves())
	if len(autoTags) == 0 {
		// only such last resorts: the automatic groups carry nothing (a group needs a member)
		autoTags = []string{OutboundTieredWaitTag}
	}
	// the tunnels outside the automatic groups talk to their servers only while used
	lazyQuietTunnels(endpoints, autoTags)
	if options.Experimental != nil && options.Experimental.Monitoring != nil {
		// the proxies outside lowest and balance: tested when selected or asked for, not in cycles
		options.Experimental.Monitoring.OnDemandTags = onDemandProxyTags(tags, autoTags)
	}
	if len(tags) > 1 {
		source := "every proxy"
		if len(profileAuto) > 0 {
			source = "the profile's urltest group"
		}
		fmt.Printf("automatic groups: %d of %d proxies (%s, UDP in auto: %v)\n", len(autoTags), len(tags), source, opt.UDPEndpointsInAuto)
	}
	urlTest := option.Outbound{
		Type: C.TypeBalancer,
		Tag:  OutboundURLTestTag,
		Options: &option.BalancerOutboundOptions{
			Outbounds:            autoTags,
			Strategy:             "lowest-delay",
			DelayAcceptableRatio: 2,
			// URL:       opt.ConnectionTestUrl,
			// URLs:      opt.ConnectionTestUrls,
			// Interval:  badoption.Duration(opt.URLTestInterval.Duration()),
			// IdleTimeout: badoption.Duration(opt.URLTestIdleTimeout.Duration()),
			Tolerance:      BalancerTolerance,
			ToleranceRatio: BalancerToleranceRatio,
			// IdleTimeout:               badoption.Duration(opt.URLTestInterval.Duration().Nanoseconds() * 3),
			InterruptExistConnections: true,
		},
	}

	balancer := option.Outbound{
		Type: C.TypeBalancer,
		Tag:  OutboundRoundRobinTag,
		Options: &option.BalancerOutboundOptions{
			Outbounds:            autoTags,
			Strategy:             opt.BalancerStrategy,
			DelayAcceptableRatio: 2,
			// URL:       opt.ConnectionTestUrl,
			// URLs:      opt.ConnectionTestUrls,
			// Interval:  badoption.Duration(opt.URLTestInterval.Duration()),
			// IdleTimeout: badoption.Duration(opt.URLTestIdleTimeout.Duration()),
			// no tolerance: it is lowest-delay's, and the pool reads it too, and with it a faster
			// member outside would take a slot, moving its sticky keys
			// IdleTimeout:               badoption.Duration(opt.URLTestInterval.Duration().Nanoseconds() * 3),
			InterruptExistConnections: true,
		},
	}
	if len(tags) == 0 {
		return fmt.Errorf("profile has no usable outbound")
	}
	defaultSelect := tags[0]

	for _, tag := range tags {
		if strings.Contains(tag, "§default§") {
			defaultSelect = "§default§"
		}
	}

	selectorTags := tags
	if len(tags) > 1 {
		outbounds = append([]option.Outbound{balancer, urlTest}, outbounds...)
		selectorTags = append([]string{urlTest.Tag, balancer.Tag}, selectorTags...)
		switch opt.DefaultProxy {
		case DefaultProxyLowest, "":
			// unset: the fastest proxy, not the balancer that spread connections over every
			// proxy of the profile, each protocol in turn (HC-10)
			defaultSelect = urlTest.Tag
		case DefaultProxyFirst:
		default:
			defaultSelect = balancer.Tag
		}
		// the subscription server's ranking: its group first, and what select starts on
		if tierPlan != nil {
			tieredGroup, wait := tierGroup(tierPlan)
			outbounds = append([]option.Outbound{tieredGroup}, append(outbounds, wait)...)
			selectorTags = append([]string{tieredGroup.Tag}, selectorTags...)
			defaultSelect = tieredGroup.Tag
			monitorTheWait(options)
			fmt.Printf("tiered group: %d of %d proxies, by the server's policy\n", len(tierPlan.Candidates), len(tags))
		}
	}
	selector := option.Outbound{
		Type: C.TypeSelector,
		Tag:  OutboundSelectTag,
		Options: &option.SelectorOutboundOptions{
			Outbounds:                 selectorTags,
			Default:                   defaultSelect,
			InterruptExistConnections: true,
		},
	}
	outbounds = append([]option.Outbound{selector}, outbounds...)

	options.Endpoints = endpoints
	options.Outbounds = append(
		outbounds,
		[]option.Outbound{
			{
				Tag:     OutboundDirectTag,
				Type:    C.TypeDirect,
				Options: &option.DirectOutboundOptions{},
			},
			{
				Tag:  OutboundDirectFragmentTag,
				Type: C.TypeDirect,
				Options: &option.DirectOutboundOptions{
					DialerOptions: option.DialerOptions{
						AbstractDialerOptions: option.AbstractDialerOptions{
							TCPFastOpen: false,
						},
						TLSFragment: option.TLSFragmentOptions{
							Enabled: true,
							Size:    opt.TLSTricks.FragmentSize,
							Sleep:   opt.TLSTricks.FragmentSleep,
						},
					},
				},
			},
		}...,
	)

	return nil
}

// quietUDPEndpoint keeps an AmneziaWG endpoint from talking to its server until it is used: its
// keepalive starts at the first connection (no handshake at every start for an endpoint nobody
// selected), and no MTU probing through the tunnel when the profile gives the MTU (HC-39).
func quietUDPEndpoint(end *option.Endpoint) {
	if options, ok := end.Options.(*option.AwgEndpointOptions); ok {
		options.KeepaliveOnUse = true
		if options.MTU > 0 && options.MTUDiscovery == nil {
			off := false
			options.MTUDiscovery = &off
		}
	}
}

// autoDetectInterface says whether the core's sockets are bound to the underlying network around
// its own TUN: on the desktop by the interface, and on Android by the platform, which protects each
// socket of the dialers (VpnService.protect) and binds it to the default network. On Android it was
// off, so no socket of the core was protected, and the app had to keep itself out of its own VPN
// (addDisallowedApplication) or the sockets carrying the tunnel would loop into it; its own
// requests then went around the tunnel (H-02 of the app audit). With it the app stays in its VPN:
// the outbounds to the servers, their UDP (hysteria2, tuic, WireGuard, AmneziaWG), the DNS servers
// and the direct outbound go out protected on the physical network, the app's other requests go
// through the tunnel. Not on iOS, where the system keeps the extension's sockets out of the tunnel.
func autoDetectInterface(hopt *HiddifyOptions, android, ios bool) bool {
	return !ios && (hopt.EnableTun || hopt.EnableTunService)
}

// regionDomainSuffixes are the domains of a region that go around the VPN from the start, before
// its rule-sets are downloaded (through the VPN, after the start) and whatever is in them: for
// Russia every Russian top-level domain (.ru alone left .su, .рф and the city domains to the VPN,
// and Russian services then saw the VPN server's address, HC-14).
func regionDomainSuffixes(region string) []string {
	if region == "ru" {
		return []string{
			".ru", ".su", ".xn--p1ai", // .рф
			".xn--p1acf",                      // .рус
			".xn--d1acj3b",                    // .дети
			".xn--80asehdb",                   // .онлайн
			".xn--80aswg",                     // .сайт
			".xn--c1avg",                      // .орг
			".xn--80adxhks",                   // .москва
			".moscow", ".tatar", ".xn--90ais", // .бел (Belarus, Russian services)
		}
	}
	return []string{"." + region}
}

// ruleSetInitialPath is the rule-set file of the app's assets (rule-set-initial-dir) to start
// with, until the first download: empty when the app gives none or it is not there.
func ruleSetInitialPath(hopt *HiddifyOptions, name string) string {
	if hopt.RuleSetInitialDir == "" {
		return ""
	}
	path := filepath.Join(hopt.RuleSetInitialDir, name)
	if info, err := os.Stat(path); err != nil || info.IsDir() {
		return ""
	}
	return path
}

func isBlockedConnectionTestUrl(d string) bool {
	u, err := url.Parse(d)
	if err != nil {
		return false
	}
	return isBlockedDomain(u.Host)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func setExperimental(options *option.Options, hopt *HiddifyOptions) {
	if len(hopt.ConnectionTestUrls) == 0 {
		// no lookup of the test URL's domain with the system resolver here (isBlockedConnectionTestUrl
		// did one at every build: a plain DNS query to the provider, HC-34)
		hopt.ConnectionTestUrls = []string{hopt.ConnectionTestUrl, "http://captive.apple.com/generate_204", "https://cp.cloudflare.com", "https://google.com/generate_204"}
	}
	// EnableClashApi now only says whether the core's own services run (traffic statistics through
	// the clash server, cache file, monitoring); only independent instances turn it off. Whether
	// the Clash API listens on a TCP port is clashAPIOptions' decision (HC-04).
	if hopt.EnableClashApi {
		options.Experimental = &option.ExperimentalOptions{
			UnifiedDelay: &option.UnifiedDelayOptions{
				Enabled: true,
			},
			ClashAPI: clashAPIOptions(hopt),

			CacheFile: &option.CacheFileOptions{
				Enabled: true, // WARP and MASQUE devices are stored by default
				Path:    "data/clash.db",
			},

			Monitoring: &option.MonitoringOptions{
				URLs:      hopt.ConnectionTestUrls,
				IpInfoURL: hopt.IpInfoUrl,
				// each proxy's IPv6 is verified once at its URL test, with the same test URL over
				// IPv6, when the apps get IPv6 at all (see ipv6ForClients)
				VerifyIPv6:     ipv6ForClients(hopt.IPv6Mode),
				Interval:       badoption.Duration(urlTestInterval(hopt)),
				DebounceWindow: badoption.Duration(time.Millisecond * 500),
				IdleTimeout:    badoption.Duration(urlTestInterval(hopt).Nanoseconds() * 3),
				// no "handshake storm" (HC-09, HC-10): two proxies at a time; never the direct
				// outbounds (their test and IP lookup go from the device's own address); no IP
				// lookup unless asked for; after a network change only the proxies in use; the
				// UDP endpoints only when selected or asked for
				Workers:               monitoringWorkers(hopt),
				ExcludeTypes:          []string{C.TypeDirect, C.TypeBlock, C.TypeDNS},
				OnDemandTypes:         onDemandTypes(hopt),
				RetestOnNetworkChange: retestOnNetworkChange(hopt),
				DisableIPInfo:         !hopt.IpInfo,
			},
			HandshakeGate: handshakeGate(hopt),
		}
	}
	setProcs(options)
}

// The pacing of the TLS handshakes to one server (the address, whatever the server name), in one
// place. A DPI rule described for Russian networks freezes a server for a client for minutes after
// more than three TLS handshakes to it within a minute with less than about 350-400 ms between
// them (research O1). So:
//   - one handshake at a time: a connection waits for the previous handshake to end;
//   - a gap drawn anew between 0.7 and 1.1 s before each handshake: a margin of about twice the
//     threshold, which a network that squeezes two packets together does not eat, and no fixed
//     rhythm to match;
//   - at most 4 handshakes starting in any 5 s: the start of the tunnel, a test of every proxy or
//     a reconnection after a network change opens its connections in a row, never in a burst.
//
// Ordinary work is not slowed: the transports of the subscription (gRPC, XHTTP) keep one or two
// long-lived multiplexed connections, which handshake once. What waits is a series: the second
// proxy of the automatic group is tested about 0.3-0.7 s later than with the old 450 ms gap, a test
// of six proxies takes about 6 s instead of 2.5 s, and a transport without multiplexing
// (WebSocket, HTTPUpgrade) opens its connections at this pace.
const (
	handshakeGateMaxInflight = 1
	handshakeGateMinGap      = 700 * time.Millisecond
	handshakeGateMaxGap      = 1100 * time.Millisecond
	handshakeGateWindow      = 5 * time.Second
	handshakeGateWindowMax   = 4
)

// handshakeGate paces the TLS handshakes to one server (see above), unless the user turned it off
// (handshake-gate false). handshake-gate-max and handshake-gate-gap-ms, when set, replace the
// number at a time and the shortest gap; the spread of the gap stays.
func handshakeGate(hopt *HiddifyOptions) *option.HandshakeGateOptions {
	if hopt.HandshakeGate != nil && !*hopt.HandshakeGate {
		return nil
	}
	maxInflight := handshakeGateMaxInflight
	if hopt.HandshakeGateMax > 0 {
		maxInflight = hopt.HandshakeGateMax
	}
	minGap, maxGap := handshakeGateMinGap, handshakeGateMaxGap
	if hopt.HandshakeGateGapMs > 0 {
		minGap = time.Duration(hopt.HandshakeGateGapMs) * time.Millisecond
		maxGap = minGap + (handshakeGateMaxGap - handshakeGateMinGap)
	}
	return &option.HandshakeGateOptions{
		Enabled:     true,
		MaxInflight: maxInflight,
		MinGap:      badoption.Duration(minGap),
		MaxGap:      badoption.Duration(maxGap),
		Window:      badoption.Duration(handshakeGateWindow),
		WindowMax:   handshakeGateWindowMax,
	}
}

// defaultURLTestInterval is the time between the regular tests of the proxies, in seconds: 30
// minutes, and never under minURLTestInterval (it was 10 minutes, to every proxy at once).
const (
	defaultURLTestInterval = 1800
	minURLTestInterval     = 300
)

func urlTestInterval(hopt *HiddifyOptions) time.Duration {
	interval := hopt.URLTestInterval.Duration()
	if interval <= 0 {
		interval = defaultURLTestInterval * time.Second
	}
	if interval < minURLTestInterval*time.Second {
		interval = minURLTestInterval * time.Second
	}
	return interval
}

// monitoringWorkers is how many proxies are tested at a time: 2 unless set, at most 4.
func monitoringWorkers(hopt *HiddifyOptions) int {
	switch {
	case hopt.MonitoringWorkers <= 0:
		return 2
	case hopt.MonitoringWorkers > 4:
		return 4
	}
	return hopt.MonitoringWorkers
}

// lazyQuietTunnels makes the AmneziaWG and WireGuard client endpoints outside the automatic groups
// lazy (the fork's lazy endpoints): only their options until a connection or a test goes through
// them, closed again once idle. A tunnel's device started with the box handshakes with its server,
// and an endpoint tests itself when it comes up: a reserve nobody chose, the last resort above all,
// talked to its server at every start and kept a keepalive to it, which marks the server's address
// for anyone who watches UDP. A chain hop is never lazy (see isChainHop).
func lazyQuietTunnels(endpoints []option.Endpoint, autoTags []string) {
	auto := map[string]bool{}
	for _, tag := range autoTags {
		auto[tag] = true
	}
	for i := range endpoints {
		end := &endpoints[i]
		if !udpEndpointTypes[end.Type] || auto[end.Tag] || isChainHop(end.Tag) {
			continue
		}
		switch options := end.Options.(type) {
		case *option.AwgEndpointOptions:
			end.Lazy = options.ListenPort == 0
		case *option.WireGuardEndpointOptions:
			end.Lazy = options.ListenPort == 0
		}
	}
}

// udpEndpointTypes are the endpoints kept out of the automatic groups and the regular tests.
var udpEndpointTypes = map[string]bool{C.TypeAwg: true, C.TypeWireGuard: true}

func onDemandTypes(hopt *HiddifyOptions) []string {
	if hopt.UDPEndpointsInAuto {
		return nil
	}
	return []string{C.TypeAwg, C.TypeWireGuard}
}

func retestOnNetworkChange(hopt *HiddifyOptions) string {
	switch hopt.RetestOnNetworkChange {
	case "all", "none", "selected":
		return hopt.RetestOnNetworkChange
	}
	return "selected"
}

// setProcs lets the core run on as few Go processors as its load needs (one, most of the time)
// instead of one for every CPU core: with spare processors the runtime wakes a thread for each
// packet a goroutine hands to the next, and on a tunnel that is most of the CPU the core uses.
// A download through QUIC, WireGuard or OpenVPN takes about half the CPU with it, at the same
// speed. See adaptive-processors in the hiddify-sing-box docs.
func setProcs(options *option.Options) {
	if options.Experimental == nil {
		options.Experimental = &option.ExperimentalOptions{}
	}
	if options.Experimental.Debug == nil {
		options.Experimental.Debug = &option.DebugOptions{}
	}
	if options.Experimental.Debug.Procs == nil {
		options.Experimental.Debug.Procs = &option.HProcsOptions{Enabled: true}
	}
}

func setLog(options *option.Options, opt *HiddifyOptions) {
	options.Log = &option.LogOptions{
		Level:        opt.LogLevel,
		Output:       opt.LogFile,
		Disabled:     false,
		Timestamp:    false,
		DisableColor: true,
	}
}
func isIPv6Supported() bool {
	if C.IsIos || C.IsDarwin {
		return true
	}
	_, err := net.ResolveIPAddr("ip6", "::1")
	return err == nil
}

// dnsStrategy is the strategy of a DNS rule: the explicit setting when there is one, else what
// the IPv6 mode asks. Neither ever becomes ipv4_only or ipv6_only: the core's own lookups then
// favour one family, but a client still gets both A and AAAA, and a config whose server has only
// the other family still routes (hiddify-app #2307, #2420 are about IPv6-first sites on proxies
// without IPv6; the mode used to reach only the local listeners).
func dnsStrategy(explicit, ipv6Mode option.DomainStrategy) option.DomainStrategy {
	strategy := explicit
	if strategy == option.DomainStrategy(C.DomainStrategyAsIS) {
		strategy = ipv6Mode
	}
	switch strategy {
	case option.DomainStrategy(C.DomainStrategyIPv4Only):
		return option.DomainStrategy(C.DomainStrategyPreferIPv4)
	case option.DomainStrategy(C.DomainStrategyIPv6Only):
		return option.DomainStrategy(C.DomainStrategyPreferIPv6)
	}
	return strategy
}

// ipv6ForClients says whether the apps on the device get IPv6 at all: AAAA answers, and IPv6
// connections through the proxy. Off unless the IPv6 mode turns it on (the user, or a
// subscription's ipv6-mode header): most proxies' exits have no IPv6, and a proxy accepts an
// IPv6 connection and then closes it, which a browser shows as a dead site and never retries over
// IPv4 (hiddify-app #2307, #2420). On, IPv6 goes only through a proxy found carrying it: the
// monitoring verifies each proxy once at its URL test (verify_ipv6), the router carries over IPv4
// a connection the proxy cannot (ipv6_fallback) and learns from it, and the DNS and route rules
// (ipv6_by_outbound, ipv6_unavailable_via) keep IPv6 away from a proxy found without. The core's
// own lookups (the proxy's address, the test URLs) use both families either way, by dnsStrategy.
func ipv6ForClients(ipv6Mode option.DomainStrategy) bool {
	switch ipv6Mode {
	case option.DomainStrategy(C.DomainStrategyPreferIPv4), option.DomainStrategy(C.DomainStrategyPreferIPv6), option.DomainStrategy(C.DomainStrategyIPv6Only):
		return true
	}
	return false
}

// ipv6ByOutbound names the outbound whose IPv6, as the monitoring knows it, limits a DNS rule's
// AAAA answers: the detour the rule's traffic takes, when the apps get IPv6 at all.
func ipv6ByOutbound(hopt *HiddifyOptions, detour string) string {
	if !ipv6ForClients(hopt.IPv6Mode) {
		return ""
	}
	return detour
}

// clientDNSStrategy is the strategy of a DNS rule that answers the apps: ipv4_only unless the
// IPv6 mode turns IPv6 on (then the mode's preference, see dnsStrategy), or the explicit setting
// names IPv6 itself, which is kept as asked.
func clientDNSStrategy(explicit, ipv6Mode option.DomainStrategy) option.DomainStrategy {
	switch explicit {
	case option.DomainStrategy(C.DomainStrategyPreferIPv6), option.DomainStrategy(C.DomainStrategyIPv6Only):
		return explicit
	}
	if !ipv6ForClients(ipv6Mode) {
		return option.DomainStrategy(C.DomainStrategyIPv4Only)
	}
	return dnsStrategy(explicit, ipv6Mode)
}

// shouldEnableIPv6 says whether the local listeners also bind IPv6: whenever the host has it. The
// IPv6 mode is a preference between the families, never a switch; it used to leave ::1 unbound.
func shouldEnableIPv6() bool {
	return isIPv6Supported()
}

func setInbound(options *option.Options, hopt *HiddifyOptions) error {
	// var inboundDomainStrategy option.DomainStrategy
	// if !opt.ResolveDestination {
	// 	inboundDomainStrategy = option.DomainStrategy(dns.DomainStrategyAsIS)
	// } else {
	// 	inboundDomainStrategy = opt.IPv6Mode
	// }
	ipv6Enable := shouldEnableIPv6()
	if hopt.EnableTun {

		opts := option.TunInboundOptions{
			Stack:       TunStack(hopt.TUNStack),
			MTU:         hopt.MTU,
			AutoRoute:   true,
			StrictRoute: hopt.StrictRoute,
			// nftables routing on Linux, with pre-matching through nfqueue: better routing and
			// performance than the TUN alone, and no conflict with Docker bridges. Left out where it
			// cannot run, and after a start it made fail (see AutoRedirectFailed). Router mode
			// always asks for it (see router_mode.go).
			AutoRedirect: tunAutoRedirect(hopt),

			// EndpointIndependentNat: true,
			// GSO:                    runtime.GOOS != "windows",

		}
		applyPerAppTun(&opts, hopt)
		tunInbound := option.Inbound{
			Type: C.TypeTun,
			Tag:  InboundTUNTag,

			Options: &opts,
		}
		// switch hopt.IPv6Mode {
		// case option.DomainStrategy(C.DomainStrategyIPv4Only):
		// 	opts.Address = []netip.Prefix{
		// 		netip.MustParsePrefix("172.19.0.1/28"),
		// 	}
		// case option.DomainStrategy(dns.DomainStrategyUseIPv6):
		// 	opts.Address = []netip.Prefix{
		// 		netip.MustParsePrefix("fdfe:dcba:9876::1/126"),
		// 	}
		// default:

		// }
		// IPv4 and IPv6, always on the TUN when auto-routing. Without the IPv6 one, sing-tun
		// installs no ::/0 and IPv6 bypasses the VPN (NE builds guard this in Swift;
		// admin_bgservice / desktop TUN must do it here). ipv6Mode only affects DNS strategy below.
		// Random per installation with tun-address-seed (tun_address.go).
		opts.Address = tunAddresses(hopt)

		options.Inbounds = append(options.Inbounds, tunInbound)

	}

	listeners, err := proxyListeners(hopt, ipv6Enable)
	if err != nil {
		return err
	}
	for _, listener := range listeners {
		addr := badoption.Addr(listener.addr)
		options.Inbounds = append(options.Inbounds, option.Inbound{
			Type: C.TypeMixed,
			Tag:  listener.tag,
			Options: &option.HTTPMixedInboundOptions{
				ListenOptions:  option.ListenOptions{Listen: &addr, ListenPort: listener.port},
				Users:          listener.users,
				SetSystemProxy: listener.systemProxy,
				DisableUDP:     !listener.udp,
			},
		})
	}

	if !transparentPortsOpen(hopt) {
		return nil
	}
	// the transparent ports, on the addresses they always had: every one while shared (a Linux
	// gateway sends the network's traffic to them), this device's own otherwise
	binds := []string{"127.0.0.1"}
	if ipv6Enable {
		binds = append(binds, "::1")
	}
	if hopt.AllowConnectionFromLAN {
		binds = []string{"0.0.0.0"}
		if ipv6Enable {
			binds = []string{"::"}
		}
	}
	for _, bind := range binds {
		addr := badoption.Addr(netip.MustParseAddr(bind))
		listen := option.ListenOptions{Listen: &addr}
		if tproxyAvailable() && portEnabled(hopt.EnableTProxyPort, hopt.TProxyPort, false) {
			listen.ListenPort = hopt.TProxyPort
			options.Inbounds = append(options.Inbounds, option.Inbound{
				Type:    C.TypeTProxy,
				Tag:     InboundTProxy + bind,
				Options: &option.TProxyInboundOptions{ListenOptions: listen},
			})
		}
		if redirectAvailable() && portEnabled(hopt.EnableRedirectPort, hopt.RedirectPort, false) {
			listen.ListenPort = hopt.RedirectPort
			options.Inbounds = append(options.Inbounds, option.Inbound{
				Type:    C.TypeRedirect,
				Tag:     InboundRedirect + bind,
				Options: &option.RedirectInboundOptions{ListenOptions: listen},
			})
		}
		if !C.IsAndroid && !C.IsIos && portEnabled(hopt.EnableDirectPort, hopt.DirectPort, false) {
			listen.ListenPort = hopt.DirectPort
			options.Inbounds = append(options.Inbounds, option.Inbound{
				Type:    C.TypeDirect,
				Tag:     InboundDirectTag + bind,
				Options: &option.DirectInboundOptions{ListenOptions: listen},
			})
		}
	}
	return nil
}

func setRoutingOptions(options *option.Options, hopt *HiddifyOptions) error {
	dnsRules := []option.DefaultDNSRule{}
	routeRules := []option.Rule{}
	rulesets := []option.RuleSet{}

	// if opt.EnableTun && runtime.GOOS == "android" {
	// 	// routeRules = append(
	// 	// 	routeRules,
	// 	// 	option.Rule{
	// 	// 		Type: C.RuleTypeDefault,

	// 	// 		DefaultOptions: option.DefaultRule{
	// 	// 			Inbound:     []string{InboundTUNTag},
	// 	// 			PackageName: []string{"app.hiddify.com"},
	// 	// 			Outbound:    OutboundBypassTag,
	// 	// 		},
	// 	// 	},
	// 	// )
	// }
	// if opt.EnableTun && runtime.GOOS == "windows" {
	// 	// routeRules = append(
	// 	// 	routeRules,
	// 	// 	option.Rule{
	// 	// 		Type: C.RuleTypeDefault,
	// 	// 		DefaultOptions: option.DefaultRule{
	// 	// 			ProcessName: []string{"Hiddify", "Hiddify.exe", "HiddifyCli", "HiddifyCli.exe"},
	// 	// 			Outbound:    OutboundBypassTag,
	// 	// 		},
	// 	// 	},
	// 	// )
	// }

	// dnsRules = append(dnsRules, option.DefaultDNSRule{
	// 	RawDefaultDNSRule: option.RawDefaultDNSRule{},
	// 	DNSRuleAction: option.DNSRuleAction{
	// 		Action: C.RuleActionTypeRoute,
	// 		RouteOptions: option.DNSRouteActionOptions{
	// 			Server:         DNSStaticTag,
	// 			BypassIfFailed: false,
	// 		},
	// 	},
	// },
	// )
	// first of all: the flows of an app the VPN does not cover, sent into the TUN anyway (leak B),
	// rejected before any other rule sees them, and before the handshake (see per_app.go)
	if strictOwnerFilter(hopt) {
		if tun := tunInboundOptions(options); tun != nil {
			routeRules = append(routeRules, ownerFilterRules(hopt, tun)...)
		}
	}
	forceDirectRules, err := addForceDirect(options, hopt)
	if err != nil {
		return err
	}

	dnsRules = append(dnsRules, forceDirectRules...)

	// SP3-06: the TUN's own subnets come before every other rule (tun_subnet.go).
	if tun := tunInboundOptions(options); tun != nil {
		routeRules = append(routeRules, tunSubnetRules(tun)...)
	}

	// An IPv6 connection is refused at once, before its handshake, so the app falls back to IPv4
	// instead of being accepted and then closed by the proxy: every one while IPv6 is off for the
	// apps (see ipv6ForClients); otherwise those through a proxy the monitoring found without
	// IPv6 (ipv6_unavailable_via), the others going on, carried over IPv4 by the router when the
	// proxy turns out not to carry them. The rule goes before the sniff rule: the TUN judges a
	// TCP connection before its handshake only up to the first rule that needs the stream, and a
	// reject after the handshake is the very "connection closed" the browser gives up on. The TUN
	// keeps ::/0, so nothing leaks around the VPN. The LAN keeps its IPv6 when the LAN is bypassed.
	{
		if hopt.BypassLAN && (hopt.RouteRule == nil || hopt.RouteRule.RouteRule == nil) {
			routeRules = append(routeRules, option.Rule{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{IPVersion: 6, IPIsPrivate: true},
					RuleAction: option.RuleAction{
						Action:       C.RuleActionTypeRoute,
						RouteOptions: option.RouteActionOptions{Outbound: OutboundDirectTag},
					},
				},
			})
		}
		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{IPVersion: 6, IPv6UnavailableVia: ipv6ByOutbound(hopt, OutboundMainDetour)},
				RuleAction: option.RuleAction{
					Action:        C.RuleActionTypeReject,
					RejectOptions: option.RejectActionOptions{Method: C.RuleActionRejectMethodDefault},
				},
			},
		})
	}
	routeRules = append(routeRules, option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeSniff,
			},
		},
	})
	routeRules = append(routeRules, option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{
				Protocol: []string{C.ProtocolDNS},
			},
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeHijackDNS,
			},
		},
	})
	routeRules = append(routeRules, option.Rule{
		Type: C.RuleTypeDefault,

		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{
				IPCIDR: prefixables([]string{
					"10.10.34.0/24",
					"2001:4188:2:600:10:10:34:0/120",
				}),
			},
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.RouteActionOptions{
					Outbound: OutboundMainDetour,
				},
			},
		},
	})
	// {
	// 	Type: C.RuleTypeDefault,
	// 	DefaultOptions: option.DefaultRule{
	// 		ClashMode: "Direct",
	// 		Outbound:  OutboundDirectTag,
	// 	},
	// },
	// {
	// 	Type: C.RuleTypeDefault,
	// 	DefaultOptions: option.DefaultRule{
	// 		ClashMode: "Global",
	// 		Outbound:  OutboundMainProxyTag,
	// 	},
	// },	}

	appRules := buildAppRouteRules(hopt)
	useAppRules := hopt.RouteRule != nil && hopt.RouteRule.RouteRule != nil
	if useAppRules {
		routeRules = append(routeRules, appRules.routeRules...)
	}
	if !useAppRules && hopt.BypassLAN {
		routeRules = append(
			routeRules,
			option.Rule{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{
						IPIsPrivate: true,
					},
					RuleAction: option.RuleAction{
						Action: C.RuleActionTypeRoute,
						RouteOptions: option.RouteActionOptions{
							Outbound: OutboundDirectTag,
						},
					},
				},
			},
		)
	}

	// for _, rule := range opt.Rules {
	// 	routeRule := rule.MakeRule()
	// 	switch rule.Outbound {
	// 	case "bypass":
	// 		routeRule.Outbound = OutboundBypassTag
	// 	case "block":
	// 		routeRule.Outbound = OutboundBlockTag
	// 	case "proxy":
	// 		routeRule.Outbound = OutboundMainProxyTag
	// 	}

	// 	if routeRule.IsValid() {
	// 		routeRules = append(
	// 			routeRules,
	// 			option.Rule{
	// 				Type:           C.RuleTypeDefault,
	// 				DefaultOptions: routeRule,
	// 			},
	// 		)
	// 	}

	// 	dnsRule := rule.MakeDNSRule()
	// 	switch rule.Outbound {
	// 	case "bypass":
	// 		dnsRule.Server = DNSDirectTag
	// 	case "block":
	// 		dnsRule.Server = DNSBlockTag
	// 		dnsRule.DisableCache = true
	// 	case "proxy":
	// 		if opt.EnableFakeDNS {
	// 			fakeDnsRule := dnsRule
	// 			fakeDnsRule.Server = DNSFakeTag
	// 			fakeDnsRule.Inbound = []string{InboundTUNTag, InboundMixedTag}
	// 			dnsRules = append(dnsRules, fakeDnsRule)
	// 		}
	// 		dnsRule.Server = DNSRemoteTag
	// 	}
	// 	dnsRules = append(dnsRules, dnsRule)
	// }
	forceDirectRoute := make([]string, 0)
	if options.NTP != nil && options.NTP.Enabled {
		forceDirectRoute = append(forceDirectRoute, options.NTP.Server)
	}

	// parsedURL, err := url.Parse(opt.ConnectionTestUrl)
	// if err == nil {
	// 	dnsRules = append(dnsRules, option.DefaultDNSRule{
	// 		Domain:       []string{parsedURL.Host},
	// 		Server:       DNSRemoteTag,
	// 		RewriteTTL:   &dnsCPttl,
	// 		DisableCache: false,
	// 	})
	// }

	if len(forceDirectRoute) > 0 {

		dnsRules = append(dnsRules, option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{
				Domain: forceDirectRoute,
			},
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{
					Server: DNSMultiDirectTag,
					AbstractDNSRouteActionOptions: option.AbstractDNSRouteActionOptions{
						Strategy:       clientDNSStrategy(hopt.DirectDnsDomainStrategy, hopt.IPv6Mode),
						IPv6ByOutbound: ipv6ByOutbound(hopt, OutboundDirectTag),
						RewriteTTL:     &DEFAULT_DNS_TTL,
						DisableCache:   false,
						BypassIfFailed: false,
					},
				},
			},
		})
		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					Domain: forceDirectRoute,
				},
				RuleAction: option.RuleAction{
					Action: C.RuleActionTypeRoute,
					RouteOptions: option.RouteActionOptions{
						Outbound: OutboundDirectTag,
					},
				},
			},
		})
	}
	rejectRCode := (option.DNSRCode(sdns.RcodeRefused))
	rejectDnsAction := option.DNSRuleAction{
		Action: C.RuleActionTypePredefined,
		PredefinedOptions: option.DNSRouteActionPredefined{
			Rcode: &rejectRCode,
		},
	}
	if useAppRules {
		dnsRules = append(dnsRules, appRules.dnsRules...)
		rulesets = append(rulesets, appRules.ruleSets...)
	}
	if !useAppRules && hopt.BlockAds {
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    badoption.Listable[string]{"geosite-ads"},
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geosite-category-ads-all.srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
				DownloadDetour: OutboundSelectTag,
			},
		})
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    badoption.Listable[string]{"geosite-malware"},
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geosite-malware.srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
				DownloadDetour: OutboundSelectTag,
			},
		})
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    badoption.Listable[string]{"geosite-phishing"},
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geosite-phishing.srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
				DownloadDetour: OutboundSelectTag,
			},
		})
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    badoption.Listable[string]{"geosite-cryptominers"},
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geosite-cryptominers.srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
				DownloadDetour: OutboundSelectTag,
			},
		})
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    badoption.Listable[string]{"geoip-phishing"},
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geoip-phishing.srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
				DownloadDetour: OutboundSelectTag,
			},
		})
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    badoption.Listable[string]{"geoip-malware"},
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geoip-malware.srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
				DownloadDetour: OutboundSelectTag,
			},
		})

		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					RuleSet: []string{
						"geosite-ads",
						"geosite-malware",
						"geosite-phishing",
						"geosite-cryptominers",
						"geoip-malware",
						"geoip-phishing",
					},
				},
				RuleAction: option.RuleAction{
					Action: C.RuleActionTypeReject,
					RejectOptions: option.RejectActionOptions{
						Method: C.RuleActionRejectMethodDefault,
					},
				},
			},
		})
		dnsRules = append(dnsRules, option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{

				RuleSet: []string{
					"geosite-ads",
					"geosite-malware",
					"geosite-phishing",
					"geosite-cryptominers",
				},
			},
			DNSRuleAction: rejectDnsAction,
		})
	}
	if !useAppRules && hopt.Region != "other" {
		dnsRules = append(dnsRules, option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{
				DomainSuffix: regionDomainSuffixes(hopt.Region),
			},
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{
					Server: DNSMultiDirectTag,
					AbstractDNSRouteActionOptions: option.AbstractDNSRouteActionOptions{
						Strategy:       clientDNSStrategy(hopt.DirectDnsDomainStrategy, hopt.IPv6Mode),
						IPv6ByOutbound: ipv6ByOutbound(hopt, OutboundDirectTag),
						RewriteTTL:     &DEFAULT_DNS_TTL,
						BypassIfFailed: false,
					},
				},
			},
		})
		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					DomainSuffix: regionDomainSuffixes(hopt.Region),
				},
				RuleAction: option.RuleAction{
					Action: C.RuleActionTypeRoute,
					RouteOptions: option.RouteActionOptions{
						Outbound: OutboundDirectTag,
					},
				},
			},
		})

		dnsRules = append(dnsRules, option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{

				RuleSet: []string{
					"geosite-" + hopt.Region,
				},
			},
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{
					Server: DNSMultiDirectTag,
					AbstractDNSRouteActionOptions: option.AbstractDNSRouteActionOptions{
						Strategy:       clientDNSStrategy(hopt.DirectDnsDomainStrategy, hopt.IPv6Mode),
						IPv6ByOutbound: ipv6ByOutbound(hopt, OutboundDirectTag),
						RewriteTTL:     &DEFAULT_DNS_TTL,
						BypassIfFailed: false,
					},
				},
			},
		})

		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    badoption.Listable[string]{"geoip-" + hopt.Region},
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/country/geoip-" + hopt.Region + ".srs",
				InitialPath:    ruleSetInitialPath(hopt, "geoip-"+hopt.Region+".srs"),
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
				DownloadDetour: OutboundSelectTag, // through the VPN, never from the device's own address
			},
		})
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    badoption.Listable[string]{"geosite-" + hopt.Region},
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/country/geosite-" + hopt.Region + ".srs",
				InitialPath:    ruleSetInitialPath(hopt, "geosite-"+hopt.Region+".srs"),
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
				DownloadDetour: OutboundSelectTag, // through the VPN
			},
		})

		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					RuleSet: []string{
						"geoip-" + hopt.Region,
						"geosite-" + hopt.Region,
					},
				},
				RuleAction: option.RuleAction{
					Action: C.RuleActionTypeRoute,
					RouteOptions: option.RouteActionOptions{
						Outbound: OutboundDirectTag,
					},
				},
			},
		})
	}
	if hopt.RouteOptions.BlockQuic {
		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					Protocol: []string{C.ProtocolQUIC},
				},
				RuleAction: option.RuleAction{
					Action: C.RuleActionTypeReject,
					RejectOptions: option.RejectActionOptions{
						Method: C.RuleActionRejectMethodDefault,
					},
				},
			},
		})
	}
	options.Route = &option.RouteOptions{
		Rules:               routeRules,
		Final:               OutboundMainDetour,
		IPv6Fallback:        ipv6ForClients(hopt.IPv6Mode), // see ipv6ForClients
		AutoDetectInterface: autoDetectInterface(hopt, C.IsAndroid, C.IsIos),
		DefaultDomainResolver: &option.DomainResolveOptions{
			Server:   serverNamesResolver(hopt),
			Strategy: dnsStrategy(hopt.DirectDnsDomainStrategy, hopt.IPv6Mode),
		},
		// OverrideAndroidVPN: hopt.EnableTun && C.IsAndroid,
		RuleSet:     rulesets,
		FindProcess: false,
		// GeoIP: &option.GeoIPOptions{
		// 	Path: opt.GeoIPPath,
		// },
		// Geosite: &option.GeositeOptions{
		// 	Path: opt.GeoSitePath,
		// },
	}
	// if opt.EnableDNSRouting {
	if hopt.EnableFakeDNS {
		// inbounds := []string{InboundTUNTag}
		// for _, inp := range options.Inbounds {
		// 	if strings.Contains(inp.Tag, InboundDirectTag) || strings.Contains(inp.Tag, InboundRedirect) || strings.Contains(inp.Tag, InboundTProxy) {
		// 		inbounds = append(inbounds, inp.Tag)
		// 	}
		// }
		dnsRules = append(
			dnsRules,
			option.DefaultDNSRule{
				// No query_type matcher: it takes sing-box out of the legacy DNS mode, and the
				// strategy the rules set is fatal outside it (the core stopped at Connecting).
				// The fake IP server answers only A and AAAA and fails the rest, which
				// bypass_if_failed sends on to the remote rule below.
				RawDefaultDNSRule: option.RawDefaultDNSRule{
					// Inbound: inbounds,
				},
				DNSRuleAction: option.DNSRuleAction{
					Action: C.RuleActionTypeRoute,
					RouteOptions: option.DNSRouteActionOptions{
						Server: DNSFakeTag,
						AbstractDNSRouteActionOptions: option.AbstractDNSRouteActionOptions{
							Strategy:       clientDNSStrategy(hopt.RemoteDnsDomainStrategy, hopt.IPv6Mode),
							IPv6ByOutbound: ipv6ByOutbound(hopt, OutboundMainDetour),
							RewriteTTL:     &DEFAULT_DNS_TTL,
							DisableCache:   true,
							BypassIfFailed: true,
						},
					},
				},
			})

	}

	dnsRules = append(dnsRules, option.DefaultDNSRule{
		RawDefaultDNSRule: option.RawDefaultDNSRule{},
		DNSRuleAction: option.DNSRuleAction{
			Action: C.RuleActionTypeRoute,
			RouteOptions: option.DNSRouteActionOptions{
				Server: DNSMultiRemoteTag,
				AbstractDNSRouteActionOptions: option.AbstractDNSRouteActionOptions{
					// no AAAA for the apps unless the IPv6 mode turns IPv6 on, and then none
					// through a proxy found without IPv6 (hiddify-app #2307, #2420)
					Strategy:       clientDNSStrategy(hopt.RemoteDnsDomainStrategy, hopt.IPv6Mode),
					IPv6ByOutbound: ipv6ByOutbound(hopt, OutboundMainDetour),
					RewriteTTL:     &DEFAULT_DNS_TTL,
					BypassIfFailed: false,
				},
			},
		},
	},
	)
	// dnsRules = append(dnsRules, option.DefaultDNSRule{
	// 	RawDefaultDNSRule: option.RawDefaultDNSRule{},
	// 	DNSRuleAction: option.DNSRuleAction{
	// 		Action: C.RuleActionTypeRoute,
	// 		RouteOptions: option.DNSRouteActionOptions{
	// 			Server:         DNSRemoteTagFallback,
	// 			Strategy:       dnsStrategy(hopt.RemoteDnsDomainStrategy, hopt.IPv6Mode),
	// 			RewriteTTL:     &DEFAULT_DNS_TTL,
	// 			BypassIfFailed: false,
	// 		},
	// 	},
	// },
	// )

	// dnsRules = append(dnsRules, option.DefaultDNSRule{

	// 	RawDefaultDNSRule: option.RawDefaultDNSRule{},
	// 	DNSRuleAction: option.DNSRuleAction{
	// 		Action: C.RuleActionTypeRoute,
	// 		RouteOptions: option.DNSRouteActionOptions{
	// 			Server:         DNSTricksDirectTag,
	// 			BypassIfFailed: false,
	// 		},
	// 	},
	// },
	// )
	// dnsRules = append(dnsRules, option.DefaultDNSRule{
	// 	RawDefaultDNSRule: option.RawDefaultDNSRule{},
	// 	DNSRuleAction: option.DNSRuleAction{
	// 		Action: C.RuleActionTypeRoute,
	// 		RouteOptions: option.DNSRouteActionOptions{
	// 			Server:         DNSDirectTag,
	// 			BypassIfFailed: false,
	// 		},
	// 	},
	// },
	// )
	// dnsRules = append(dnsRules, option.DefaultDNSRule{
	// 	RawDefaultDNSRule: option.RawDefaultDNSRule{},
	// 	DNSRuleAction: option.DNSRuleAction{
	// 		Action: C.RuleActionTypeRoute,
	// 		RouteOptions: option.DNSRouteActionOptions{
	// 			Server: DNSLocalTag,
	// 			// BypassIfFailed: false,
	// 		},
	// 	},
	// },
	// )

	for _, dnsRule := range dnsRules {
		if dnsRule.IsValid() {
			options.DNS.Rules = append(
				options.DNS.Rules,
				option.DNSRule{
					Type:           C.RuleTypeDefault,
					DefaultOptions: dnsRule,
				},
			)
		}
	}
	// }
	return nil
}

var (
	ipMaps      = map[string][]string{}
	ipMapsMutex sync.Mutex
)

func getIPs(domains ...string) []string {
	var wg sync.WaitGroup
	resChan := make(chan string, len(domains)*10) // Collect both IPv4 and IPv6
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	for _, d := range domains {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", domain)
			if err != nil {
				return
			}
			for _, ip := range ips {
				ipStr := ip.String()
				if !isBlockedIP(ipStr) {
					resChan <- ipStr
				}
			}
		}(d)
	}

	go func() {
		wg.Wait()
		close(resChan)
	}()

	var res []string
	for ip := range resChan {
		res = append(res, ip)
	}
	if len(res) == 0 && ipMaps[domains[0]] != nil {
		return ipMaps[domains[0]]
	}
	ipMapsMutex.Lock()
	ipMaps[domains[0]] = res
	ipMapsMutex.Unlock()

	return res
}

func isBlockedDomain(domain string) bool {
	if strings.HasPrefix(domain, "full:") {
		return false
	}
	if strings.Contains(domain, "instagram") || strings.Contains(domain, "facebook") || strings.Contains(domain, "telegram") || strings.Contains(domain, "t.me") {
		return true
	}
	ips := getIPs(domain)
	if len(ips) == 0 {
		// fmt.Println(err)
		return true
	}

	// // Print the IP addresses associated with the domain
	// fmt.Printf("IP addresses for %s:\n", domain)
	// for _, ip := range ips {
	// 	if isBlockedIP(ip) {
	// 		return true
	// 	}
	// }
	return false
}

func isBlockedIP(ip string) bool {
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "2001:4188:2:600:10") {
		return true
	}
	return false
}

func removeDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

// defaultClashApiSecret is generated once per process, so the same settings build the same
// config (hot reload compares the running config with the new one): 32 random bytes (HC-35).
var defaultClashApiSecret = sync.OnceValue(func() string {
	return hex.EncodeToString(randomBytes(32))
})

// defaultClashApiPort is a free loopback port, picked once per process for the same reason.
var defaultClashApiPort = sync.OnceValue(func() uint16 {
	return freeLoopbackPort()
})

// clashAPIOptions is the Clash API: always without a listener on Android and iOS, and on the
// desktop unless the user asked for one (clash-api-listen). Without an external controller the
// clash server still runs in the core, for the traffic statistics the app reads over gRPC, and
// opens no port (HC-04). With one: 127.0.0.1 only, a port of its own (the fixed 16756 is what
// a port scan knows Hiddify by), a secret of 32 random bytes unless the user set a long one, and
// no cross-origin access from web pages.
func clashAPIOptions(hopt *HiddifyOptions) *option.ClashAPIOptions {
	if !clashAPIListens(hopt) {
		return &option.ClashAPIOptions{}
	}
	port := hopt.ClashApiPort
	if port == 0 || port == legacyClashApiPort {
		port = defaultClashApiPort()
	}
	secret := hopt.ClashApiSecret
	if len(secret) < 32 {
		secret = defaultClashApiSecret()
	}
	controller := fmt.Sprintf("127.0.0.1:%d", port)
	return &option.ClashAPIOptions{
		ExternalController:       controller,
		Secret:                   secret,
		AccessControlAllowOrigin: badoption.Listable[string]{"http://" + controller},
	}
}

// legacyClashApiPort is the port the app used to ask for; a listener asked for keeps off it.
const legacyClashApiPort = 16756

// clashAPIListens says whether the Clash API opens a TCP port: never on Android and iOS, where
// any app on the device finds it on the loopback; on the desktop only when asked for.
func clashAPIListens(hopt *HiddifyOptions) bool {
	return hopt.ClashApiListen && !C.IsAndroid && !C.IsIos
}

// freeLoopbackPort is a TCP port free on 127.0.0.1 now, or 0 if none could be had.
func freeLoopbackPort() uint16 {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	defer listener.Close()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

// randomBytes are n bytes from crypto/rand; it panics if the system has no randomness, as a
// secret made from anything else must not be used.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	return b
}

// generateRandomString is a random string of length characters (URL-safe base64 alphabet) from
// crypto/rand. It used to be math/rand with "hiddify" as its fallback (HC-35).
func generateRandomString(length int) string {
	s := base64.RawURLEncoding.EncodeToString(randomBytes((length*6 + 7) / 8))
	return s[:length]
}
