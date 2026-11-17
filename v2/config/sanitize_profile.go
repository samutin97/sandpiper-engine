package config

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// The outbounds and endpoints of an imported profile (subscription, link, QR, deeplink,
// clipboard) are checked before they run (HC-03, HC-19): only the proxy types below, without the
// fields that make the core start a program, read a local file, open a port or leave the VPN.
// What is not allowed is dropped with a warning; a profile left with nothing fails.

// allowedProfileTypes are the outbound and endpoint types an imported profile may have: the
// proxy protocols, WireGuard and AmneziaWG, WARP, and the placeholders the parsers put for a link
// they could not read (hinvalid) or for a core the build lacks (xray).
var allowedProfileTypes = map[string]bool{
	C.TypeVLESS: true, C.TypeVMess: true, C.TypeTrojan: true, C.TypeShadowsocks: true,
	C.TypeShadowsocksR: true, C.TypeShadowTLS: true, C.TypeAnyTLS: true, C.TypeHysteria: true,
	C.TypeHysteria2: true, C.TypeTUIC: true, C.TypeNaive: true, C.TypeSSH: true, C.TypeHTTP: true,
	C.TypeSOCKS: true, C.TypeWireGuard: true, C.TypeLegacyWireGuard: true, C.TypeAwg: true, C.TypeWARP: true,
	C.TypeMASQUE: true, C.TypeMASQUEClient: true, C.TypeMieru: true, C.TypeSnell: true,
	// OpenVPN here is a Go client: no scripts; its *_path fields are stripped like every other
	C.TypeOpenVPNClient:  true,
	C.TypeHInvalidConfig: true, C.TypeXray: true,
	// groups are dropped later by the builder, the profile's own choice of members kept
	C.TypeSelector: true, C.TypeURLTest: true,
}

// silentlyDroppedTypes leave the VPN or do nothing: a profile's direct outbound took part of the
// traffic around the VPN through the balancer (HC-19).
var silentlyDroppedTypes = map[string]bool{C.TypeDirect: true, C.TypeBlock: true, C.TypeDNS: true}

// strippedFields are removed from every outbound and endpoint: binding to an interface or a
// network namespace, a routing mark (around the VPN's own rules), a port to listen on, a second
// system TUN, the interface name of one.
var strippedFields = []string{
	"bind_interface", "inet4_bind_address", "inet6_bind_address", "bind_address_no_port",
	"routing_mark", "netns", "protect_path", "listen_port", "useIntegratedTun", "use_integrated_tun",
	"system", "name",
}

// SanitizeProfileJSON checks the outbounds and endpoints of a profile (a sing-box config as JSON)
// and returns it cleaned, with a warning for each thing it dropped.
func SanitizeProfileJSON(content []byte) ([]byte, []string, error) {
	return sanitizeProfileJSON(content, profilePolicy{allowInsecure: true})
}

func sanitizeProfileJSON(content []byte, policy profilePolicy) ([]byte, []string, error) {
	var config map[string]any
	if err := json.Unmarshal(content, &config); err != nil {
		return nil, nil, err
	}
	warnings := sanitizeProfileMap(config, policy)
	if !hasProfileProxies(config) {
		return nil, warnings, fmt.Errorf("no usable outbound in the profile: %s", strings.Join(warnings, "; "))
	}
	cleaned, err := json.Marshal(config)
	return cleaned, warnings, err
}

func hasProfileProxies(config map[string]any) bool {
	outbounds, _ := config["outbounds"].([]any)
	endpoints, _ := config["endpoints"].([]any)
	return len(outbounds)+len(endpoints) > 0
}

// profilePolicy is what the user allows of a profile beyond the default.
type profilePolicy struct {
	// allowInsecure keeps a TLS client that checks no certificate (insecure without a pin)
	allowInsecure bool
}

// SanitizeProfileMap cleans the "outbounds" and "endpoints" of a decoded config in place, as
// imported: insecure TLS is kept there (the user may allow it later); BuildConfig decides.
func SanitizeProfileMap(config map[string]any) []string {
	return sanitizeProfileMap(config, profilePolicy{allowInsecure: true})
}

func sanitizeProfileMap(config map[string]any, policy profilePolicy) []string {
	var warnings []string
	tags := map[string]bool{}
	for _, key := range []string{"outbounds", "endpoints"} {
		list, _ := config[key].([]any)
		for _, item := range list {
			if obj, ok := item.(map[string]any); ok {
				if tag, ok := obj["tag"].(string); ok {
					tags[tag] = true
				}
			}
		}
	}
	for _, key := range []string{"outbounds", "endpoints"} {
		list, ok := config[key].([]any)
		if !ok {
			continue
		}
		kept := make([]any, 0, len(list))
		for _, item := range list {
			obj, ok := item.(map[string]any)
			if !ok {
				warnings = append(warnings, fmt.Sprintf("%s: an entry that is not an object", key))
				continue
			}
			if err := sanitizeProxyObject(obj, tags, policy); err != nil {
				warnings = append(warnings, err.Error())
				continue
			}
			kept = append(kept, obj)
		}
		config[key] = kept
	}
	return warnings
}

// sanitizeProxyObject cleans one outbound or endpoint, or says why it must go.
func sanitizeProxyObject(obj map[string]any, tags map[string]bool, policy profilePolicy) error {
	typ, _ := obj["type"].(string)
	tag, _ := obj["tag"].(string)
	if !policy.allowInsecure && hasUnpinnedInsecureTLS(obj) {
		return fmt.Errorf("%q: insecure TLS without a certificate pin refused (pinSHA256 / pcs, or allow-insecure)", tag)
	}
	if silentlyDroppedTypes[typ] {
		return fmt.Errorf("%q: type %q dropped (it would take traffic around the VPN)", tag, typ)
	}
	if !allowedProfileTypes[typ] {
		return fmt.Errorf("%q: type %q is not allowed in an imported profile", tag, typ)
	}
	if typ == C.TypeSSH {
		for _, field := range []string{"private_key_path"} {
			if v, ok := obj[field].(string); ok && v != "" {
				return fmt.Errorf("%q: ssh with a local key file is not allowed", tag)
			}
		}
	}
	for _, field := range strippedFields {
		delete(obj, field)
	}
	stripPathFields(obj)
	if detour, ok := obj["detour"].(string); ok && detour != "" && !tags[detour] {
		delete(obj, "detour") // only chains inside the profile
	}
	switch typ {
	case C.TypeAwg:
		return checkAwgObject(obj)
	case C.TypeWireGuard, C.TypeLegacyWireGuard:
		return checkWireGuardPeers(obj)
	}
	return nil
}

// hasUnpinnedInsecureTLS says whether a TLS client of the object (its own, or a transport's,
// such as the XHTTP download channel) checks no certificate: insecure, and no certificate_sha256
// pin. Anyone between the client and the server (a Wi-Fi, the provider's DPI) can then read the
// proxy's password and traffic (HC-02, HC-24).
func hasUnpinnedInsecureTLS(value any) bool {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			if key == "tls" {
				if tls, ok := child.(map[string]any); ok && tls["insecure"] == true && !hasPin(tls["certificate_sha256"]) {
					return true
				}
			}
			if hasUnpinnedInsecureTLS(child) {
				return true
			}
		}
	case []any:
		for _, child := range v {
			if hasUnpinnedInsecureTLS(child) {
				return true
			}
		}
	}
	return false
}

// hasPin: a certificate_sha256 with a value (a list, or one value written alone).
func hasPin(value any) bool {
	switch v := value.(type) {
	case []any:
		return len(v) > 0
	case string:
		return v != ""
	}
	return false
}

// stripPathFields removes, at any depth, the fields naming a local file: *_path (certificates,
// keys, ECH config, wrapper scripts, executables), and the Tor-only program fields.
func stripPathFields(value any) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			if strings.HasSuffix(key, "_path") || key == "executable_path" || key == "extra_args" || key == "data_directory" || key == "torrc" {
				delete(v, key)
				continue
			}
			stripPathFields(child)
		}
	case []any:
		for _, child := range v {
			stripPathFields(child)
		}
	}
}

// AmneziaWG limits (P22): the core panicked or allocated gigabytes on values out of them (HC-21).
const (
	maxAwgJunkCount  = 128
	maxAwgPacketSize = 65507
)

// checkAwgObject checks the AmneziaWG values of an awg endpoint, and writes the header
// protection key as the hex the UAPI reads.
func checkAwgObject(obj map[string]any) error {
	tag, _ := obj["tag"].(string)
	if err := checkWireGuardPeers(obj); err != nil {
		return err
	}
	awg, _ := obj["awg"].(map[string]any)
	if awg == nil {
		return nil
	}
	ints := map[string]int64{}
	for _, key := range []string{"jc", "jmin", "jmax", "s1", "s2", "s3", "s4"} {
		raw, ok := awg[key]
		if !ok {
			continue
		}
		n, err := jsonInt(raw)
		if err != nil || n < 0 {
			return fmt.Errorf("%q: awg %s must be a number of at least 0", tag, key)
		}
		ints[key] = n
	}
	if ints["jc"] > maxAwgJunkCount {
		return fmt.Errorf("%q: awg jc %d is above %d", tag, ints["jc"], maxAwgJunkCount)
	}
	if ints["jmax"] > maxAwgPacketSize || ints["jmin"] > ints["jmax"] && ints["jmax"] != 0 {
		return fmt.Errorf("%q: awg jmin %d / jmax %d: want jmin <= jmax <= %d", tag, ints["jmin"], ints["jmax"], maxAwgPacketSize)
	}
	if ints["jc"] > 0 && ints["jmax"] == 0 {
		return fmt.Errorf("%q: awg jc without jmax", tag)
	}
	for _, key := range []string{"s1", "s2", "s3", "s4"} {
		if ints[key] > 65535 {
			return fmt.Errorf("%q: awg %s above 65535", tag, key)
		}
	}
	for key, raw := range awg {
		if s, ok := raw.(string); ok {
			if strings.ContainsAny(s, "\r\n") {
				return fmt.Errorf("%q: awg %s has a line break", tag, key)
			}
			if len(s) > 65535 {
				return fmt.Errorf("%q: awg %s is too long", tag, key)
			}
		}
	}
	if key, ok := awg["header_protection_key"].(string); ok && key != "" {
		normalized, err := awgHeaderProtectionKeyHex(key)
		if err != nil {
			return fmt.Errorf("%q: awg header_protection_key: %v", tag, err)
		}
		awg["header_protection_key"] = normalized
	}
	return nil
}

// checkWireGuardPeers: a client endpoint has its peers, each with an address and a port; no
// line breaks in the keys (they go into the UAPI text).
func checkWireGuardPeers(obj map[string]any) error {
	tag, _ := obj["tag"].(string)
	for _, field := range []string{"private_key"} {
		if s, ok := obj[field].(string); ok && strings.ContainsAny(s, "\r\n") {
			return fmt.Errorf("%q: %s has a line break", tag, field)
		}
	}
	peers, _ := obj["peers"].([]any)
	for _, p := range peers {
		peer, ok := p.(map[string]any)
		if !ok {
			return fmt.Errorf("%q: a peer that is not an object", tag)
		}
		for key, raw := range peer {
			if s, ok := raw.(string); ok && strings.ContainsAny(s, "\r\n") {
				return fmt.Errorf("%q: peer %s has a line break", tag, key)
			}
		}
	}
	return nil
}

// awgHeaderProtectionKeyHex is the 32-byte key as 64 hex digits, from hex or base64.
func awgHeaderProtectionKeyHex(key string) (string, error) {
	key = strings.TrimSpace(key)
	if len(key) == 64 {
		if _, err := hex.DecodeString(key); err == nil {
			return strings.ToLower(key), nil
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(key); err == nil && len(b) == 32 {
			return hex.EncodeToString(b), nil
		}
	}
	return "", fmt.Errorf("want 32 bytes in hex or base64")
}

func jsonInt(raw any) (int64, error) {
	switch v := raw.(type) {
	case float64:
		return int64(v), nil
	case json.Number:
		return v.Int64()
	case string:
		return strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	}
	return 0, fmt.Errorf("not a number")
}

// SanitizeOptions is input with its outbounds and endpoints checked (SanitizeProfileMap), through
// their JSON; the rest of input is kept as it is.
func SanitizeOptions(ctx context.Context, input *option.Options) (*option.Options, []string, error) {
	return sanitizeOptions(ctx, input, profilePolicy{allowInsecure: true})
}

// sanitizeOptions is SanitizeOptions with the user's policy (BuildConfig).
func sanitizeOptions(ctx context.Context, input *option.Options, policy profilePolicy) (*option.Options, []string, error) {
	if input == nil || len(input.Outbounds)+len(input.Endpoints) == 0 {
		return input, nil, nil
	}
	proxies := option.Options{Outbounds: input.Outbounds, Endpoints: input.Endpoints}
	content, err := proxies.MarshalJSONContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	cleaned, warnings, err := sanitizeProfileJSON(content, policy)
	if err != nil {
		return nil, warnings, err
	}
	var checked option.Options
	if err := checked.UnmarshalJSONContext(ctx, cleaned); err != nil {
		return nil, warnings, err
	}
	sort.Strings(warnings)
	result := *input
	result.Outbounds, result.Endpoints = checked.Outbounds, checked.Endpoints
	return &result, warnings, nil
}
