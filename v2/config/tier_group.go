package config

import (
	"net"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	"github.com/hiddify/hiddify-core/v2/tiered"
)

// The tiered group: the subscription server ranks its proxies (the profile-policy header, read by
// the app and passed as tier-policy), and a selector of the ranked proxies, first in select, lets
// the core choose among them by that ranking (hcore's tiered controller, package v2/tiered). The
// group is a plain sing-box selector: the core only selects in it, the monitoring tests what it
// selects, and nothing in hiddify-sing-box knows of it. Without a policy, or when none of its
// references names a proxy of the profile, nothing changes: no group, select as before.

// OutboundTieredTag is the selector the controller selects in.
const OutboundTieredTag = "tiered"

// TierPolicyOptions is the profile's policy as the app sends it.
type TierPolicyOptions struct {
	// Policy is the profile-policy header in its canonical form; read again here, as strictly.
	Policy string `json:"policy,omitempty"`
	// ProbeHost is the host of the subscription's URL: the checks go to it, through the proxy
	// checked and, for the path check, directly. Never a host from the policy.
	ProbeHost string `json:"probe-host,omitempty"`
	// ProbePath is the get path of the subscription's profile-probe header: a file of 64 KiB or
	// more the checks download the first 64 KiB of. Empty: the checks are URL tests only.
	ProbePath string `json:"probe-path,omitempty"`
}

// TierPolicyOf is the parsed policy of the options, nil without a usable one.
func TierPolicyOf(hopt *HiddifyOptions) *tiered.Policy {
	if hopt == nil || hopt.TierPolicy == nil || hopt.TierPolicy.Policy == "" {
		return nil
	}
	policy, err := tiered.Parse(hopt.TierPolicy.Policy)
	if err != nil || policy.Empty() {
		return nil
	}
	return policy
}

// ValidProbeHost: a domain name or an IP address, no port, scheme, path or user.
func ValidProbeHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

// ValidProbePath follows the profile-probe rules: one leading slash, unreserved characters, / and
// %XX escapes, no dot segments, at most 256 characters.
func ValidProbePath(path string) bool {
	if len(path) < 1 || len(path) > 256 || path[0] != '/' || strings.HasPrefix(path, "//") {
		return false
	}
	for i := 0; i < len(path); i++ {
		c := path[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == '~', c == '/':
		case c == '%':
			if i+2 >= len(path) || !isHexDigit(path[i+1]) || !isHexDigit(path[i+2]) {
				return false
			}
			i += 2
		default:
			return false
		}
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// tierGroup is the tiered selector of the proxies tags (their order in the profile) by the
// policy, nil when it binds no proxy. udp says which proxies carry their traffic over UDP.
func tierGroup(hopt *HiddifyOptions, tags []string, udp map[string]bool) *option.Outbound {
	policy := TierPolicyOf(hopt)
	if policy == nil {
		return nil
	}
	plan := policy.Bind(tags, func(tag string) bool { return udp[tag] })
	if len(plan.Candidates) == 0 {
		return nil
	}
	return &option.Outbound{
		Type: C.TypeSelector,
		Tag:  OutboundTieredTag,
		Options: &option.SelectorOutboundOptions{
			Outbounds: plan.Tags(),
			Default:   plan.Candidates[0].Tag,
			// a proxy left because it froze leaves frozen connections: they are cut, so the apps
			// open them again at once; a way back up is rare (two passes, hours apart at most)
			InterruptExistConnections: true,
		},
	}
}

// TierPlan is the policy bound to the members of the built config's tiered group, nil without one.
func TierPlan(options *option.Options, hopt *HiddifyOptions) *tiered.Plan {
	policy := TierPolicyOf(hopt)
	if policy == nil || options == nil {
		return nil
	}
	var members []string
	udp := map[string]bool{}
	for _, out := range options.Outbounds {
		if out.Tag == OutboundTieredTag {
			if sel, ok := out.Options.(*option.SelectorOutboundOptions); ok {
				members = sel.Outbounds
			}
		}
		if udpProxy(out.Type, out.Options) {
			udp[out.Tag] = true
		}
	}
	for _, end := range options.Endpoints {
		if udpProxy(end.Type, end.Options) {
			udp[end.Tag] = true
		}
	}
	if len(members) == 0 {
		return nil
	}
	plan := policy.Bind(members, func(tag string) bool { return udp[tag] })
	if len(plan.Candidates) == 0 {
		return nil
	}
	return plan
}
