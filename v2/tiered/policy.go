// Package tiered chooses the proxy of a profile by the server's own ranking: ordered tiers of
// proxies, each proxy with three scores (reliability, stealth, security), sent by the subscription
// server in a response header. The controller (controller.go) goes down the tiers only when a proxy
// is shown not to carry data, and back up after rare checks in the background.
//
// The package is plain logic: it knows nothing of the engine. The core gives it an Env that checks
// a proxy, checks the path to the server and selects a proxy; tests give it a scripted one.
package tiered

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// HeaderName is the response header of a subscription that carries the policy.
const HeaderName = "profile-policy"

// Modes of a tier.
const (
	ModeAuto       = "auto"        // used in normal work; a start may begin on it
	ModeFallback   = "fallback"    // only once every proxy above failed in this network
	ModeLastResort = "last-resort" // as fallback, with a warning; with confirm, only once the user agrees
	ModeManual     = "manual"      // never chosen by the controller
)

// Limits of the format (v1).
const (
	maxHeaderLength = 2048
	maxNodes        = 64
	maxTiers        = 8
	maxRefsPerTier  = 32
	maxCaptions     = 2
	maxNameBytes    = 96
	maxRefNumber    = 999
)

// Params are the timings of the controller, each within the client's bounds.
type Params struct {
	Fail  int           // failed checks in a row that make a proxy down
	Retry time.Duration // between two checks of one proxy
	Up    time.Duration // the first wait before a check of the tiers above; doubles after a failure
	Hold  time.Duration // the least time on a tier before going back up
	Check time.Duration // how often the active proxy's data transfer is checked
	TTL   time.Duration // how long the app keeps the policy when an update comes without it
}

type bound struct {
	key           string
	min, max, def int
	unit          time.Duration
}

var bounds = []bound{
	{"fail", 1, 4, 2, 0},
	{"retry", 2, 30, 4, time.Second},
	{"up", 300, 7200, 900, time.Second},
	{"hold", 60, 3600, 300, time.Second},
	{"chk", 120, 3600, 600, time.Second},
	{"ttl", 24, 720, 168, time.Hour},
}

// DefaultParams are the timings without any parameter in the policy.
func DefaultParams() Params {
	p := Params{}
	for _, b := range bounds {
		setParam(&p, b, b.def)
	}
	return p
}

func setParam(p *Params, b bound, v int) {
	d := time.Duration(v) * b.unit
	switch b.key {
	case "fail":
		p.Fail = v
	case "retry":
		p.Retry = d
	case "up":
		p.Up = d
	case "hold":
		p.Hold = d
	case "chk":
		p.Check = d
	case "ttl":
		p.TTL = d
	}
}

// MaxUp is the longest wait between two checks of the tiers above.
const MaxUp = 4 * time.Hour

// Ref names a proxy of the subscription: by the number its name starts with, or by its exact name.
type Ref struct {
	Number int    // 1..999, or 0
	Name   string // the exact display name when Number is 0
}

func (r Ref) String() string {
	if r.Number > 0 {
		return strconv.Itoa(r.Number)
	}
	return "@" + escapeName(r.Name)
}

// Scores are 1..5, 5 the best.
type Scores struct {
	Reliability, Stealth, Security int
}

// Sum orders the proxies of a tier: the higher first.
func (s Scores) Sum() int { return s.Reliability + s.Stealth + s.Security }

// Node is what the policy says of one proxy.
type Node struct {
	Ref      Ref
	Scores   Scores
	Captions []string // keys of a fixed set the app translates; unknown ones are not shown
}

// Tier is one level of the policy.
type Tier struct {
	Mode    string
	Confirm bool          // last-resort: the user must agree before it is tried
	Max     time.Duration // last-resort: after this long on it, the way up is checked every 5 minutes
	Refs    []Ref
}

// Policy is a parsed profile-policy header.
type Policy struct {
	Nodes  []Node
	Tiers  []Tier
	Params Params
	// set: the parameters the header gave, for the canonical form
	set map[string]int
}

// Empty is a policy without tiers: "no policy" (it clears a kept one at once).
func (p *Policy) Empty() bool { return p == nil || len(p.Tiers) == 0 }

var errGarbage = errors.New("profile-policy: not a valid policy")

func garbage(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errGarbage, fmt.Sprintf(format, args...))
}

// Parse reads a profile-policy header strictly: anything that does not fit the format makes the
// whole header garbage (an error), so the subscription works as without a policy. Unknown keys and
// flags are skipped, numbers out of bounds are brought to the bound.
func Parse(header string) (*Policy, error) {
	if len(header) == 0 || len(header) > maxHeaderLength {
		return nil, garbage("length %d", len(header))
	}
	for i := 0; i < len(header); i++ {
		if c := header[i]; c < 0x20 || c > 0x7e {
			return nil, garbage("byte 0x%02x", c)
		}
	}
	policy := &Policy{Params: DefaultParams(), set: map[string]int{}}
	scored := map[Ref]bool{}
	tiered := map[Ref]bool{}
	first := true
	for _, item := range strings.Split(header, ";") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		key, value, ok := strings.Cut(item, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !ok || key == "" {
			return nil, garbage("item %q", item)
		}
		if first {
			if key != "v" || value != "1" {
				return nil, garbage("the first item is not v=1")
			}
			first = false
			continue
		}
		switch key {
		case "v":
			return nil, garbage("v repeated")
		case "n":
			node, err := parseNode(value)
			if err != nil {
				return nil, err
			}
			if scored[node.Ref] {
				return nil, garbage("n=%s repeated", node.Ref)
			}
			scored[node.Ref] = true
			policy.Nodes = append(policy.Nodes, node)
			if len(policy.Nodes) > maxNodes {
				return nil, garbage("more than %d nodes", maxNodes)
			}
		case "t":
			tier, err := parseTier(value)
			if err != nil {
				return nil, err
			}
			for _, ref := range tier.Refs {
				if tiered[ref] {
					return nil, garbage("%s in two tiers", ref)
				}
				tiered[ref] = true
			}
			policy.Tiers = append(policy.Tiers, tier)
			if len(policy.Tiers) > maxTiers {
				return nil, garbage("more than %d tiers", maxTiers)
			}
		default:
			b, known := boundOf(key)
			if !known {
				continue // a key of a later version
			}
			if _, repeated := policy.set[key]; repeated {
				return nil, garbage("%s repeated", key)
			}
			n, err := parseNumber(value)
			if err != nil {
				return nil, garbage("%s=%q", key, value)
			}
			n = min(max(n, b.min), b.max)
			policy.set[key] = n
			setParam(&policy.Params, b, n)
		}
	}
	if first {
		return nil, garbage("no v=1")
	}
	// the canonical form (what the app keeps and gives the core) brings numbers to their bounds, which
	// can make it a few bytes longer than the header: one over the limit is no policy, here as in the
	// app, so the two never disagree
	if n := len(policy.Canonical()); n > maxHeaderLength {
		return nil, garbage("canonical form of %d bytes", n)
	}
	return policy, nil
}

func boundOf(key string) (bound, bool) {
	for _, b := range bounds {
		if b.key == key {
			return b, true
		}
	}
	return bound{}, false
}

// parseNumber is a decimal without sign or leading zeros, at most 7 digits.
func parseNumber(s string) (int, error) {
	if s == "" || len(s) > 7 || (len(s) > 1 && s[0] == '0') {
		return 0, errGarbage
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errGarbage
		}
	}
	return strconv.Atoi(s)
}

func parseNode(value string) (Node, error) {
	parts := strings.Split(value, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return Node{}, garbage("n=%q", value)
	}
	ref, err := parseRef(strings.TrimSpace(parts[0]))
	if err != nil {
		return Node{}, err
	}
	digits := strings.TrimSpace(parts[1])
	if len(digits) != 3 {
		return Node{}, garbage("scores %q", digits)
	}
	var s [3]int
	for i := range 3 {
		c := digits[i]
		if c < '1' || c > '5' {
			return Node{}, garbage("scores %q", digits)
		}
		s[i] = int(c - '0')
	}
	node := Node{Ref: ref, Scores: Scores{Reliability: s[0], Stealth: s[1], Security: s[2]}}
	if len(parts) == 3 {
		caps := strings.Split(strings.TrimSpace(parts[2]), "+")
		if len(caps) > maxCaptions {
			return Node{}, garbage("captions %q", parts[2])
		}
		for _, c := range caps {
			c = strings.TrimSpace(c)
			if !validCaption(c) {
				return Node{}, garbage("caption %q", c)
			}
			node.Captions = append(node.Captions, c)
		}
	}
	return node, nil
}

func validCaption(c string) bool {
	if c == "" || len(c) > 16 {
		return false
	}
	for _, r := range c {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func parseTier(value string) (Tier, error) {
	head, list, ok := strings.Cut(value, ":")
	if !ok {
		return Tier{}, garbage("t=%q", value)
	}
	flags := strings.Split(head, ",")
	tier := Tier{Mode: strings.TrimSpace(flags[0])}
	switch tier.Mode {
	case ModeAuto, ModeFallback, ModeLastResort, ModeManual:
	default:
		return Tier{}, garbage("mode %q", tier.Mode)
	}
	for _, flag := range flags[1:] {
		flag = strings.TrimSpace(flag)
		switch {
		case flag == "confirm":
			tier.Confirm = tier.Mode == ModeLastResort
		case strings.HasPrefix(flag, "max="):
			n, err := parseNumber(strings.TrimPrefix(flag, "max="))
			if err != nil {
				return Tier{}, garbage("flag %q", flag)
			}
			if tier.Mode == ModeLastResort {
				tier.Max = time.Duration(min(max(n, 5), 240)) * time.Minute
			}
		case flag == "":
			return Tier{}, garbage("empty flag in %q", head)
		default:
			// a flag of a later version
		}
	}
	for _, item := range strings.Split(list, ",") {
		ref, err := parseRef(strings.TrimSpace(item))
		if err != nil {
			return Tier{}, err
		}
		for _, seen := range tier.Refs {
			if seen == ref {
				return Tier{}, garbage("%s twice in a tier", ref)
			}
		}
		tier.Refs = append(tier.Refs, ref)
	}
	if len(tier.Refs) > maxRefsPerTier {
		return Tier{}, garbage("more than %d proxies in a tier", maxRefsPerTier)
	}
	return tier, nil
}

func parseRef(s string) (Ref, error) {
	if strings.HasPrefix(s, "@") {
		name, err := unescapeName(s[1:])
		if err != nil || name == "" || len(name) > maxNameBytes {
			return Ref{}, garbage("ref %q", s)
		}
		return Ref{Name: name}, nil
	}
	n, err := parseNumber(s)
	if err != nil || n < 1 || n > maxRefNumber {
		return Ref{}, garbage("ref %q", s)
	}
	return Ref{Number: n}, nil
}

// unescapeName decodes a name of unreserved characters and %XX escapes (UTF-8).
func unescapeName(s string) (string, error) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == '~':
		case c == '%':
			if i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
				return "", errGarbage
			}
			i += 2
		default:
			return "", errGarbage
		}
	}
	name, err := url.PathUnescape(s)
	if err != nil || !utf8Valid(name) {
		return "", errGarbage
	}
	return name, nil
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func utf8Valid(s string) bool {
	for _, r := range s {
		if r == '�' || r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func escapeName(name string) string {
	var b strings.Builder
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// Canonical is the policy as the app keeps it: v=1, the nodes, the tiers, the parameters given.
func (p *Policy) Canonical() string {
	items := []string{"v=1"}
	for _, n := range p.Nodes {
		s := fmt.Sprintf("n=%s:%d%d%d", n.Ref, n.Scores.Reliability, n.Scores.Stealth, n.Scores.Security)
		if len(n.Captions) > 0 {
			s += ":" + strings.Join(n.Captions, "+")
		}
		items = append(items, s)
	}
	for _, t := range p.Tiers {
		head := t.Mode
		if t.Confirm {
			head += ",confirm"
		}
		if t.Max > 0 {
			head += ",max=" + strconv.Itoa(int(t.Max/time.Minute))
		}
		refs := make([]string, len(t.Refs))
		for i, r := range t.Refs {
			refs[i] = r.String()
		}
		items = append(items, "t="+head+":"+strings.Join(refs, ","))
	}
	for _, b := range bounds {
		if v, ok := p.set[b.key]; ok {
			items = append(items, b.key+"="+strconv.Itoa(v))
		}
	}
	return strings.Join(items, ";")
}

// DisplayName is a tag as the app shows it: without the core's "§…" suffix, trimmed.
func DisplayName(tag string) string {
	name, _, _ := strings.Cut(tag, "§")
	return strings.TrimSpace(name)
}

// numberOf is the number a display name starts with (followed by its end or a non-digit), or 0.
func numberOf(name string) int {
	end := 0
	for end < len(name) && end < 4 && name[end] >= '0' && name[end] <= '9' {
		end++
	}
	if end == 0 || end == 4 || (end > 1 && name[0] == '0') {
		return 0
	}
	if end < len(name) && name[end] >= '0' && name[end] <= '9' {
		return 0
	}
	n, _ := strconv.Atoi(name[:end])
	return n
}

// Resolve finds the tag a reference names among tags; "" when none or more than one match.
func Resolve(ref Ref, tags []string) string {
	found := ""
	for _, tag := range tags {
		name := DisplayName(tag)
		match := false
		if ref.Number > 0 {
			match = numberOf(name) == ref.Number
		} else {
			match = name == ref.Name
		}
		if match {
			if found != "" {
				return "" // ambiguous: not applied
			}
			found = tag
		}
	}
	return found
}

// Candidate is a proxy of the profile in the order the controller tries them.
type Candidate struct {
	Tag     string
	Tier    int // index of its tier in the policy
	Mode    string
	Confirm bool
	Max     time.Duration
	UDP     bool
	// Server is the server the proxy connects to: its address as the handshake gate counts it (an
	// address or a subnet), or its domain; "" when not known. TCP to one server being out says
	// nothing of another's.
	Server   string
	Scores   Scores
	Scored   bool
	Order    int // its place in the tier as the policy lists it
	Captions []string
}

// Plan is a policy bound to the tags of one profile.
type Plan struct {
	Candidates []Candidate // the proxies of the tiers other than manual, in order
	Manual     []string    // tags of manual tiers, then the proxies the policy does not name
	Params     Params
}

// Strictness orders the tiers for a proxy the policy names in several of them (by its number in one
// and its name in another): the strictest one holds it, so that an alias never lets the controller
// use by itself a proxy another tier keeps for the user's agreement. Manual is the strictest (never
// chosen), then a last resort that waits for the user, a last resort, a fallback, auto.
func Strictness(mode string, confirm bool) int {
	switch mode {
	case ModeManual:
		return 4
	case ModeLastResort:
		if confirm {
			return 3
		}
		return 2
	case ModeFallback:
		return 1
	}
	return 0
}

// Bind binds the policy to the tags of a profile (its proxies, in their order); udp says whether a
// proxy carries its traffic over UDP. A reference that names no tag, or several, is skipped; a proxy
// named in several tiers (a number and a name of the same proxy) is in the strictest of them (see
// Strictness), of equal ones the first.
func (p *Policy) Bind(tags []string, udp func(tag string) bool) *Plan {
	plan := &Plan{Params: p.Params}
	if p.Empty() {
		return plan
	}
	scores := map[string]Node{}
	for _, n := range p.Nodes {
		if tag := Resolve(n.Ref, tags); tag != "" {
			scores[tag] = n
		}
	}
	home := map[string]int{} // tag -> the index of its tier
	for ti, t := range p.Tiers {
		for _, ref := range t.Refs {
			tag := Resolve(ref, tags)
			if tag == "" {
				continue
			}
			if prev, seen := home[tag]; !seen || Strictness(t.Mode, t.Confirm) > Strictness(p.Tiers[prev].Mode, p.Tiers[prev].Confirm) {
				home[tag] = ti
			}
		}
	}
	used := map[string]bool{}
	for ti, t := range p.Tiers {
		var tier []Candidate
		for order, ref := range t.Refs {
			tag := Resolve(ref, tags)
			if tag == "" || used[tag] || home[tag] != ti {
				continue
			}
			used[tag] = true
			if t.Mode == ModeManual {
				plan.Manual = append(plan.Manual, tag)
				continue
			}
			node, scored := scores[tag]
			isUDP := false
			if udp != nil {
				isUDP = udp(tag)
			}
			tier = append(tier, Candidate{
				Tag: tag, Tier: ti, Mode: t.Mode, Confirm: t.Confirm, Max: t.Max, UDP: isUDP,
				Scores: node.Scores, Scored: scored, Order: order, Captions: node.Captions,
			})
		}
		// the best scored first; a proxy without scores after the scored ones; then as listed
		sort.SliceStable(tier, func(i, j int) bool {
			if tier[i].Scored != tier[j].Scored {
				return tier[i].Scored
			}
			return tier[i].Scores.Sum() > tier[j].Scores.Sum()
		})
		plan.Candidates = append(plan.Candidates, tier...)
	}
	for _, tag := range tags {
		if !used[tag] {
			plan.Manual = append(plan.Manual, tag)
		}
	}
	return plan
}

// SetServers gives each candidate the server it connects to (Candidate.Server); server answers ""
// when it does not know.
func (p *Plan) SetServers(server func(tag string) string) {
	if p == nil || server == nil {
		return
	}
	for i := range p.Candidates {
		p.Candidates[i].Server = server(p.Candidates[i].Tag)
	}
}

// Reserves are the last resorts that wait for the user's agreement: nothing may use or even test
// them before it (a test is a handshake with the server).
func (p *Plan) Reserves() []string {
	if p == nil {
		return nil
	}
	var tags []string
	for _, c := range p.Candidates {
		if c.Mode == ModeLastResort && c.Confirm {
			tags = append(tags, c.Tag)
		}
	}
	return tags
}

// Tags are the candidates' tags, in order.
func (p *Plan) Tags() []string {
	tags := make([]string, len(p.Candidates))
	for i, c := range p.Candidates {
		tags[i] = c.Tag
	}
	return tags
}
