package tiered

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"
)

// Outcome of a check of a proxy: a transfer through it.
type Outcome int

const (
	OK        Outcome = iota // the data came
	Slow                     // it came, slower than SlowBelow
	Stall                    // the answer started, then nothing came for a while (a freeze)
	NoConnect                // no connection, handshake or answer
)

func (o Outcome) String() string {
	return [...]string{"ok", "slow", "stall", "noconnect"}[o]
}

// Works: the proxy carries data.
func (o Outcome) Works() bool { return o == OK || o == Slow }

// CheckResult is what a check of a proxy found.
type CheckResult struct {
	Outcome Outcome
	Latency time.Duration // to the first byte of the answer
}

// PathVerdict is what a check of the path to the server, outside the tunnel, found.
type PathVerdict int

const (
	PathUnknown PathVerdict = iota // no check possible (no test path, busy, error)
	PathOK                         // TCP, TLS and the transfer went through
	PathBlocked                    // TCP to the server freezes or is cut: every TCP proxy is out
)

// Network is the network the device uses now.
type Network struct {
	ID     string // a hash, never the Wi-Fi name; "" when not known
	Online bool
}

// Env is what the controller does in the world: the core gives the real one, tests a scripted one.
// The controller calls it from one goroutine at a time.
type Env interface {
	Now() time.Time
	// Sleep waits d or until ctx ends (then an error).
	Sleep(ctx context.Context, d time.Duration) error
	// Check sends a small transfer of known size through the proxy (tag), without selecting it.
	Check(ctx context.Context, tag string) CheckResult
	// CheckPath checks the path to the server outside the tunnel (TCP, TLS, a transfer).
	CheckPath(ctx context.Context) PathVerdict
	// Select makes tag the proxy of the tiered group.
	Select(tag string) error
	Network() Network
	Log(message string)
}

// Store keeps the controller's memory of the networks between runs.
type Store interface {
	Load() []byte
	Save([]byte)
}

// Timings of the controller that the policy does not set.
const (
	NodeDownTTL      = 45 * time.Minute // a proxy that did not answer: tried after the others for this long
	TransportDownTTL = 2 * time.Hour    // TCP to the server confirmed out (frozen or cut) in a network
	MemoryTTL        = TransportDownTTL // a network is forgotten when its last mark is this old
	retryChecks      = 3                // checks of the proxies marked down in one walk
	ConfirmPass     = time.Minute      // between the two checks that bring a proxy above back
	LastResortRetry = 5 * time.Minute  // on last resort past its max: the way up is checked this often
	NoneFirst       = time.Minute      // nothing works: the first wait before trying again
	NoneMax         = 15 * time.Minute // nothing works: the longest wait
	maxNetworks     = 16
	upChecksPerTurn = 2 // checks of the proxies above in one turn of the way up
)

// Reasons the app shows.
const (
	ReasonOK         = "ok"
	ReasonChecking   = "checking"
	ReasonNodeFailed = "node-failed" // the proxies above fail in this network
	ReasonTCP        = "tcp-blocked" // TCP to the server freezes or is cut in this network
	ReasonSlow       = "slow"
	ReasonOffline    = "offline"
	ReasonNone       = "none"    // no proxy of the policy works
	ReasonConfirm    = "confirm" // the last resort waits for the user
	ReasonIdle       = "idle"    // the user picked something else than the tiered group
)

// State is what the app is told (JSON in OutboundGroup.tier_state).
type State struct {
	Tier     int      `json:"tier"` // index of the active proxy's tier in the policy; -1 none
	Mode     string   `json:"mode,omitempty"`
	Node     string   `json:"node,omitempty"`
	Reason   string   `json:"reason"`
	Checking bool     `json:"checking,omitempty"`
	Confirm  string   `json:"confirm,omitempty"` // the last-resort proxy waiting for the user
	Down     []string `json:"down,omitempty"`    // proxies that failed in this network
	Network  string   `json:"network,omitempty"`
	Since    int64    `json:"since,omitempty"` // unix seconds the active proxy was chosen
}

// JSON is the state as the app gets it.
func (s State) JSON() string {
	b, _ := json.Marshal(s)
	return string(b)
}

type netMemory struct {
	Down       map[string]time.Time `json:"down,omitempty"` // tag -> until
	TCPBlocked time.Time            `json:"tcp,omitzero"`   // until
	Updated    time.Time            `json:"at"`
}

// Controller chooses the proxy of the tiered group. Its methods other than State are called from
// one goroutine (the core's loop, or a test).
type Controller struct {
	// OnChange, when set, is called after the state changed (to tell the app at once).
	OnChange func()
	// OnConsent, when set, is called when the user agreed to a last-resort proxy: the core keeps the
	// agreement for the rest of its run (a reload makes a new controller, see Consent).
	OnConsent func(tag string)

	env   Env
	plan  *Plan
	store Store

	stateMu sync.Mutex
	state   State

	memory   map[string]*netMemory
	network  Network
	enabled  bool
	active   int // index in plan.Candidates, -1 none
	since    time.Time
	slow     bool
	confirms map[string]bool

	nextCheck time.Time // the active proxy's data check
	nextUp    time.Time // the next turn of the way up
	upWait    time.Duration
	upCursor  int
	upPassed  string // the proxy above that passed one check; the second brings it back
	noneWait  time.Duration
}

// New makes a controller of plan. store may be nil.
func New(env Env, plan *Plan, store Store) *Controller {
	c := &Controller{env: env, plan: plan, store: store, active: -1, confirms: map[string]bool{}, memory: map[string]*netMemory{}}
	c.loadMemory()
	c.setState(State{Tier: -1, Reason: ReasonIdle})
	return c
}

// Consent records that the user already agreed to the last-resort proxy tag in this run of the core.
func (c *Controller) Consent(tag string) { c.confirms[tag] = true }

// State is the state for the app; safe from any goroutine.
func (c *Controller) State() State {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	s := c.state
	s.Down = slices.Clone(s.Down)
	return s
}

func (c *Controller) setState(s State) {
	c.stateMu.Lock()
	changed := c.state.JSON() != s.JSON()
	c.state = s
	c.stateMu.Unlock()
	if changed && c.OnChange != nil {
		c.OnChange()
	}
}

func (c *Controller) logf(format string, args ...any) {
	c.env.Log(fmt.Sprintf("tiers: "+format, args...))
}

// SetEnabled: whether the tiered group is the user's pick in select. Off, the controller does
// nothing at all: no check, no selection.
func (c *Controller) SetEnabled(ctx context.Context, enabled bool) {
	if enabled == c.enabled {
		return
	}
	c.enabled = enabled
	if !enabled {
		c.logf("idle: another choice is selected")
		c.setState(State{Tier: -1, Reason: ReasonIdle})
		return
	}
	c.Evaluate(ctx, "selected")
}

// Evaluate finds the proxy to use from the top: at the start, after a network change, when the
// user selects the tiered group or agrees to the last resort.
func (c *Controller) Evaluate(ctx context.Context, why string) {
	if !c.enabled || len(c.plan.Candidates) == 0 {
		return
	}
	c.network = c.env.Network()
	if !c.network.Online {
		c.offline()
		return
	}
	c.logf("choosing (%s), network %s", why, c.network.ID)
	c.walk(ctx, false)
}

// NetworkChanged: the default network changed (or came back).
func (c *Controller) NetworkChanged(ctx context.Context) {
	if !c.enabled {
		return
	}
	now := c.env.Network()
	switch {
	case !now.Online:
		c.network = now
		c.offline()
	case now.ID != c.network.ID || !c.network.Online || c.active < 0:
		c.Evaluate(ctx, "network changed")
	default:
		// the same network again: a quick look at the proxy in use
		c.nextCheck = c.env.Now().Add(5 * time.Second)
	}
}

// ActiveFailed: the monitoring saw the proxy in use fail its URL test.
func (c *Controller) ActiveFailed(ctx context.Context) {
	if !c.enabled || c.active < 0 {
		return
	}
	c.nextCheck = c.env.Now()
	c.Tick(ctx)
}

// Confirm: the user agreed to use the last-resort proxy tag.
func (c *Controller) Confirm(ctx context.Context, tag string) bool {
	if !c.enabled {
		return false
	}
	if c.State().Confirm != tag {
		return false
	}
	c.confirms[tag] = true
	if c.OnConsent != nil {
		c.OnConsent(tag)
	}
	c.logf("the user agreed to %s", tag)
	c.Evaluate(ctx, "the user agreed to the last resort")
	return true
}

func (c *Controller) offline() {
	c.logf("no network: waiting, nothing marked")
	s := c.State()
	s.Reason, s.Checking, s.Network = ReasonOffline, false, ""
	c.setState(s)
}

// NextWake is when Tick has something to do; zero when nothing is planned.
func (c *Controller) NextWake() time.Time {
	if !c.enabled || !c.network.Online {
		return time.Time{}
	}
	if c.active < 0 {
		if r := c.State().Reason; r != ReasonNone && r != ReasonConfirm {
			return time.Time{}
		}
		return c.nextUp
	}
	next := c.nextCheck
	if c.active > 0 && !c.nextUp.IsZero() && c.nextUp.Before(next) {
		next = c.nextUp
	}
	return next
}

// Tick does what is due: the data check of the proxy in use, a turn of the way up, another try
// when nothing worked.
func (c *Controller) Tick(ctx context.Context) {
	if !c.enabled || len(c.plan.Candidates) == 0 {
		return
	}
	if net := c.env.Network(); !net.Online {
		c.network = net
		c.offline()
		return
	} else if net.ID != c.network.ID || !c.network.Online {
		c.Evaluate(ctx, "network changed")
		return
	}
	now := c.env.Now()
	if c.active < 0 {
		if r := c.State().Reason; (r == ReasonNone || r == ReasonConfirm) && !c.nextUp.IsZero() && !now.Before(c.nextUp) {
			c.logf("trying again: nothing worked %s ago", c.noneWait)
			c.walk(ctx, true)
		}
		return
	}
	if !now.Before(c.nextCheck) {
		cand := c.plan.Candidates[c.active]
		c.checking(true)
		r := c.env.Check(ctx, cand.Tag)
		c.checking(false)
		if ctx.Err() != nil {
			return
		}
		if r.Outcome.Works() {
			c.slow = r.Outcome == Slow
			c.clearMark(cand)
			c.nextCheck = c.env.Now().Add(c.plan.Params.Check)
			c.publish()
		} else {
			c.logf("%s in use: %s", cand.Tag, r.Outcome)
			switch c.confirmFailure(ctx, cand, r, 1) {
			case verdictWorks:
				c.nextCheck = c.env.Now().Add(c.plan.Params.Check)
				c.publish()
			case verdictAborted:
			default:
				c.walk(ctx, false)
			}
			return
		}
	}
	if c.active > 0 && !c.nextUp.IsZero() && !c.env.Now().Before(c.nextUp) {
		c.wayUp(ctx, c.active)
	}
}

type verdict int

const (
	verdictWorks verdict = iota
	verdictDown
	verdictTCP
	verdictAborted
)

func (c *Controller) mem() *netMemory {
	id := c.network.ID
	m := c.memory[id]
	if m == nil {
		m = &netMemory{Down: map[string]time.Time{}}
		c.memory[id] = m
	}
	if m.Down == nil {
		m.Down = map[string]time.Time{}
	}
	return m
}

// A mark is a priority, not a ban: the proxies marked down in this network are tried after the
// others, the oldest mark first, never left out while the policy has nothing else to try. A proxy
// that did not answer is marked for NodeDownTTL; TCP to the server confirmed out marks every TCP
// proxy for TransportDownTTL; any check that works takes its mark away.

// isDown: the candidate is marked in this network (by itself, or as a TCP proxy while TCP is out).
func (c *Controller) isDown(cand Candidate) bool {
	return !c.markUntil(cand).IsZero()
}

// markUntil is when the candidate's mark ends, zero without one.
func (c *Controller) markUntil(cand Candidate) time.Time {
	m := c.mem()
	now := c.env.Now()
	var until time.Time
	if u, ok := m.Down[cand.Tag]; ok && now.Before(u) {
		until = u
	}
	if !cand.UDP && now.Before(m.TCPBlocked) && m.TCPBlocked.After(until) {
		until = m.TCPBlocked
	}
	return until
}

func (c *Controller) tcpBlocked() bool { return c.env.Now().Before(c.mem().TCPBlocked) }

func (c *Controller) markDown(tag string) {
	m := c.mem()
	m.Down[tag] = c.env.Now().Add(NodeDownTTL)
	m.Updated = c.env.Now()
	c.saveMemory()
}

func (c *Controller) markTCP() {
	m := c.mem()
	m.TCPBlocked = c.env.Now().Add(TransportDownTTL)
	m.Updated = c.env.Now()
	c.saveMemory()
}

// clearMark: the candidate works, so its mark goes; a TCP proxy that works also clears TCP.
func (c *Controller) clearMark(cand Candidate) {
	m := c.mem()
	_, marked := m.Down[cand.Tag]
	if !marked && (cand.UDP || m.TCPBlocked.IsZero()) {
		return
	}
	delete(m.Down, cand.Tag)
	if !cand.UDP {
		m.TCPBlocked = time.Time{}
	}
	m.Updated = c.env.Now()
	c.saveMemory()
}

func (c *Controller) clearUp(to int) {
	m := c.mem()
	for i := 0; i <= to && i < len(c.plan.Candidates); i++ {
		delete(m.Down, c.plan.Candidates[i].Tag)
	}
	if !c.plan.Candidates[to].UDP {
		m.TCPBlocked = time.Time{}
	}
	m.Updated = c.env.Now()
	c.saveMemory()
}

// needsConsent: a last resort the user has to agree to first; until then it is not even checked
// (a check is already a handshake with the server).
func (c *Controller) needsConsent(cand Candidate) bool {
	return cand.Mode == ModeLastResort && cand.Confirm && !c.confirms[cand.Tag]
}

// NeedsConsent are the tags of the last-resort proxies still waiting for the user's agreement:
// nothing may test them meanwhile.
func (c *Controller) NeedsConsent() []string {
	var tags []string
	for _, cand := range c.plan.Candidates {
		if c.needsConsent(cand) {
			tags = append(tags, cand.Tag)
		}
	}
	return tags
}

// walkState is what one walk learned.
type walkState struct {
	tried       map[int]bool
	stalls      map[string]bool
	pathChecked bool
	pathVerdict PathVerdict
	tcpNow      bool // this walk found TCP to the server out
	checks      int
}

// walk tries the candidates and selects the first that carries data: first the ones not marked in
// this network, in the policy's order, then the marked ones, the oldest mark first, a last resort
// after the others (at most
// retryChecks of them, a TCP one only if this walk did not just find TCP out). A last resort that
// waits for the user's agreement is offered only when nothing else worked. retry: a later try while
// nothing works, one check a proxy, at most retryChecks in all.
func (c *Controller) walk(ctx context.Context, retry bool) {
	w := &walkState{tried: map[int]bool{}, stalls: map[string]bool{}}
	attempts := c.plan.Params.Fail
	if retry {
		attempts = 1
	}
	consent := -1
	for i, cand := range c.plan.Candidates {
		if c.needsConsent(cand) {
			if consent < 0 {
				consent = i
			}
			continue
		}
		if c.isDown(cand) || (w.tcpNow && !cand.UDP) {
			continue
		}
		if retry && w.checks >= retryChecks {
			break
		}
		switch c.try(ctx, w, i, attempts) {
		case verdictWorks:
			c.use(i)
			return
		case verdictAborted:
			return
		}
	}
	budget := retryChecks
	if retry {
		budget = max(retryChecks-w.checks, 0)
	}
	for _, i := range c.markedOrder(w) {
		if budget <= 0 {
			break
		}
		if w.tcpNow && !c.plan.Candidates[i].UDP {
			continue // found out in this walk
		}
		budget--
		c.logf("trying %s again although it failed here lately", c.plan.Candidates[i].Tag)
		switch c.try(ctx, w, i, 1) {
		case verdictWorks:
			c.use(i)
			return
		case verdictAborted:
			return
		}
	}
	c.active = -1
	c.scheduleNone()
	if consent >= 0 {
		cand := c.plan.Candidates[consent]
		c.logf("last resort %s waits for the user", cand.Tag)
		c.setState(State{Tier: cand.Tier, Mode: cand.Mode, Reason: ReasonConfirm, Confirm: cand.Tag, Down: c.downTags(), Network: c.network.ID})
		return
	}
	// nothing works: the choice stays, and everything is tried again later
	c.logf("no proxy of the policy works; again in %s", c.noneWait)
	c.setState(State{Tier: -1, Reason: ReasonNone, Down: c.downTags(), Network: c.network.ID})
}

// markedOrder are the marked candidates this walk did not try, the oldest mark first.
func (c *Controller) markedOrder(w *walkState) []int {
	var order []int
	for i, cand := range c.plan.Candidates {
		if w.tried[i] || c.needsConsent(cand) || (w.tcpNow && !cand.UDP) || !c.isDown(cand) {
			continue
		}
		order = append(order, i)
	}
	// the oldest mark first, a last resort after the others, then the policy's order
	sort.SliceStable(order, func(a, b int) bool {
		ca, cb := c.plan.Candidates[order[a]], c.plan.Candidates[order[b]]
		if la, lb := ca.Mode == ModeLastResort, cb.Mode == ModeLastResort; la != lb {
			return lb
		}
		return c.markedAt(ca).Before(c.markedAt(cb))
	})
	return order
}

// markedAt is when the candidate got the newest of the marks it carries now.
func (c *Controller) markedAt(cand Candidate) time.Time {
	m := c.mem()
	now := c.env.Now()
	var at time.Time
	if u, ok := m.Down[cand.Tag]; ok && now.Before(u) {
		at = u.Add(-NodeDownTTL)
	}
	if !cand.UDP && now.Before(m.TCPBlocked) {
		if t := m.TCPBlocked.Add(-TransportDownTTL); t.After(at) {
			at = t
		}
	}
	return at
}

// try checks candidate i up to attempts times and marks it, or TCP, when it fails.
func (c *Controller) try(ctx context.Context, w *walkState, i int, attempts int) verdict {
	cand := c.plan.Candidates[i]
	w.tried[i] = true
	c.setState(State{Tier: cand.Tier, Mode: cand.Mode, Node: cand.Tag, Reason: ReasonChecking, Checking: true, Down: c.downTags(), Network: c.network.ID})
	v := verdictDown
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			if c.env.Sleep(ctx, c.plan.Params.Retry) != nil {
				return verdictAborted
			}
		}
		if c.networkMoved() {
			c.Evaluate(ctx, "network changed")
			return verdictAborted
		}
		w.checks++
		r := c.env.Check(ctx, cand.Tag)
		if ctx.Err() != nil {
			return verdictAborted
		}
		c.logf("%s: %s", cand.Tag, r.Outcome)
		if r.Outcome.Works() {
			c.slow = r.Outcome == Slow
			c.clearMark(cand)
			return verdictWorks
		}
		if cand.UDP {
			continue
		}
		// a TCP proxy that stalled or got no answer: is it the proxy, or TCP to the server?
		if !w.pathChecked {
			w.pathChecked = true
			w.pathVerdict = c.env.CheckPath(ctx)
			if ctx.Err() != nil {
				return verdictAborted
			}
			c.logf("the path to the server: %s", [...]string{"unknown", "ok", "blocked"}[w.pathVerdict])
			if c.networkMoved() {
				c.Evaluate(ctx, "network changed")
				return verdictAborted
			}
		}
		if w.pathVerdict == PathBlocked {
			v = verdictTCP
			break
		}
		if w.pathVerdict == PathUnknown && r.Outcome == Stall {
			// no verdict of the path: a stall is a strong sign by itself, so on at once; two
			// TCP proxies that stall in a row make TCP out
			w.stalls[cand.Tag] = true
			if len(w.stalls) >= 2 {
				v = verdictTCP
			}
			break
		}
	}
	if v == verdictTCP {
		c.logf("TCP to the server is out in this network: on to UDP")
		w.tcpNow = true
		c.markTCP()
	} else {
		c.markDown(cand.Tag)
	}
	return v
}

// scheduleNone plans the next try while no proxy is in use: 1 min, then twice as long, up to 15.
func (c *Controller) scheduleNone() {
	if c.noneWait == 0 {
		c.noneWait = NoneFirst
	} else {
		c.noneWait = min(c.noneWait*2, NoneMax)
	}
	c.nextUp = c.env.Now().Add(c.noneWait)
}

// confirmFailure goes on checking the proxy in use after a failure (already failed times).
func (c *Controller) confirmFailure(ctx context.Context, cand Candidate, first CheckResult, failed int) verdict {
	if !cand.UDP {
		path := c.env.CheckPath(ctx)
		if ctx.Err() != nil {
			return verdictAborted
		}
		if path == PathBlocked {
			c.logf("TCP to the server is out in this network: on to UDP")
			c.markTCP()
			return verdictTCP
		}
	}
	for ; failed < c.plan.Params.Fail; failed++ {
		if c.env.Sleep(ctx, c.plan.Params.Retry) != nil {
			return verdictAborted
		}
		if c.networkMoved() {
			c.Evaluate(ctx, "network changed")
			return verdictAborted
		}
		r := c.env.Check(ctx, cand.Tag)
		if ctx.Err() != nil {
			return verdictAborted
		}
		if r.Outcome.Works() {
			return verdictWorks
		}
	}
	c.markDown(cand.Tag)
	return verdictDown
}

func (c *Controller) networkMoved() bool {
	now := c.env.Network()
	return !now.Online || now.ID != c.network.ID
}

// use selects candidate i.
func (c *Controller) use(i int) {
	cand := c.plan.Candidates[i]
	if err := c.env.Select(cand.Tag); err != nil {
		c.logf("select %s: %v", cand.Tag, err)
	}
	if c.active != i {
		c.since = c.env.Now()
	}
	c.active = i
	c.noneWait = 0
	c.upPassed = ""
	c.upCursor = 0
	c.upWait = c.plan.Params.Up
	c.nextCheck = c.env.Now().Add(c.plan.Params.Check)
	c.nextUp = c.since.Add(max(c.plan.Params.Hold, c.upWait))
	if cand.Mode == ModeLastResort && cand.Max > 0 {
		c.nextUp = c.since.Add(min(max(c.plan.Params.Hold, c.upWait), cand.Max))
	}
	c.clearMark(cand)
	c.logf("using %s (tier %d, %s)", cand.Tag, cand.Tier+1, cand.Mode)
	c.publish()
}

func (c *Controller) publish() {
	if c.active < 0 {
		return
	}
	cand := c.plan.Candidates[c.active]
	reason := ReasonOK
	switch {
	case c.active == 0:
	case cand.UDP && c.tcpBlocked():
		reason = ReasonTCP
	case len(c.downTags()) > 0:
		reason = ReasonNodeFailed
	}
	if c.slow && reason == ReasonOK {
		reason = ReasonSlow
	}
	c.setState(State{
		Tier: cand.Tier, Mode: cand.Mode, Node: cand.Tag, Reason: reason, Down: c.downTags(),
		Network: c.network.ID, Since: c.since.Unix(),
	})
}

func (c *Controller) checking(on bool) {
	s := c.State()
	s.Checking = on
	c.setState(s)
}

// downTags are the candidates that failed in this network.
func (c *Controller) downTags() []string {
	var tags []string
	for _, cand := range c.plan.Candidates {
		if c.isDown(cand) {
			tags = append(tags, cand.Tag)
		}
	}
	return tags
}

// wayUp is one turn of the way up from below index limit: at most upChecksPerTurn checks of the
// proxies above, in order from where the last turn stopped, none selected until it passes twice.
func (c *Controller) wayUp(ctx context.Context, limit int) {
	if limit <= 0 {
		return
	}
	now := c.env.Now()
	nothing := c.active < 0
	// a candidate that passed once: its second check
	if c.upPassed != "" {
		i := c.indexOf(c.upPassed)
		c.upPassed = ""
		if i >= 0 && i < limit {
			r := c.env.Check(ctx, c.plan.Candidates[i].Tag)
			if ctx.Err() != nil {
				return
			}
			c.logf("way up, second check of %s: %s", c.plan.Candidates[i].Tag, r.Outcome)
			if r.Outcome.Works() {
				c.clearUp(i)
				c.use(i)
				return
			}
			c.upFailed(now)
			return
		}
	}
	// a turn checks the top first (the best way up), then one of the others in turn
	order := []int{0}
	if limit > 1 {
		order = append(order, 1+c.upCursor%(limit-1))
		c.upCursor = (c.upCursor + 1) % (limit - 1)
	}
	for _, i := range order[:min(len(order), upChecksPerTurn)] {
		cand := c.plan.Candidates[i]
		if c.needsConsent(cand) {
			continue
		}
		r := c.env.Check(ctx, cand.Tag)
		if ctx.Err() != nil {
			return
		}
		c.logf("way up, %s: %s", cand.Tag, r.Outcome)
		if !r.Outcome.Works() {
			continue
		}
		if nothing {
			// nothing works now: one pass is enough
			c.clearUp(i)
			c.use(i)
			return
		}
		c.upPassed = cand.Tag
		c.nextUp = c.env.Now().Add(ConfirmPass)
		return
	}
	c.upFailed(now)
}

// upFailed plans the next turn of the way up after one that found nothing: twice the wait, up to
// MaxUp; on the last resort past its max, every LastResortRetry.
func (c *Controller) upFailed(now time.Time) {
	if c.active < 0 {
		c.scheduleNone()
		return
	}
	c.upWait = min(c.upWait*2, MaxUp)
	cand := c.plan.Candidates[c.active]
	if cand.Mode == ModeLastResort && cand.Max > 0 && now.Sub(c.since) >= cand.Max {
		c.upWait = LastResortRetry
	}
	c.nextUp = c.env.Now().Add(c.upWait)
}

func (c *Controller) indexOf(tag string) int {
	for i, cand := range c.plan.Candidates {
		if cand.Tag == tag {
			return i
		}
	}
	return -1
}

func (c *Controller) loadMemory() {
	if c.store == nil {
		return
	}
	data := c.store.Load()
	if len(data) == 0 {
		return
	}
	var memory map[string]*netMemory
	if json.Unmarshal(data, &memory) != nil {
		return
	}
	now := c.env.Now()
	for id, m := range memory {
		if m == nil || now.Sub(m.Updated) > MemoryTTL {
			continue
		}
		c.memory[id] = m
	}
}

func (c *Controller) saveMemory() {
	if c.store == nil {
		return
	}
	now := c.env.Now()
	type aged struct {
		id string
		at time.Time
	}
	var all []aged
	for id, m := range c.memory {
		if now.Sub(m.Updated) > MemoryTTL {
			delete(c.memory, id)
			continue
		}
		all = append(all, aged{id, m.Updated})
	}
	if len(all) > maxNetworks {
		sort.Slice(all, func(i, j int) bool { return all[i].at.After(all[j].at) })
		for _, old := range all[maxNetworks:] {
			delete(c.memory, old.id)
		}
	}
	if data, err := json.Marshal(c.memory); err == nil {
		c.store.Save(data)
	}
}
