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
	PathBlocked                    // TCP to the server freezes or is cut: every TCP proxy to it is out
)

// Network is the network the device uses now.
type Network struct {
	ID     string // a hash, never the Wi-Fi name; "" when not known
	Online bool
}

// Env is what the controller does in the world: the core gives the real one, tests a scripted one.
// The controller calls it from the goroutine that drives it, Log also from the one that calls Agree.
type Env interface {
	Now() time.Time
	// Sleep waits d or until ctx ends (then an error).
	Sleep(ctx context.Context, d time.Duration) error
	// Check sends a small transfer of known size through the proxy (tag), without selecting it.
	Check(ctx context.Context, tag string) CheckResult
	// CheckPath checks the path to the server of the proxy tag outside the tunnel (TCP, TLS, a
	// transfer): its address, and a name in TLS that server answers to.
	CheckPath(ctx context.Context, tag string) PathVerdict
	// Select makes tag the proxy of the tiered group. A last resort that waits for the user's
	// agreement is refused, and the group held instead (see Hold): the core keeps that rule too.
	Select(tag string) error
	// Hold puts the tiered group on no proxy: its connections are refused. The group waits there while
	// nothing but a last resort the user has not agreed to is left, never on that last resort.
	Hold() error
	// Picked: the tiered group is still the user's pick; a walk stops once it is not.
	Picked() bool
	// Received is how many bytes the apps' connections through the proxy tag have brought so far:
	// a counter that only grows (it starts again with a new run of the engine).
	Received(tag string) int64
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
	TransportDownTTL = 2 * time.Hour    // TCP to a server confirmed out (frozen or cut) in a network
	MemoryTTL        = TransportDownTTL // a network is forgotten when its last mark is this old
	retryChecks      = 3                // checks of the proxies marked down in one walk
	walkBudget       = 24               // checks in one walk past which a proxy gets a single try
	clockSkew        = time.Minute      // a stored time this far ahead of the clock: the clock went back
	ConfirmPass      = time.Minute      // between the two checks that bring a proxy above back
	LastResortRetry  = 5 * time.Minute  // on last resort past its max: the way up is checked this often
	NoneFirst        = time.Minute      // nothing works: the first wait before trying again
	NoneMax          = 15 * time.Minute // nothing works: the longest wait
	HeldMax          = 5 * time.Minute  // the group held for the user's agreement: the longest wait
	CarriedEnough    = 256 << 10        // bytes the apps got through the proxy in use that stand for its data check
	maxNetworks      = 16
	upChecksPerTurn  = 2 // checks of the proxies above in one turn of the way up
)

// Reasons the app shows.
const (
	ReasonOK         = "ok"
	ReasonChecking   = "checking"
	ReasonNodeFailed = "node-failed" // the proxies above fail in this network
	ReasonTCP        = "tcp-blocked" // TCP to the server in use freezes or is cut in this network
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
	Down map[string]time.Time `json:"down,omitempty"` // tag -> until
	// TCPOut: server (Candidate.Server) -> until, TCP to that server confirmed out
	TCPOut map[string]time.Time `json:"tcp_out,omitempty"`
	// TCPBlocked: until, every TCP proxy marked (a mark of a version that did not tell the servers
	// apart, kept until it ends)
	TCPBlocked time.Time `json:"tcp,omitzero"`
	Updated    time.Time `json:"at"`
}

// Note is a decision of the controller, as a journal of what stopped getting through records it
// (Controller.OnNote): never an address or a name the user visits, only the policy's proxies.
type Note struct {
	Kind   string        // one of the Note* kinds
	Tag    string        // the proxy it is about; "" for none
	Server string        // that proxy's server (Candidate.Server)
	Tier   int           // that proxy's tier, from 1; 0 for none
	Mode   string        // that proxy's mode
	From   string        // NoteUse: the proxy in use before, "" for none
	Why    string        // what led to it (see the kinds)
	Wait   time.Duration // NoteNone, NoteAsk, NoteSelect, NoteUpFailed: the next try in
}

// The kinds of Note.
const (
	NoteWalk     = "walk"          // a choice from the top starts; Why: the reason Evaluate was given, or retry
	NoteMark     = "mark"          // Tag did not answer: tried after the others in this network for NodeDownTTL
	NoteTCPOut   = "tcp_out"       // TCP to Server is out in this network (frozen or cut) for TransportDownTTL
	NoteUse      = "use"           // Tag is chosen; Why: walk, up (the way up), same (the one in use, again)
	NoteFailed   = "active_failed" // the proxy in use failed its data check; Why: its outcome
	NoteAsk      = "ask"           // only the last resort Tag is left: the group held, the user asked
	NoteAgree    = "agree"         // the user agreed to the last resort Tag
	NoteNone     = "none"          // no proxy of the policy works: everything is tried again in Wait
	NoteOffline  = "offline"       // no network: nothing is checked or marked
	NoteIdle     = "idle"          // the user picked something else than the tiered group
	NoteSelect   = "select_failed" // Tag could not be selected; tried again in Wait
	NoteUpFailed = "up_failed"     // a turn of the way up found nothing; Wait: the next one in
)

// Controller chooses the proxy of the tiered group. State, NeedsConsent, Agree and Consent are safe
// from any goroutine; the other methods are called from one (the core's loop, or a test), which
// owns every field below but the two guarded by a lock.
type Controller struct {
	// OnChange, when set, is called after the state changed (to tell the app at once).
	OnChange func()
	// OnConsent, when set, is called when the user agreed to a last-resort proxy, from the goroutine
	// that called Agree: the core keeps the agreement for the rest of its run with this profile (a
	// reload makes a new controller, see Consent).
	OnConsent func(tag string)
	// OnNote, when set, is told each decision, from the goroutine that made it (Agree's too).
	OnNote func(Note)

	env   Env
	plan  *Plan // never changes
	store Store

	stateMu sync.Mutex
	state   State // under stateMu

	consentMu sync.Mutex
	confirms  map[string]bool // the last resorts the user agreed to, under consentMu

	memory  map[string]*netMemory
	network Network
	enabled bool
	active  int // index in plan.Candidates, -1 none
	since   time.Time
	slow    bool
	waiting string // the last resort offered to the user, while the group is held for it

	received   int64 // Received of the proxy in use at its last check (or its selection)
	forceCheck bool  // the next data check is made whatever the proxy carried (a sign it fails)

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

// Consent records that the user already agreed to the last-resort proxy tag in this run of the core
// with this profile (the core's memory of it, given to a new controller).
func (c *Controller) Consent(tag string) {
	c.consentMu.Lock()
	defer c.consentMu.Unlock()
	c.confirms[tag] = true
}

// Agree records the user's agreement to the last-resort proxy tag, from any goroutine; false when tag
// is no last resort that asks for one. It holds whether or not the controller waits for it now: the
// user agreed to that proxy, and a walk that runs meanwhile takes it into account.
func (c *Controller) Agree(tag string) bool {
	if !slices.Contains(c.plan.Reserves(), tag) {
		return false
	}
	c.consentMu.Lock()
	already := c.confirms[tag]
	c.confirms[tag] = true
	c.consentMu.Unlock()
	if !already {
		c.logf("the user agreed to %s", tag)
		c.note(Note{Kind: NoteAgree, Tag: tag})
		if c.OnConsent != nil {
			c.OnConsent(tag)
		}
	}
	return true
}

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

// note tells OnNote of a decision (the server, tier and mode of its proxy filled in).
func (c *Controller) note(n Note) {
	if c.OnNote == nil {
		return
	}
	if n.Tag != "" {
		if i := c.indexOf(n.Tag); i >= 0 {
			cand := c.plan.Candidates[i]
			n.Server, n.Tier, n.Mode = cand.Server, cand.Tier+1, cand.Mode
		}
	}
	c.OnNote(n)
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
		c.note(Note{Kind: NoteIdle})
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
	// a new start (another network, the user's pick or agreement): the waits of "nothing works"
	// start again from the shortest
	c.noneWait = 0
	c.network = c.env.Network()
	if !c.network.Online {
		c.offline()
		return
	}
	c.logf("choosing (%s), network %s", why, c.network.ID)
	c.note(Note{Kind: NoteWalk, Why: why})
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
		c.forceCheck = true
	}
}

// ActiveFailed: the monitoring saw the proxy in use fail its URL test.
func (c *Controller) ActiveFailed(ctx context.Context) {
	if !c.enabled || c.active < 0 {
		return
	}
	c.nextCheck = c.env.Now()
	c.forceCheck = true
	c.Tick(ctx)
}

// Confirm: the user agreed to use the last-resort proxy tag (Agree), and the controller chooses again
// at once.
func (c *Controller) Confirm(ctx context.Context, tag string) bool {
	if !c.Agree(tag) {
		return false
	}
	c.Evaluate(ctx, "the user agreed to the last resort")
	return true
}

func (c *Controller) offline() {
	c.logf("no network: waiting, nothing marked")
	c.note(Note{Kind: NoteOffline})
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
			c.note(Note{Kind: NoteWalk, Why: "retry"})
			c.walk(ctx, true)
		}
		return
	}
	if !now.Before(c.nextCheck) && !c.checkActive(ctx, now) {
		return
	}
	if c.active > 0 && !c.nextUp.IsZero() && !c.env.Now().Before(c.nextUp) {
		c.wayUp(ctx, c.active)
	}
}

// checkActive is the data check of the proxy in use; false when it failed and Tick has nothing
// more to do (a walk or the network took over).
func (c *Controller) checkActive(ctx context.Context, now time.Time) bool {
	cand := c.plan.Candidates[c.active]
	received := c.env.Received(cand.Tag)
	if !c.forceCheck && received-c.received >= CarriedEnough {
		// the apps' data came through it since the last check, and nothing says it fails: that
		// stands for the check (no 64 KiB of its own); the next one in chk, as after a check
		c.logf("%s carried %d KiB since its last check: no check needed", cand.Tag, (received-c.received)>>10)
		c.received = received
		c.clearMark(cand)
		c.nextCheck = now.Add(c.plan.Params.Check)
		c.publish()
		return true
	}
	c.forceCheck = false
	c.checking(true)
	r := c.env.Check(ctx, cand.Tag)
	c.checking(false)
	if ctx.Err() != nil {
		return false
	}
	c.received = c.env.Received(cand.Tag)
	if r.Outcome.Works() {
		c.slow = r.Outcome == Slow
		c.clearMark(cand)
		c.nextCheck = c.env.Now().Add(c.plan.Params.Check)
		c.publish()
		return true
	}
	c.logf("%s in use: %s", cand.Tag, r.Outcome)
	c.note(Note{Kind: NoteFailed, Tag: cand.Tag, Why: r.Outcome.String()})
	switch c.confirmFailure(ctx, cand, r, 1) {
	case verdictWorks:
		c.nextCheck = c.env.Now().Add(c.plan.Params.Check)
		c.publish()
	case verdictAborted:
	default:
		c.walk(ctx, false)
	}
	return false
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
	if m.TCPOut == nil {
		m.TCPOut = map[string]time.Time{}
	}
	return m
}

// A mark is a priority, not a ban: the proxies marked down in this network are tried after the
// others, the oldest mark first, never left out while the policy has nothing else to try. A proxy
// that did not answer is marked for NodeDownTTL; TCP to a server confirmed out marks every TCP proxy
// of that server (Candidate.Server; the proxies whose server is not known are one) for
// TransportDownTTL, and no other's; any check that works takes its mark away.

// isDown: the candidate is marked in this network (by itself, or as a TCP proxy while TCP to its
// server is out).
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
	if !cand.UDP {
		if tcp := c.tcpOutUntil(cand.Server); tcp.After(until) {
			until = tcp
		}
	}
	return until
}

// tcpOutUntil is when the mark of TCP to server ends (the older mark of every TCP proxy counts
// too), zero without one.
func (c *Controller) tcpOutUntil(server string) time.Time {
	m := c.mem()
	now := c.env.Now()
	var until time.Time
	for _, u := range []time.Time{m.TCPOut[server], m.TCPBlocked} {
		if now.Before(u) && u.After(until) {
			until = u
		}
	}
	return until
}

func (c *Controller) markDown(tag string) {
	c.note(Note{Kind: NoteMark, Tag: tag})
	m := c.mem()
	m.Down[tag] = c.env.Now().Add(NodeDownTTL)
	m.Updated = c.env.Now()
	c.saveMemory()
}

func (c *Controller) markTCP(server string) {
	m := c.mem()
	m.TCPOut[server] = c.env.Now().Add(TransportDownTTL)
	m.Updated = c.env.Now()
	c.saveMemory()
}

// clearMark: the candidate works, so its mark goes; a TCP proxy that works also clears TCP to its
// server (and the older mark of every TCP proxy).
func (c *Controller) clearMark(cand Candidate) {
	m := c.mem()
	_, marked := m.Down[cand.Tag]
	_, tcp := m.TCPOut[cand.Server]
	if !marked && (cand.UDP || (!tcp && m.TCPBlocked.IsZero())) {
		return
	}
	delete(m.Down, cand.Tag)
	if !cand.UDP {
		delete(m.TCPOut, cand.Server)
		m.TCPBlocked = time.Time{}
	}
	m.Updated = c.env.Now()
	c.saveMemory()
}

// needsConsent: a last resort the user has to agree to first; until then it is not even checked
// (a check is already a handshake with the server).
func (c *Controller) needsConsent(cand Candidate) bool {
	if cand.Mode != ModeLastResort || !cand.Confirm {
		return false
	}
	c.consentMu.Lock()
	defer c.consentMu.Unlock()
	return !c.confirms[cand.Tag]
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
	tried  map[int]bool
	stalls map[string]map[string]bool // server -> the TCP proxies of it that stalled
	paths  map[string]PathVerdict     // server -> the check of its path in this walk
	tcpOut map[string]bool            // the servers this walk found TCP out to
	checks int
}

// tcpOutTo: this walk found TCP to the candidate's server out.
func (w *walkState) tcpOutTo(cand Candidate) bool { return !cand.UDP && w.tcpOut[cand.Server] }

// walk tries the candidates and selects the first that carries data: first the ones not marked in
// this network, in the policy's order, then the marked ones, the oldest mark first, a last resort
// after the others (at most retryChecks of them, a TCP one only if this walk did not just find TCP
// to its server out). A TCP proxy is left out only for its own server: TCP to one server being out
// leaves the TCP proxies of the others in the walk. A last resort that waits for the user's
// agreement is offered only when nothing else worked, of any server. retry: a later try while
// nothing works, one check a proxy, at most retryChecks in all.
func (c *Controller) walk(ctx context.Context, retry bool) {
	w := &walkState{tried: map[int]bool{}, stalls: map[string]map[string]bool{}, paths: map[string]PathVerdict{}, tcpOut: map[string]bool{}}
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
		if c.isDown(cand) || w.tcpOutTo(cand) {
			continue
		}
		if retry && w.checks >= retryChecks {
			break
		}
		switch c.try(ctx, w, i, attempts) {
		case verdictWorks:
			c.use(i, "walk")
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
		if w.tcpOutTo(c.plan.Candidates[i]) {
			continue // found out in this walk
		}
		budget--
		c.logf("trying %s again although it failed here lately", c.plan.Candidates[i].Tag)
		switch c.try(ctx, w, i, 1) {
		case verdictWorks:
			c.use(i, "walk")
			return
		case verdictAborted:
			return
		}
	}
	c.active = -1
	c.scheduleNone()
	if consent >= 0 && c.needsConsent(c.plan.Candidates[consent]) {
		// only the last resort is left: the group is held (no connection, never through it) until
		// the user agrees, or a later try finds a proxy above that works
		cand := c.plan.Candidates[consent]
		c.waiting = cand.Tag
		c.hold()
		// held, there is no connection at all (no proxy that may come back by itself): the proxies
		// above are tried again at least every HeldMax, so a device nobody watches is back within
		// minutes of its server
		if c.noneWait > HeldMax {
			c.noneWait = HeldMax
			c.nextUp = c.env.Now().Add(HeldMax)
		}
		c.logf("last resort %s waits for the user: no connection meanwhile; again in %s", cand.Tag, c.noneWait)
		c.note(Note{Kind: NoteAsk, Tag: cand.Tag, Wait: c.noneWait})
		c.setState(State{Tier: cand.Tier, Mode: cand.Mode, Reason: ReasonConfirm, Confirm: cand.Tag, Down: c.downTags(), Network: c.network.ID})
		return
	}
	// nothing works: the choice stays, and everything is tried again later (an agreement given
	// while this walk ran is taken by the walk it starts)
	c.waiting = ""
	c.logf("no proxy of the policy works; again in %s", c.noneWait)
	c.note(Note{Kind: NoteNone, Wait: c.noneWait})
	c.setState(State{Tier: -1, Reason: ReasonNone, Down: c.downTags(), Network: c.network.ID})
}

// hold puts the group on no proxy (Env.Hold).
func (c *Controller) hold() {
	if err := c.env.Hold(); err != nil {
		c.logf("hold: %v", err)
	}
}

// offered is the last resort still waiting for the user's agreement, kept in the state while later
// tries run, so the question does not come and go; "" when none.
func (c *Controller) offered() string {
	if c.waiting == "" {
		return ""
	}
	if i := c.indexOf(c.waiting); i < 0 || !c.needsConsent(c.plan.Candidates[i]) {
		return ""
	}
	return c.waiting
}

// markedOrder are the marked candidates this walk did not try, the oldest mark first.
func (c *Controller) markedOrder(w *walkState) []int {
	var order []int
	for i, cand := range c.plan.Candidates {
		if w.tried[i] || c.needsConsent(cand) || w.tcpOutTo(cand) || !c.isDown(cand) {
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
	if !cand.UDP {
		if u := c.tcpOutUntil(cand.Server); !u.IsZero() {
			if t := u.Add(-TransportDownTTL); t.After(at) {
				at = t
			}
		}
	}
	return at
}

// try checks candidate i up to attempts times and marks it, or TCP, when it fails.
func (c *Controller) try(ctx context.Context, w *walkState, i int, attempts int) verdict {
	cand := c.plan.Candidates[i]
	w.tried[i] = true
	c.setState(State{
		Tier: cand.Tier, Mode: cand.Mode, Node: cand.Tag, Reason: ReasonChecking, Checking: true, Confirm: c.offered(),
		Down: c.downTags(), Network: c.network.ID,
	})
	v := verdictDown
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			if w.checks >= walkBudget {
				break // a long walk: one try a proxy from here on
			}
			if c.env.Sleep(ctx, c.plan.Params.Retry) != nil {
				return verdictAborted
			}
		}
		if !c.env.Picked() {
			// the user picked something else meanwhile: the walk stops here
			c.SetEnabled(ctx, false)
			return verdictAborted
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
		// a TCP proxy that stalled or got no answer: is it the proxy, or TCP to its server? The path
		// to each server is checked once a walk
		path, checked := w.paths[cand.Server]
		if !checked {
			path = c.env.CheckPath(ctx, cand.Tag)
			w.paths[cand.Server] = path
			if ctx.Err() != nil {
				return verdictAborted
			}
			c.logf("the path to the server%s: %s", c.ofServer(cand), [...]string{"unknown", "ok", "blocked"}[path])
			if c.networkMoved() {
				c.Evaluate(ctx, "network changed")
				return verdictAborted
			}
		}
		if path == PathBlocked {
			v = verdictTCP
			break
		}
		if path == PathUnknown && r.Outcome == Stall {
			// no verdict of the path: a stall is a strong sign by itself, so on at once; two
			// TCP proxies of one server that stall make TCP to it out
			if w.stalls[cand.Server] == nil {
				w.stalls[cand.Server] = map[string]bool{}
			}
			w.stalls[cand.Server][cand.Tag] = true
			if len(w.stalls[cand.Server]) >= 2 {
				v = verdictTCP
			}
			break
		}
	}
	if v == verdictTCP {
		c.tcpOut(w, cand)
	} else {
		c.markDown(cand.Tag)
	}
	return v
}

// tcpOut marks TCP to the candidate's server out, for this walk and the network.
func (c *Controller) tcpOut(w *walkState, cand Candidate) {
	if c.servers() > 1 {
		c.logf("TCP to the server of %s is out in this network: on to the other servers and UDP", cand.Tag)
	} else {
		c.logf("TCP to the server is out in this network: on to UDP")
	}
	if w != nil {
		w.tcpOut[cand.Server] = true
	}
	c.note(Note{Kind: NoteTCPOut, Tag: cand.Tag})
	c.markTCP(cand.Server)
}

// servers is how many servers the plan's proxies connect to (the unknown one counted once).
func (c *Controller) servers() int {
	seen := map[string]bool{}
	for _, cand := range c.plan.Candidates {
		seen[cand.Server] = true
	}
	return len(seen)
}

// ofServer names the candidate's server in a log line when the plan has several.
func (c *Controller) ofServer(cand Candidate) string {
	if c.servers() > 1 {
		return " of " + cand.Tag
	}
	return ""
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
		path := c.env.CheckPath(ctx, cand.Tag)
		if ctx.Err() != nil {
			return verdictAborted
		}
		if path == PathBlocked {
			c.tcpOut(nil, cand)
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
			c.slow = r.Outcome == Slow
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

// use selects candidate i; why is what found it (walk, up).
func (c *Controller) use(i int, why string) {
	cand := c.plan.Candidates[i]
	if c.needsConsent(cand) {
		// the walk and the way up leave such a proxy out; the rule holds here as well
		c.logf("%s waits for the user's agreement: not used", cand.Tag)
		c.note(Note{Kind: NoteAsk, Tag: cand.Tag})
		c.active, c.waiting = -1, cand.Tag
		c.hold()
		c.setState(State{Tier: cand.Tier, Mode: cand.Mode, Reason: ReasonConfirm, Confirm: cand.Tag, Down: c.downTags(), Network: c.network.ID})
		return
	}
	if err := c.env.Select(cand.Tag); err != nil {
		// not selected: nothing changes, and the choice is made again later, as when nothing
		// works (a proxy still in use is checked again then; failing, a walk follows)
		c.logf("select %s: %v; trying again later", cand.Tag, err)
		c.scheduleNone()
		c.note(Note{Kind: NoteSelect, Tag: cand.Tag, Wait: c.noneWait})
		if c.active >= 0 {
			c.nextCheck = c.nextUp
			c.publish()
		} else {
			c.setState(State{Tier: -1, Reason: ReasonNone, Down: c.downTags(), Network: c.network.ID})
		}
		return
	}
	from := ""
	if c.active >= 0 {
		from = c.plan.Candidates[c.active].Tag
	}
	if c.active != i {
		c.since = c.env.Now()
	} else {
		why = "same"
	}
	c.active = i
	c.waiting = ""
	c.noneWait = 0
	c.received = c.env.Received(cand.Tag)
	c.forceCheck = false
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
	c.note(Note{Kind: NoteUse, Tag: cand.Tag, From: from, Why: why})
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
	case cand.UDP && !c.tcpOutUntil(cand.Server).IsZero():
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
				c.slow = r.Outcome == Slow
				c.use(i, "up") // takes the mark of the proxy checked (only), and TCP's with a TCP one
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
			c.slow = r.Outcome == Slow
			c.use(i, "up")
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
	c.note(Note{Kind: NoteUpFailed, Tag: cand.Tag, Wait: c.upWait})
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
		// a network last marked in the future: the clock went back since, and its marks would last
		// that much longer; forgotten
		if m == nil || now.Sub(m.Updated) > MemoryTTL || m.Updated.After(now.Add(clockSkew)) {
			continue
		}
		// and no mark lasts longer than its time from now, whatever the clock did
		for tag, until := range m.Down {
			if until.After(now.Add(NodeDownTTL)) {
				m.Down[tag] = now.Add(NodeDownTTL)
			}
		}
		if m.TCPBlocked.After(now.Add(TransportDownTTL)) {
			m.TCPBlocked = now.Add(TransportDownTTL)
		}
		for server, until := range m.TCPOut {
			if until.After(now.Add(TransportDownTTL)) {
				m.TCPOut[server] = now.Add(TransportDownTTL)
			}
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
