package tiered

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeEnv runs the controller on a virtual clock: a check takes the time its script says, a sleep
// moves the clock. Nothing goes to a network and no engine starts.
type fakeEnv struct {
	t        *testing.T
	now      time.Time
	start    time.Time
	network  Network
	selected string
	selects  []string
	// script answers a check of tag at the current time
	script     func(tag string, now time.Time) (Outcome, time.Duration)
	path       func(now time.Time) (PathVerdict, time.Duration)
	checks     []string // every proxy checked, in order
	handshakes int      // TLS or QUIC handshakes with the server: one per check of a proxy or of the path
	log        []string
}

func newFakeEnv(t *testing.T) *fakeEnv {
	start := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	return &fakeEnv{
		t: t, now: start, start: start, network: Network{ID: "net-a", Online: true},
		script: func(string, time.Time) (Outcome, time.Duration) { return OK, 800 * time.Millisecond },
		path:   func(time.Time) (PathVerdict, time.Duration) { return PathOK, 2 * time.Second },
	}
}

func (e *fakeEnv) Now() time.Time { return e.now }
func (e *fakeEnv) Sleep(ctx context.Context, d time.Duration) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	e.now = e.now.Add(d)
	return nil
}
func (e *fakeEnv) Check(_ context.Context, tag string) CheckResult {
	e.checks = append(e.checks, tag)
	e.handshakes++
	outcome, took := e.script(tag, e.now)
	e.now = e.now.Add(took)
	return CheckResult{Outcome: outcome, Latency: took / 2}
}
func (e *fakeEnv) CheckPath(context.Context) PathVerdict {
	e.handshakes++
	v, took := e.path(e.now)
	e.now = e.now.Add(took)
	return v
}
func (e *fakeEnv) Select(tag string) error {
	e.selected = tag
	e.selects = append(e.selects, tag)
	return nil
}
func (e *fakeEnv) Network() Network { return e.network }
func (e *fakeEnv) Log(m string)     { e.log = append(e.log, m) }
func (e *fakeEnv) elapsed() time.Duration {
	return e.now.Sub(e.start)
}

// runFor ticks the controller as the core's loop would, until the virtual clock passes d.
func (e *fakeEnv) runFor(ctx context.Context, c *Controller, d time.Duration) {
	end := e.now.Add(d)
	for e.now.Before(end) {
		next := c.NextWake()
		if next.IsZero() || next.After(end) {
			e.now = end
			return
		}
		if next.After(e.now) {
			e.now = next
		}
		c.Tick(ctx)
	}
}

type memStore struct{ data []byte }

func (m *memStore) Load() []byte  { return m.data }
func (m *memStore) Save(b []byte) { m.data = append([]byte(nil), b...) }

func samplePlan(t *testing.T) *Plan {
	p, err := Parse(samplePolicy)
	if err != nil {
		t.Fatal(err)
	}
	return p.Bind(sampleTags, sampleUDP)
}

func number(tag string) string { n, _, _ := strings.Cut(tag, " "); return n }

func started(t *testing.T, env *fakeEnv, store Store) *Controller {
	c := New(env, samplePlan(t), store)
	c.SetEnabled(context.Background(), true)
	return c
}

func TestTierAllWorks(t *testing.T) {
	env := newFakeEnv(t)
	c := started(t, env, nil)
	if env.selected != "2 Bravo gRPC" || len(env.checks) != 1 {
		t.Fatalf("selected %q after checks %q", env.selected, env.checks)
	}
	if s := c.State(); s.Reason != ReasonOK || s.Tier != 0 || s.Mode != ModeAuto || s.Node != "2 Bravo gRPC" {
		t.Fatalf("state %+v", s)
	}
	// an hour of work: only the data check of the proxy in use, every 10 min
	env.runFor(context.Background(), c, time.Hour)
	for _, tag := range env.checks {
		if tag != "2 Bravo gRPC" {
			t.Fatalf("checked %q while all works", tag)
		}
	}
	if n := len(env.checks); n < 6 || n > 8 {
		t.Fatalf("%d checks in an hour", n)
	}
}

func TestTierFirstProxyFails(t *testing.T) {
	env := newFakeEnv(t)
	env.script = func(tag string, _ time.Time) (Outcome, time.Duration) {
		if number(tag) == "2" {
			return NoConnect, 6 * time.Second
		}
		return OK, time.Second
	}
	c := started(t, env, nil)
	if env.selected != "3 Charlie XHTTP" {
		t.Fatalf("selected %q (checks %q)", env.selected, env.checks)
	}
	// two tries of 2 (fail=2), one look at the path, then 3
	if got := strings.Join(env.checks, ","); got != "2 Bravo gRPC,2 Bravo gRPC,3 Charlie XHTTP" {
		t.Fatalf("checks %s", got)
	}
	if s := c.State(); s.Reason != ReasonNodeFailed || len(s.Down) != 1 {
		t.Fatalf("state %+v", s)
	}
	if env.elapsed() > 25*time.Second {
		t.Fatalf("took %s", env.elapsed())
	}
}

// The "16 KB" freeze of TCP on the network: every TCP proxy connects and stalls, UDP works.
func freezeTCP(env *fakeEnv) {
	env.script = func(tag string, _ time.Time) (Outcome, time.Duration) {
		if sampleUDP(tag) {
			return OK, 2 * time.Second
		}
		return Stall, 6 * time.Second // ~1 s handshake, data, then 4 s without a byte
	}
}

func TestTierTCPFreezeGoesStraightToUDP(t *testing.T) {
	env := newFakeEnv(t)
	freezeTCP(env)
	env.path = func(time.Time) (PathVerdict, time.Duration) { return PathBlocked, 6 * time.Second }
	c := started(t, env, nil)
	if env.selected != "9 India HTTP3" {
		t.Fatalf("selected %q (checks %q)", env.selected, env.checks)
	}
	if env.elapsed() > 20*time.Second || env.handshakes > 3 {
		t.Fatalf("UDP after %s and %d handshakes (checks %q)", env.elapsed(), env.handshakes, env.checks)
	}
	if s := c.State(); s.Reason != ReasonTCP || s.Mode != ModeFallback {
		t.Fatalf("state %+v", s)
	}
	// the last resort was never touched
	for _, tag := range env.checks {
		if number(tag) == "10" {
			t.Fatal("the last resort was checked")
		}
	}
}

func TestTierTCPFreezeWithoutAPathCheck(t *testing.T) {
	env := newFakeEnv(t)
	freezeTCP(env)
	env.path = func(time.Time) (PathVerdict, time.Duration) { return PathUnknown, 0 }
	c := started(t, env, nil)
	if env.selected != "9 India HTTP3" {
		t.Fatalf("selected %q (checks %q)", env.selected, env.checks)
	}
	// two TCP proxies stalled (no repeat of either), then UDP
	if env.elapsed() > 20*time.Second || len(env.checks) != 3 {
		t.Fatalf("after %s, checks %q", env.elapsed(), env.checks)
	}
	if c.State().Reason != ReasonTCP {
		t.Fatalf("state %+v", c.State())
	}
}

func TestTierNoNetworkMarksNothing(t *testing.T) {
	env := newFakeEnv(t)
	env.network = Network{ID: "", Online: false}
	c := started(t, env, nil)
	if len(env.checks) != 0 || env.selected != "" || c.State().Reason != ReasonOffline {
		t.Fatalf("checks %q, state %+v", env.checks, c.State())
	}
	env.runFor(context.Background(), c, time.Hour)
	if len(env.checks) != 0 {
		t.Fatalf("checked while offline: %q", env.checks)
	}
	// the network is back: the top works, nothing was marked meanwhile
	env.network = Network{ID: "net-a", Online: true}
	c.NetworkChanged(context.Background())
	if env.selected != "2 Bravo gRPC" || len(c.State().Down) != 0 {
		t.Fatalf("selected %q, state %+v", env.selected, c.State())
	}
}

func TestTierLostNetworkDuringAWalkStopsIt(t *testing.T) {
	env := newFakeEnv(t)
	env.script = func(tag string, _ time.Time) (Outcome, time.Duration) {
		env.network = Network{Online: false} // the network goes during the first check
		return NoConnect, 6 * time.Second
	}
	c := started(t, env, nil)
	if len(env.checks) != 1 || len(c.State().Down) != 0 || c.State().Reason != ReasonOffline {
		t.Fatalf("checks %q, state %+v", env.checks, c.State())
	}
}

func TestTierWayBackUp(t *testing.T) {
	env := newFakeEnv(t)
	freezeTCP(env)
	env.path = func(time.Time) (PathVerdict, time.Duration) { return PathBlocked, 6 * time.Second }
	c := started(t, env, nil)
	if env.selected != "9 India HTTP3" {
		t.Fatalf("selected %q", env.selected)
	}
	// the freeze lasts 40 minutes more
	thaw := env.now.Add(40 * time.Minute)
	env.script = func(tag string, now time.Time) (Outcome, time.Duration) {
		if sampleUDP(tag) || !now.Before(thaw) {
			return OK, time.Second
		}
		return Stall, 6 * time.Second
	}
	env.checks = nil
	env.runFor(context.Background(), c, 14*time.Minute)
	for _, tag := range env.checks {
		if !sampleUDP(tag) {
			t.Fatalf("checked %q above before hold and up (%s)", tag, env.elapsed())
		}
	}
	// first turn at 15 min: fails (frozen still), the wait doubles to 30 min; at 45 min it passes,
	// then once more a minute later, and the top comes back
	env.runFor(context.Background(), c, 50*time.Minute)
	if env.selected != "2 Bravo gRPC" {
		t.Fatalf("not back up: %q, checks %q", env.selected, env.checks)
	}
	if s := c.State(); s.Reason != ReasonOK || len(s.Down) != 0 {
		t.Fatalf("state %+v", s)
	}
	above := 0
	for _, tag := range env.checks {
		if !sampleUDP(tag) {
			above++
		}
	}
	// at most two checks a turn: 2 + 2 (failed turns are at 15 and 45 min... ) + the second pass
	if above > 6 {
		t.Fatalf("%d checks of the proxies above: %q", above, env.checks)
	}
	if len(env.selects) != 2 {
		t.Fatalf("switched %d times: %q", len(env.selects), env.selects)
	}
}

func TestTierNoFlapping(t *testing.T) {
	env := newFakeEnv(t)
	n := 0
	// the top proxy answers every other check
	env.script = func(tag string, _ time.Time) (Outcome, time.Duration) {
		if number(tag) == "2" {
			n++
			if n%2 == 0 {
				return NoConnect, 6 * time.Second
			}
		}
		return OK, time.Second
	}
	c := started(t, env, nil)
	env.runFor(context.Background(), c, 4*time.Hour)
	// a flaky proxy may move the choice now and then, never back and forth every few minutes
	if len(env.selects) > 5 {
		t.Fatalf("%d switches in 4 h: %q", len(env.selects), env.selects)
	}
	_ = c
}

func TestTierLastResortWaitsForTheUser(t *testing.T) {
	env := newFakeEnv(t)
	env.script = func(tag string, _ time.Time) (Outcome, time.Duration) {
		if number(tag) == "10" {
			return OK, time.Second
		}
		return NoConnect, 6 * time.Second
	}
	env.path = func(time.Time) (PathVerdict, time.Duration) { return PathOK, 2 * time.Second }
	c := started(t, env, nil)
	s := c.State()
	if s.Reason != ReasonConfirm || s.Confirm != "10 Juliet WG" || s.Mode != ModeLastResort {
		t.Fatalf("state %+v", s)
	}
	for _, tag := range env.checks {
		if number(tag) == "10" {
			t.Fatal("the last resort was checked before the user agreed")
		}
	}
	// waiting: the proxies above are tried again now and then, never the last resort
	env.runFor(context.Background(), c, time.Hour)
	for _, tag := range env.checks {
		if number(tag) == "10" {
			t.Fatal("the last resort was checked before the user agreed")
		}
	}
	if c.Confirm(context.Background(), "9 India HTTP3") {
		t.Fatal("agreed to a proxy that does not wait")
	}
	if !c.Confirm(context.Background(), "10 Juliet WG") || env.selected != "10 Juliet WG" {
		t.Fatalf("selected %q, state %+v", env.selected, c.State())
	}
	if c.State().Mode != ModeLastResort {
		t.Fatalf("state %+v", c.State())
	}
}

func TestTierTheUsersChoiceStopsIt(t *testing.T) {
	env := newFakeEnv(t)
	c := started(t, env, nil)
	c.SetEnabled(context.Background(), false)
	env.checks, env.selects = nil, nil
	env.runFor(context.Background(), c, 3*time.Hour)
	c.NetworkChanged(context.Background())
	c.ActiveFailed(context.Background())
	if len(env.checks) != 0 || len(env.selects) != 0 || c.State().Reason != ReasonIdle {
		t.Fatalf("checks %q, selects %q, state %+v", env.checks, env.selects, c.State())
	}
	// back to the tiered group: it chooses again
	c.SetEnabled(context.Background(), true)
	if env.selected != "2 Bravo gRPC" {
		t.Fatalf("selected %q", env.selected)
	}
}

func TestTierNetworksAreRemembered(t *testing.T) {
	env := newFakeEnv(t)
	store := &memStore{}
	frozen := map[string]bool{"net-a": true}
	env.script = func(tag string, _ time.Time) (Outcome, time.Duration) {
		if frozen[env.network.ID] && !sampleUDP(tag) {
			return Stall, 6 * time.Second
		}
		return OK, time.Second
	}
	env.path = func(time.Time) (PathVerdict, time.Duration) {
		if frozen[env.network.ID] {
			return PathBlocked, 6 * time.Second
		}
		return PathOK, 2 * time.Second
	}
	c := started(t, env, store)
	if env.selected != "9 India HTTP3" {
		t.Fatalf("network a: %q", env.selected)
	}
	env.network = Network{ID: "net-b", Online: true}
	c.NetworkChanged(context.Background())
	if env.selected != "2 Bravo gRPC" {
		t.Fatalf("network b: %q", env.selected)
	}
	// back on a: straight to UDP, one check
	env.checks = nil
	env.network = Network{ID: "net-a", Online: true}
	c.NetworkChanged(context.Background())
	if env.selected != "9 India HTTP3" || len(env.checks) != 1 {
		t.Fatalf("network a again: %q after %q", env.selected, env.checks)
	}
	// a new run of the core (app restarted) remembers it too; the memory is kept no longer than 6 h
	env.checks = nil
	c2 := New(env, samplePlan(t), store)
	c2.SetEnabled(context.Background(), true)
	if env.selected != "9 India HTTP3" || len(env.checks) != 1 {
		t.Fatalf("new run: %q after %q", env.selected, env.checks)
	}
	if strings.Contains(string(store.data), "Wi") {
		t.Fatal("the store holds a network name")
	}
	env.now = env.now.Add(7 * time.Hour)
	env.checks = nil
	c3 := New(env, samplePlan(t), store)
	c3.SetEnabled(context.Background(), true)
	if env.checks[0] != "2 Bravo gRPC" {
		t.Fatalf("the memory outlived 6 h: %q", env.checks)
	}
}

func TestTierFreezeLaterInTheSession(t *testing.T) {
	env := newFakeEnv(t)
	c := started(t, env, nil)
	freezeTCP(env)
	env.path = func(time.Time) (PathVerdict, time.Duration) { return PathBlocked, 6 * time.Second }
	before := env.now
	env.runFor(context.Background(), c, 11*time.Minute)
	if env.selected != "9 India HTTP3" || c.State().Reason != ReasonTCP {
		t.Fatalf("selected %q, state %+v", env.selected, c.State())
	}
	// found at the periodic check (10 min), not later
	if env.now.Sub(before) > 11*time.Minute {
		t.Fatal("too late")
	}
}

func TestTierActiveFailureFromTheMonitoring(t *testing.T) {
	env := newFakeEnv(t)
	c := started(t, env, nil)
	env.script = func(tag string, _ time.Time) (Outcome, time.Duration) {
		if number(tag) == "2" {
			return NoConnect, 6 * time.Second
		}
		return OK, time.Second
	}
	c.ActiveFailed(context.Background())
	if env.selected != "3 Charlie XHTTP" {
		t.Fatalf("selected %q", env.selected)
	}
}

func TestTierNothingWorks(t *testing.T) {
	env := newFakeEnv(t)
	env.script = func(string, time.Time) (Outcome, time.Duration) { return NoConnect, 6 * time.Second }
	env.path = func(time.Time) (PathVerdict, time.Duration) { return PathBlocked, 5 * time.Second }
	c := started(t, env, nil)
	if s := c.State(); s.Reason != ReasonConfirm {
		// TCP out, 9 fails too, the last resort waits for the user
		t.Fatalf("state %+v", s)
	}
	checks := len(env.checks)
	env.runFor(context.Background(), c, time.Hour)
	// tried again 1, 2, 4, 8, 15, 15... minutes apart, at most three checks a turn
	if extra := len(env.checks) - checks; extra < 4 || extra > 21 {
		t.Fatalf("%d checks in an hour of nothing", extra)
	}
	if env.selected != "" {
		t.Fatalf("selected %q", env.selected)
	}
}

func TestTierStateJSON(t *testing.T) {
	s := State{Tier: 3, Mode: ModeFallback, Node: "9 x", Reason: ReasonTCP, Down: []string{"2 y"}, Network: "a1b2c3d4", Since: 1}
	if got := s.JSON(); got != `{"tier":3,"mode":"fallback","node":"9 x","reason":"tcp-blocked","down":["2 y"],"network":"a1b2c3d4","since":1}` {
		t.Fatal(got)
	}
	if errors.Is(nil, context.Canceled) {
		t.Fatal()
	}
}

// SP5-08: after a spell of UDP being cut (9 and 10 marked), TCP fails too: 9 is tried again, the
// oldest mark first, not left out until its mark ends; the tunnel is never left with nothing to try.
func TestTierMarksArePriorityNotBan(t *testing.T) {
	env := newFakeEnv(t)
	tcpOut, udpOut := true, true
	env.script = func(tag string, _ time.Time) (Outcome, time.Duration) {
		if sampleUDP(tag) && udpOut || !sampleUDP(tag) && tcpOut {
			return NoConnect, 3 * time.Second
		}
		return OK, time.Second
	}
	env.path = func(time.Time) (PathVerdict, time.Duration) {
		if tcpOut {
			return PathBlocked, 3 * time.Second
		}
		return PathOK, time.Second
	}
	c := started(t, env, nil)
	if s := c.State(); s.Reason != ReasonConfirm {
		t.Fatalf("both out: %+v", s)
	}
	// the user agrees, the last resort fails too
	c.Confirm(context.Background(), "10 Juliet WG")
	if s := c.State(); s.Reason != ReasonNone || len(s.Down) == 0 {
		t.Fatalf("after the last resort: %+v", s)
	}
	// both come back: the next try finds the top
	tcpOut, udpOut = false, false
	env.runFor(context.Background(), c, 3*time.Minute)
	if env.selected != "2 Bravo gRPC" {
		t.Fatalf("not back: %q, %+v", env.selected, c.State())
	}
	// 10 minutes later TCP is cut again; 9 and 10 still carry their marks from the spell
	env.runFor(context.Background(), c, 5*time.Minute)
	tcpOut = true
	before := env.now
	env.checks = nil
	env.runFor(context.Background(), c, 10*time.Minute)
	if env.selected != "9 India HTTP3" {
		t.Fatalf("left with nothing: %q, %+v, checks %q", env.selected, c.State(), env.checks)
	}
	if c.State().Reason == ReasonNone {
		t.Fatalf("state %+v", c.State())
	}
	if took := env.now.Sub(before); took > 11*time.Minute {
		t.Fatalf("took %s", took)
	}
}

// Every proxy marked from an earlier spell (a new run with the memory): the switch turned on finds
// one that works at once, no minute of "none" first.
func TestTierStaleMarksDoNotStall(t *testing.T) {
	env := newFakeEnv(t)
	store := &memStore{}
	mem := map[string]*netMemory{"net-a": {Down: map[string]time.Time{}, TCPBlocked: env.now.Add(time.Hour), Updated: env.now}}
	for _, tag := range []string{"2 Bravo gRPC", "9 India HTTP3", "10 Juliet WG"} {
		mem["net-a"].Down[tag] = env.now.Add(20 * time.Minute)
	}
	store.data, _ = json.Marshal(mem)
	c := started(t, env, store)
	// the oldest mark first: TCP's (an hour ago) before 2's own (25 min ago), so 3, at once
	if env.selected != "3 Charlie XHTTP" || len(env.checks) != 1 || c.State().Reason == ReasonNone {
		t.Fatalf("selected %q, state %+v, checks %q", env.selected, c.State(), env.checks)
	}
	// TCP's mark is gone with the TCP proxy that worked; 2 keeps its own, 9 its own
	if s := c.State(); slices.Contains(s.Down, "1 Alpha gRPC compact") || !slices.Contains(s.Down, "2 Bravo gRPC") || !slices.Contains(s.Down, "9 India HTTP3") {
		t.Fatalf("marks kept: %+v", s)
	}
}

// A mark ends by itself: a proxy that did not answer for NodeDownTTL, TCP out for TransportDownTTL.
func TestTierMarksEnd(t *testing.T) {
	if NodeDownTTL < 30*time.Minute || NodeDownTTL > time.Hour || TransportDownTTL <= NodeDownTTL || TransportDownTTL > 3*time.Hour {
		t.Fatalf("ttl %s / %s", NodeDownTTL, TransportDownTTL)
	}
	env := newFakeEnv(t)
	env.script = func(tag string, _ time.Time) (Outcome, time.Duration) {
		if number(tag) == "2" {
			return NoConnect, 2 * time.Second
		}
		return OK, time.Second
	}
	c := started(t, env, nil)
	if !slices.Contains(c.State().Down, "2 Bravo gRPC") {
		t.Fatalf("not marked: %+v", c.State())
	}
	env.now = env.now.Add(NodeDownTTL + time.Minute)
	if c.isDown(c.plan.Candidates[0]) {
		t.Fatal("the mark outlived its time")
	}
}

// The user's agreement to the last resort holds for the core's run: a reload makes a new controller.
func TestTierConsentOutlivesAReload(t *testing.T) {
	env := newFakeEnv(t)
	env.script = func(tag string, _ time.Time) (Outcome, time.Duration) {
		if number(tag) == "10" {
			return OK, time.Second
		}
		return NoConnect, 2 * time.Second
	}
	agreed := ""
	c := New(env, samplePlan(t), nil)
	c.OnConsent = func(tag string) { agreed = tag }
	c.SetEnabled(context.Background(), true)
	if !slices.Equal(c.NeedsConsent(), []string{"10 Juliet WG"}) {
		t.Fatalf("needs consent %q", c.NeedsConsent())
	}
	c.Confirm(context.Background(), "10 Juliet WG")
	if agreed != "10 Juliet WG" || len(c.NeedsConsent()) != 0 {
		t.Fatalf("agreed %q", agreed)
	}
	c2 := New(env, samplePlan(t), nil)
	c2.Consent(agreed)
	c2.SetEnabled(context.Background(), true)
	if env.selected != "10 Juliet WG" || c2.State().Reason == ReasonConfirm {
		t.Fatalf("asked again: %q, %+v", env.selected, c2.State())
	}
}
