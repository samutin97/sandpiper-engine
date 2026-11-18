package tiered

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// The rule of the last resort: never used, nor checked, before the user agrees; the agreement safe
// from any goroutine; and the smaller rules (aliases, the waits of "nothing works", the clock, the
// user's pick during a walk, the slow mark, the length of the canonical form).

const lastResort = "10 Juliet WG"

// everything but the last resort fails
func onlyTheLastResortWorks(env *fakeEnv) {
	env.script = func(tag string, _ time.Time) (Outcome, time.Duration) {
		if number(tag) == "10" {
			return OK, time.Second
		}
		return NoConnect, 3 * time.Second
	}
	env.path = func(time.Time) (PathVerdict, time.Duration) { return PathOK, time.Second }
}

func checkedTheLastResort(env *fakeEnv) bool {
	for _, tag := range env.checks {
		if tag == lastResort {
			return true
		}
	}
	return false
}

// The group starts on the last resort (its choice kept from a run that ended without a stop) and the
// proxies above fail: it is held, never left on the last resort, which is neither checked nor
// selected until the user agrees.
func TestTierNeverLeftOnAnUnagreedLastResort(t *testing.T) {
	env := newFakeEnv(t)
	onlyTheLastResortWorks(env)
	env.selected = lastResort
	c := started(t, env, nil)
	if env.selected != held || c.State().Confirm != lastResort {
		t.Fatalf("selected %q, state %+v", env.selected, c.State())
	}
	env.runFor(context.Background(), c, time.Hour)
	c.NetworkChanged(context.Background())
	env.network = Network{ID: "net-b", Online: true}
	c.NetworkChanged(context.Background())
	env.runFor(context.Background(), c, time.Hour)
	for _, tag := range env.selects {
		if tag == lastResort {
			t.Fatalf("selected the last resort without the user: %q", env.selects)
		}
	}
	if checkedTheLastResort(env) || env.selected != held {
		t.Fatalf("checked %q, selected %q", env.checks, env.selected)
	}
	// the user agrees: now it is used
	if !c.Confirm(context.Background(), lastResort) || env.selected != lastResort {
		t.Fatalf("after the agreement: %q, %+v", env.selected, c.State())
	}
}

// use itself refuses a last resort without the agreement, whoever asks.
func TestTierUseRefusesAnUnagreedLastResort(t *testing.T) {
	env := newFakeEnv(t)
	c := started(t, env, nil)
	c.use(c.indexOf(lastResort), "walk")
	if env.selected != held || c.State().Reason != ReasonConfirm {
		t.Fatalf("selected %q, state %+v", env.selected, c.State())
	}
}

// Agree and NeedsConsent from other goroutines than the loop's (the app's calls): no data race
// (run with -race).
func TestTierConsentFromAnyGoroutine(t *testing.T) {
	env := newFakeEnv(t)
	onlyTheLastResortWorks(env)
	c := started(t, env, nil)
	var readers, agreed sync.WaitGroup
	stop := make(chan struct{})
	for range 2 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = c.NeedsConsent()
				_ = c.State()
			}
		}()
	}
	agreed.Add(1)
	go func() {
		defer agreed.Done()
		c.Agree(lastResort)
	}()
	// the loop goes on meanwhile: a walk reads the agreements
	c.Evaluate(context.Background(), "test")
	agreed.Wait()
	c.Evaluate(context.Background(), "test")
	close(stop)
	readers.Wait()
	if len(c.NeedsConsent()) != 0 || env.selected != lastResort {
		t.Fatalf("needs %q, selected %q", c.NeedsConsent(), env.selected)
	}
}

// Agree takes only a last resort that asks for the agreement.
func TestTierAgreeOnlyToALastResort(t *testing.T) {
	env := newFakeEnv(t)
	c := started(t, env, nil)
	consents := 0
	c.OnConsent = func(string) { consents++ }
	if c.Agree("2 Bravo gRPC") || c.Agree("9 India HTTP3") || c.Agree("nothing") {
		t.Fatal("agreed to a proxy that asks for no agreement")
	}
	if !c.Agree(lastResort) || !c.Agree(lastResort) || consents != 1 {
		t.Fatalf("consents %d", consents)
	}
}

// The user agrees while a later try runs, and that try finds a proxy above: the agreement is kept,
// not lost (next time the last resort is used without asking again); meanwhile the question stays
// in the state, so it does not come and go.
func TestTierAgreementDuringATry(t *testing.T) {
	env := newFakeEnv(t)
	twoBack := false
	confirmShown := true
	var c *Controller
	env.script = func(tag string, _ time.Time) (Outcome, time.Duration) {
		if twoBack && c.State().Reason == ReasonChecking && c.State().Confirm != lastResort && c.NeedsConsent() != nil {
			confirmShown = false
		}
		switch {
		case number(tag) == "10":
			return OK, time.Second
		case number(tag) == "2" && twoBack:
			if c.NeedsConsent() != nil {
				c.Agree(lastResort) // the user's tap, while this try runs
			}
			return OK, time.Second
		}
		return NoConnect, 3 * time.Second
	}
	c = New(env, samplePlan(t), nil)
	agreed := ""
	c.OnConsent = func(tag string) { agreed = tag }
	c.SetEnabled(context.Background(), true)
	if c.State().Reason != ReasonConfirm {
		t.Fatalf("state %+v", c.State())
	}
	twoBack = true
	env.runFor(context.Background(), c, 2*time.Minute)
	if env.selected != "2 Bravo gRPC" || agreed != lastResort || !confirmShown {
		t.Fatalf("selected %q, agreed %q, confirm shown during the try %v", env.selected, agreed, confirmShown)
	}
	// 2 fails again later: the last resort, without a question
	twoBack = false
	c.ActiveFailed(context.Background())
	if env.selected != lastResort || c.State().Reason == ReasonConfirm {
		t.Fatalf("selected %q, state %+v", env.selected, c.State())
	}
}

// the sample without its last resort: nothing waits for the user, the group is never held
func planWithoutTheLastResort(t *testing.T) *Plan {
	p, err := Parse(strings.Replace(samplePolicy, "; t=last-resort,confirm,max=60:10", "", 1))
	if err != nil {
		t.Fatal(err)
	}
	return p.Bind(sampleTags, sampleUDP)
}

// An hour of nothing in one network makes the waits long (15 min; 5 while the group is held for the
// user); in another network they start from the shortest again.
func TestTierNoneWaitStartsOverInANewNetwork(t *testing.T) {
	env := newFakeEnv(t)
	env.script = func(string, time.Time) (Outcome, time.Duration) { return NoConnect, 3 * time.Second }
	c := New(env, planWithoutTheLastResort(t), nil)
	c.SetEnabled(context.Background(), true)
	env.runFor(context.Background(), c, time.Hour)
	if c.noneWait != NoneMax || c.State().Reason != ReasonNone {
		t.Fatalf("wait after an hour: %s, %+v", c.noneWait, c.State())
	}
	env.network = Network{ID: "net-b", Online: true}
	c.NetworkChanged(context.Background())
	if wait := c.NextWake().Sub(env.now); wait > NoneFirst {
		t.Fatalf("next try in %s in the new network", wait)
	}
}

// A clock set back three hours does not make a stored mark last three hours more.
func TestTierClockBackDoesNotLengthenMarks(t *testing.T) {
	env := newFakeEnv(t)
	store := &memStore{}
	env.script = func(tag string, _ time.Time) (Outcome, time.Duration) {
		if number(tag) == "2" {
			return NoConnect, 3 * time.Second
		}
		return OK, time.Second
	}
	started(t, env, store)
	two := Candidate{Tag: "2 Bravo gRPC"}
	// back three hours, a new run
	env.now = env.now.Add(-3 * time.Hour)
	env.script = func(string, time.Time) (Outcome, time.Duration) { return OK, time.Second }
	c := New(env, samplePlan(t), store)
	c.network = env.network
	if c.isDown(two) {
		t.Fatalf("the mark lasts until %s, the clock is at %s", c.markUntil(two), env.now)
	}
	// a mark stored a little ahead (a clock moved back by seconds) lasts no longer than its time
	memory := map[string]*netMemory{"net-a": {Down: map[string]time.Time{"2 Bravo gRPC": env.now.Add(5 * time.Hour)}, Updated: env.now.Add(30 * time.Second)}}
	data, _ := json.Marshal(memory)
	c = New(env, samplePlan(t), &memStore{data: data})
	c.network = env.network
	if until := c.markUntil(two); until.Sub(env.now) > NodeDownTTL {
		t.Fatalf("the mark lasts %s", until.Sub(env.now))
	}
}

// The user picks another proxy during a walk: the walk stops at once, nothing more is checked or
// selected.
func TestTierWalkStopsWhenTheUserPicksAnother(t *testing.T) {
	env := newFakeEnv(t)
	env.script = func(string, time.Time) (Outcome, time.Duration) { return NoConnect, 3 * time.Second }
	env.picked = func() bool { return len(env.checks) < 1 }
	c := started(t, env, nil)
	if len(env.checks) != 1 || len(env.selects) != 0 || c.State().Reason != ReasonIdle {
		t.Fatalf("checks %q, selects %q, state %+v", env.checks, env.selects, c.State())
	}
}

// With the policy's longest tries (fail=4, retry=30) a walk of everything failing stays bounded:
// past walkBudget checks a proxy gets one try.
func TestTierWalkIsBounded(t *testing.T) {
	p, err := Parse(strings.Replace(samplePolicy, "fail=2", "fail=4;retry=30", 1))
	if err != nil {
		t.Fatal(err)
	}
	env := newFakeEnv(t)
	env.script = func(string, time.Time) (Outcome, time.Duration) { return NoConnect, 3 * time.Second }
	env.path = func(time.Time) (PathVerdict, time.Duration) { return PathUnknown, time.Second }
	c := New(env, p.Bind(sampleTags, sampleUDP), nil)
	c.SetEnabled(context.Background(), true)
	t.Logf("%d checks in %s", len(env.checks), env.elapsed())
	if n := len(env.checks); n > walkBudget+len(sampleTags) {
		t.Fatalf("%d checks in one walk", n)
	}
	if env.elapsed() > 12*time.Minute {
		t.Fatalf("the walk took %s", env.elapsed())
	}
}

// Back up to the top after a slow reserve: the reason is the top's own, not "slow".
func TestTierSlowEndsOnTheWayUp(t *testing.T) {
	env := newFakeEnv(t)
	frozen := true
	env.script = func(tag string, _ time.Time) (Outcome, time.Duration) {
		switch {
		case frozen && !sampleUDP(tag):
			return Stall, 6 * time.Second
		case sampleUDP(tag):
			return Slow, 2 * time.Second
		}
		return OK, time.Second
	}
	env.path = func(time.Time) (PathVerdict, time.Duration) {
		if frozen {
			return PathBlocked, 5 * time.Second
		}
		return PathOK, time.Second
	}
	c := started(t, env, nil)
	if env.selected != "9 India HTTP3" || c.State().Reason != ReasonTCP {
		t.Fatalf("selected %q, state %+v", env.selected, c.State())
	}
	frozen = false
	env.runFor(context.Background(), c, 40*time.Minute)
	if s := c.State(); env.selected != "2 Bravo gRPC" || s.Reason != ReasonOK {
		t.Fatalf("selected %q, state %+v", env.selected, s)
	}
}

// A proxy named by its number in one tier and by its name in another is in the strictest: a last
// resort that asks for the agreement stays one, a manual proxy stays manual.
func TestPolicyAliasTakesTheStrictestTier(t *testing.T) {
	p, err := Parse("v=1;t=auto:@10%20Juliet%20WG,2;t=last-resort,confirm:10")
	if err != nil {
		t.Fatal(err)
	}
	plan := p.Bind(sampleTags, sampleUDP)
	if got := plan.Reserves(); len(got) != 1 || got[0] != lastResort {
		t.Fatalf("reserves %q, plan %+v", got, plan.Candidates)
	}
	for _, c := range plan.Candidates {
		if c.Tag == lastResort && (c.Mode != ModeLastResort || !c.Confirm || c.Tier != 1) {
			t.Fatalf("the alias: %+v", c)
		}
	}
	p, err = Parse("v=1;t=auto:2,3;t=manual:@2%20Bravo%20gRPC")
	if err != nil {
		t.Fatal(err)
	}
	plan = p.Bind(sampleTags, sampleUDP)
	if got := plan.Tags(); len(got) != 1 || got[0] != "3 Charlie XHTTP" {
		t.Fatalf("candidates %q, manual %q", got, plan.Manual)
	}
	// of two equal tiers the first, as before
	p, _ = Parse("v=1;t=auto:2;t=auto:@2%20Bravo%20gRPC,3")
	if plan := p.Bind(sampleTags, sampleUDP); plan.Candidates[0].Tag != "2 Bravo gRPC" || plan.Candidates[0].Tier != 0 {
		t.Fatalf("plan %+v", plan.Candidates)
	}
}

// A header within the limit whose canonical form (numbers brought to their bounds) is longer is no
// policy, so the core and the app never disagree on it; and no accepted policy has a canonical form
// over the limit.
func TestPolicyCanonicalStaysWithinTheLimit(t *testing.T) {
	params := ";up=1;chk=1;hold=1;ttl=1" // canonical: up=300;hold=60;chk=120;ttl=24, 6 bytes more
	header := "v=1;t=auto:1"
	// nodes ";n=@<name>:555" (8 bytes and the name) fill the rest exactly
	room := maxHeaderLength - len(header) - len(params)
	nodes := (room + 97) / 98
	names := room - 8*nodes
	for i := range nodes {
		l := min(names-(nodes-1-i), 90)
		names -= l
		header += ";n=@" + string(rune('a'+i)) + strings.Repeat("x", l-1) + ":555"
	}
	header += params
	if len(header) != maxHeaderLength {
		t.Fatalf("header of %d bytes", len(header))
	}
	if _, err := Parse(header); err == nil {
		t.Fatal("a policy whose canonical form is over the limit was taken")
	}
	// the same header without the parameters brought up is a policy
	short := strings.TrimSuffix(header, params) + ";up=300;chk=120"
	p, err := Parse(short)
	if err != nil {
		t.Fatalf("%d bytes: %v", len(short), err)
	}
	if n := len(p.Canonical()); n > maxHeaderLength {
		t.Fatalf("canonical of %d bytes", n)
	}
	if _, err := Parse(p.Canonical()); err != nil {
		t.Fatal(err)
	}
}

// Held for the user's agreement there is no connection at all: the proxies above are tried again
// at least every HeldMax (not up to 15 min), so the connection comes back by itself within minutes
// of the server; without the hold the waits still grow to NoneMax.
func TestTierHeldIsTriedAgainOften(t *testing.T) {
	env := newFakeEnv(t)
	serverBack := false
	env.script = func(tag string, _ time.Time) (Outcome, time.Duration) {
		if serverBack && number(tag) == "2" {
			return OK, time.Second
		}
		return NoConnect, 3 * time.Second
	}
	c := started(t, env, nil)
	if env.selected != held {
		t.Fatalf("selected %q", env.selected)
	}
	env.runFor(context.Background(), c, 2*time.Hour)
	if c.noneWait != HeldMax || c.NextWake().Sub(env.now) > HeldMax {
		t.Fatalf("held: wait %s, next in %s", c.noneWait, c.NextWake().Sub(env.now))
	}
	if checkedTheLastResort(env) {
		t.Fatal("the last resort was checked")
	}
	// the server comes back: the connection follows within HeldMax and a turn's checks
	serverBack = true
	back := env.now
	for env.selected == held && env.now.Sub(back) < time.Hour {
		env.runFor(context.Background(), c, 10*time.Second)
	}
	if env.selected != "2 Bravo gRPC" || env.now.Sub(back) > HeldMax+30*time.Second {
		t.Fatalf("selected %q after %s", env.selected, env.now.Sub(back))
	}
}

// The way up takes the mark of the proxy it checked, not of the ones above it it did not check.
func TestTierWayUpTakesOnlyTheCheckedMark(t *testing.T) {
	env := newFakeEnv(t)
	down := map[string]bool{"2": true, "3": true, "1": true}
	env.script = func(tag string, _ time.Time) (Outcome, time.Duration) {
		if down[number(tag)] {
			return NoConnect, 3 * time.Second
		}
		return OK, time.Second
	}
	c := started(t, env, nil)
	if env.selected != "4 Delta XHTTP compact" {
		t.Fatalf("selected %q", env.selected)
	}
	// 3 (second in the order) comes back; 2 and 1 still fail
	delete(down, "3")
	env.runFor(context.Background(), c, 40*time.Minute)
	if env.selected != "3 Charlie XHTTP" {
		t.Fatalf("selected %q", env.selected)
	}
	marked := c.downTags()
	if !slices.Contains(marked, "2 Bravo gRPC") || slices.Contains(marked, "3 Charlie XHTTP") {
		t.Fatalf("marked %q", marked)
	}
	if s := c.State(); s.Reason != ReasonNodeFailed {
		t.Fatalf("state %+v", s)
	}
}

// A selection that fails is not taken for one: the state stays, and the choice is made again.
func TestTierFailedSelectIsTriedAgain(t *testing.T) {
	env := newFakeEnv(t)
	broken := true
	selectEnv := &failingSelect{fakeEnv: env, broken: &broken}
	c := New(selectEnv, samplePlan(t), nil)
	c.SetEnabled(context.Background(), true)
	if env.selected != "" || c.State().Reason != ReasonNone || c.active >= 0 {
		t.Fatalf("selected %q, state %+v", env.selected, c.State())
	}
	if wait := c.NextWake().Sub(env.now); wait <= 0 || wait > NoneFirst {
		t.Fatalf("next try in %s", wait)
	}
	broken = false
	env.runFor(context.Background(), c, 2*time.Minute)
	if env.selected != "2 Bravo gRPC" || c.State().Reason != ReasonOK {
		t.Fatalf("selected %q, state %+v", env.selected, c.State())
	}
}

type failingSelect struct {
	*fakeEnv
	broken *bool
}

func (f *failingSelect) Select(tag string) error {
	if *f.broken {
		return errors.New("the group is being replaced")
	}
	return f.fakeEnv.Select(tag)
}

// The proxy in use carries the apps' data: that stands for its data check (no 64 KiB of its own);
// with too little data, or once something says it fails, the check is made as before.
func TestTierDataCarriedStandsForTheCheck(t *testing.T) {
	env := newFakeEnv(t)
	var carried int64
	env.received = func(tag string) int64 {
		if tag == "2 Bravo gRPC" {
			return carried
		}
		return 0
	}
	c := started(t, env, nil)
	if env.selected != "2 Bravo gRPC" {
		t.Fatalf("selected %q", env.selected)
	}
	checks := func() int {
		n := 0
		for _, tag := range env.checks {
			if tag == "2 Bravo gRPC" {
				n++
			}
		}
		return n
	}
	first := checks()
	// an hour of browsing: 1 MiB every 10 min, no check
	for range 6 {
		carried += 1 << 20
		env.runFor(context.Background(), c, 10*time.Minute)
	}
	if n := checks() - first; n != 0 {
		t.Fatalf("%d checks while it carried data", n)
	}
	// little data (less than CarriedEnough): checked again, every chk
	carried += 10 << 10
	env.runFor(context.Background(), c, 10*time.Minute+time.Second)
	if n := checks() - first; n != 1 {
		t.Fatalf("%d checks with little data", n)
	}
	// a sign it fails (the monitoring, the apps' connections): checked at once, data or not
	carried += 4 << 20
	c.ActiveFailed(context.Background())
	if n := checks() - first; n != 2 {
		t.Fatalf("%d checks after a sign of failure", n)
	}
	// a counter that starts again (a new run of the engine) is no data
	carried = 0
	env.runFor(context.Background(), c, 10*time.Minute+time.Second)
	if n := checks() - first; n != 3 {
		t.Fatalf("%d checks after the counter started again", n)
	}
}
