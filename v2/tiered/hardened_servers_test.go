package tiered

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Two servers in one subscription, the proxies of the first numbered 1-10 and of the second 11-20,
// in one ranking. Proxy types as in the sample (9, 19: XHTTP over HTTP/3; 10, 20: WireGuard).
var twoServerTags = []string{
	"1 A gRPC compact", "2 A gRPC", "3 A XHTTP", "4 A XHTTP compact", "5 A Naive", "6 A gRPC two", "7 A XHTTP two",
	"9 A HTTP3", "10 A WG",
	"11 B gRPC compact", "12 B gRPC", "13 B XHTTP", "14 B XHTTP compact", "15 B Naive", "16 B gRPC two",
	"17 B XHTTP two", "19 B HTTP3", "20 B WG",
}

const twoServerPolicy = "v=1; t=auto:2,3; t=auto:12,13; t=auto:1,4,11,14; t=fallback:5,15,6,7; t=fallback:9,19;" +
	" t=last-resort,confirm,max=60:10,20; fail=2; retry=4"

func twoServerUDP(tag string) bool {
	n := number(tag)
	return n == "9" || n == "10" || n == "19" || n == "20"
}

// serverOf is the server of a proxy: A for 1-10, B for 11-20.
func serverOf(tag string) string {
	var n int
	fmt.Sscan(number(tag), &n)
	if n > 10 {
		return "B"
	}
	return "A"
}

// twoServerPlan binds the policy; servers: whether the plan tells the servers apart (the core does
// since 5.9.8-sp.11; without, all the proxies are of one unknown server, as before).
func twoServerPlan(t *testing.T, servers bool) *Plan {
	p, err := Parse(twoServerPolicy)
	if err != nil {
		t.Fatal(err)
	}
	plan := p.Bind(twoServerTags, twoServerUDP)
	if servers {
		plan.SetServers(func(tag string) string {
			return map[string]string{"A": "192.0.2.1/32", "B": "198.51.100.1/32"}[serverOf(tag)]
		})
	}
	return plan
}

// blocked is what the network does to the servers: their TCP, their UDP. A blocked address drops
// the packets: a check of a proxy times out after 6 s (tierCheckAnswer), the check of the path
// after 5 s (its TimeoutMs); a working check takes 1 s.
type blocked struct{ tcpA, udpA, tcpB, udpB bool }

func (b blocked) script(tag string, _ time.Time) (Outcome, time.Duration) {
	udp := twoServerUDP(tag)
	out := map[string]bool{"A": udp && b.udpA || !udp && b.tcpA, "B": udp && b.udpB || !udp && b.tcpB}[serverOf(tag)]
	if out {
		return NoConnect, 6 * time.Second
	}
	return OK, time.Second
}

func (b blocked) path(tag string, _ time.Time) (PathVerdict, time.Duration) {
	if map[string]bool{"A": b.tcpA, "B": b.tcpB}[serverOf(tag)] {
		return PathBlocked, 5 * time.Second
	}
	return PathOK, time.Second
}

// handshakesBy are the handshakes with each server's address: a check of a proxy, or of the path.
func handshakesBy(env *fakeEnv) map[string]int {
	by := map[string]int{}
	for _, tag := range append(append([]string(nil), env.checks...), env.paths...) {
		by[serverOf(tag)]++
	}
	return by
}

type serverRun struct {
	selected   string
	took       time.Duration
	handshakes map[string]int
	checks     string
	state      State
}

func runServers(t *testing.T, b blocked, servers bool) (serverRun, *fakeEnv, *Controller) {
	env := newFakeEnv(t)
	env.script = b.script
	env.pathOf = b.path
	c := New(env, twoServerPlan(t, servers), nil)
	c.SetEnabled(context.Background(), true)
	run := serverRun{selected: env.selected, took: env.elapsed(), handshakes: handshakesBy(env), state: c.State()}
	var names []string
	for _, tag := range env.checks {
		names = append(names, number(tag))
	}
	run.checks = strings.Join(names, ",")
	t.Logf("servers told apart %v, blocked %+v: selected %q after %s, handshakes %v, checks %s, paths %d",
		servers, b, env.selected, env.elapsed(), run.handshakes, run.checks, len(env.paths))
	return run, env, c
}

// The address of the first server blocked (TCP and UDP): the check of the path to the subscription's
// server marked every TCP proxy, of both servers, and the walk went down to UDP (the first server's
// HTTP/3, then the second's). Now TCP to the first server says nothing of the second: on to its TCP
// proxy, the next in the ranking.
func TestTierServersFirstAddressBlocked(t *testing.T) {
	b := blocked{tcpA: true, udpA: true}
	before, _, _ := runServers(t, b, false)
	if number(before.selected) != "19" {
		t.Fatalf("one server as before: selected %q", before.selected)
	}
	now, env, c := runServers(t, b, true)
	if number(now.selected) != "12" {
		t.Fatalf("selected %q (checks %s)", now.selected, now.checks)
	}
	// one check of 2 (no second try once its server's path is out), one check of the path to A, 12
	if now.checks != "2,12" || len(env.paths) != 1 || serverOf(env.paths[0]) != "A" {
		t.Fatalf("checks %s, paths %q", now.checks, env.paths)
	}
	if now.took != 12*time.Second || now.handshakes["A"] != 2 || now.handshakes["B"] != 1 {
		t.Fatalf("after %s, handshakes %v", now.took, now.handshakes)
	}
	if before.took != 28*time.Second || before.handshakes["A"] != 4 || before.handshakes["B"] != 1 {
		t.Fatalf("before: after %s, handshakes %v", before.took, before.handshakes)
	}
	// TCP to A is marked, the TCP proxies of B are not
	for _, tag := range c.State().Down {
		if serverOf(tag) == "B" {
			t.Fatalf("a proxy of B marked: %v", c.State().Down)
		}
	}
	if s := c.State(); s.Reason == ReasonConfirm || s.Mode != ModeAuto || s.Tier != 1 {
		t.Fatalf("state %+v", s)
	}
}

// TCP of the first server blocked, its UDP working: before, the walk went to that UDP proxy (below
// the second server's TCP proxies in the ranking); now to the second server's TCP proxy.
func TestTierServersFirstTCPBlocked(t *testing.T) {
	b := blocked{tcpA: true}
	before, _, _ := runServers(t, b, false)
	now, _, _ := runServers(t, b, true)
	if number(before.selected) != "9" || number(now.selected) != "12" {
		t.Fatalf("before %q, now %q", before.selected, now.selected)
	}
	if now.took != 12*time.Second || before.took != 12*time.Second {
		t.Fatalf("before %s, now %s", before.took, now.took)
	}
}

// TCP of both servers blocked: one check of the path to each, then UDP, with no question.
func TestTierServersBothTCPBlocked(t *testing.T) {
	b := blocked{tcpA: true, tcpB: true}
	now, env, c := runServers(t, b, true)
	if number(now.selected) != "9" {
		t.Fatalf("selected %q (checks %s)", now.selected, now.checks)
	}
	if now.checks != "2,12,9" || len(env.paths) != 2 {
		t.Fatalf("checks %s, paths %q", now.checks, env.paths)
	}
	if now.took != 23*time.Second || now.handshakes["A"] != 3 || now.handshakes["B"] != 2 {
		t.Fatalf("after %s, handshakes %v", now.took, now.handshakes)
	}
	if s := c.State(); s.Reason != ReasonTCP {
		t.Fatalf("state %+v", s)
	}
	before, _, _ := runServers(t, b, false)
	if number(before.selected) != "9" || before.took != 12*time.Second {
		t.Fatalf("before: %q after %s", before.selected, before.took)
	}
}

// Everything blocked, on both servers: the last resort is asked for once, after the proxies of both
// servers were tried, and stays asked for while the later tries run.
func TestTierServersAllBlockedAsksOnce(t *testing.T) {
	b := blocked{tcpA: true, udpA: true, tcpB: true, udpB: true}
	now, env, c := runServers(t, b, true)
	if s := c.State(); s.Reason != ReasonConfirm || number(s.Confirm) != "10" || env.selected != held {
		t.Fatalf("state %+v, selected %q (checks %s)", s, env.selected, now.checks)
	}
	// both servers' TCP (one check and one look at the path each) and UDP were tried first
	for _, n := range []string{"2", "12", "9", "19"} {
		if !strings.Contains(","+now.checks+",", ","+n+",") {
			t.Fatalf("%s not tried before the question (checks %s)", n, now.checks)
		}
	}
	for _, tag := range env.checks {
		if n := number(tag); n == "10" || n == "20" {
			t.Fatal("a last resort was checked before the user agreed")
		}
	}
	asked := 0
	last := ""
	c.OnChange = func() {
		if s := c.State(); s.Confirm != "" && s.Confirm != last {
			asked++
		}
		last = c.State().Confirm
	}
	last = c.State().Confirm
	env.runFor(context.Background(), c, 30*time.Minute)
	if s := c.State(); s.Reason != ReasonConfirm || number(s.Confirm) != "10" || asked != 0 {
		t.Fatalf("after 30 min: %+v, asked %d more times", s, asked)
	}
	t.Logf("question after %s, handshakes %v", now.took, now.handshakes)
}

// The marks are kept between runs per server: a new run knows TCP to A is out, and starts on B's
// TCP proxy without a check of the path; a mark from an older version (every TCP proxy) still holds
// until it ends.
func TestTierServersMemoryTellsServersApart(t *testing.T) {
	b := blocked{tcpA: true, udpA: true}
	env := newFakeEnv(t)
	env.script, env.pathOf = b.script, b.path
	store := &memStore{}
	c := New(env, twoServerPlan(t, true), store)
	c.SetEnabled(context.Background(), true)
	if number(env.selected) != "12" || !strings.Contains(string(store.data), `"tcp_out":{"192.0.2.1/32"`) {
		t.Fatalf("selected %q, memory %s", env.selected, store.data)
	}
	env2 := newFakeEnv(t)
	env2.now = env.now.Add(time.Minute)
	env2.script, env2.pathOf = b.script, b.path
	c2 := New(env2, twoServerPlan(t, true), store)
	c2.SetEnabled(context.Background(), true)
	if number(env2.selected) != "12" || len(env2.paths) != 0 || len(env2.checks) != 1 {
		t.Fatalf("second run: selected %q, checks %q, paths %q", env2.selected, env2.checks, env2.paths)
	}
}

// The ranking of the task, the first server's address blocked: the switch, before and now.
func TestTierServersSwitchTimes(t *testing.T) {
	for _, tc := range []struct {
		name string
		b    blocked
	}{
		{"first address blocked", blocked{tcpA: true, udpA: true}},
		{"first TCP blocked", blocked{tcpA: true}},
		{"both TCP blocked", blocked{tcpA: true, tcpB: true}},
		{"everything blocked", blocked{tcpA: true, udpA: true, tcpB: true, udpB: true}},
	} {
		before, _, _ := runServers(t, tc.b, false)
		now, _, _ := runServers(t, tc.b, true)
		t.Logf("%-22s before: %-14q %5s %v | now: %-14q %5s %v", tc.name,
			before.selected, before.took, before.handshakes, now.selected, now.took, now.handshakes)
	}
}

// Before servers were told apart, the first server's address blocked left the client on the second
// server's UDP proxy, and only the way up brought it to its TCP proxy, the turns of which come after
// the policy's up (900 s here), twice that after a turn that found nothing, and a proxy above has to
// pass twice, a minute apart.
func TestTierServersWayUpBefore(t *testing.T) {
	b := blocked{tcpA: true, udpA: true}
	for _, servers := range []bool{false, true} {
		env := newFakeEnv(t)
		env.script, env.pathOf = b.script, b.path
		c := New(env, twoServerPlan(t, servers), nil)
		ctx := context.Background()
		c.SetEnabled(ctx, true)
		end := env.now.Add(4 * time.Hour)
		for number(env.selected) != "12" && env.now.Before(end) {
			next := c.NextWake()
			if next.IsZero() || next.After(end) {
				break
			}
			if next.After(env.now) {
				env.now = next
			}
			c.Tick(ctx)
		}
		t.Logf("servers told apart %v: on 12 after %s (handshakes %v)", servers, env.elapsed(), handshakesBy(env))
		if number(env.selected) != "12" {
			t.Fatalf("servers %v: still on %q after %s", servers, env.selected, env.elapsed())
		}
		if servers && env.elapsed() != 12*time.Second {
			t.Fatalf("on 12 after %s", env.elapsed())
		}
	}
}
