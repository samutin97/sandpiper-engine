package hcore

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"

	"github.com/hiddify/hiddify-core/v2/tiered"
)

// The proxy the controller chose after a check of its own stands for a working connection until
// the monitoring has a result for it (E12-03 of the sp.12 acceptance): the last resort is not
// tested before the user agrees, so after the agreement the home screen said "connection failed"
// though the proxy carried data, until its first ping came.
func TestTierChoiceStandsUntilAPing(t *testing.T) {
	chosen := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	state := tiered.State{Tier: 4, Mode: "last-resort", Node: "10 WG", Reason: tiered.ReasonOK, Since: chosen.Unix()}
	ping := func(at time.Time, delay uint16) *adapter.URLTestHistory {
		return &adapter.URLTestHistory{Time: at, Delay: delay}
	}
	for _, c := range []struct {
		name    string
		state   tiered.State
		tag     string
		history *adapter.URLTestHistory
		want    bool
	}{
		{"no ping yet", state, "10 WG", nil, true},
		{"only a ping from the cache", state, "10 WG", &adapter.URLTestHistory{Time: chosen.Add(time.Hour), Delay: 120, IsFromCache: true}, true},
		{"a ping from before the choice", state, "10 WG", ping(chosen.Add(-time.Minute), 0), true},
		{"a failed ping after the choice", state, "10 WG", ping(chosen.Add(30*time.Second), 0), false},
		{"a failed ping in the second of the choice", state, "10 WG", ping(chosen, 0), false},
		{"the group shows another proxy", state, "2 gRPC", nil, false},
		{"no proxy shown", state, "", nil, false},
		{"chosen at no known time", tiered.State{Node: "10 WG", Reason: tiered.ReasonOK}, "10 WG", nil, false},
		{"TCP out, on a UDP proxy", tiered.State{Node: "9 HTTP3", Reason: tiered.ReasonTCP, Since: chosen.Unix()}, "9 HTTP3", nil, true},
		{"the proxies above fail", tiered.State{Node: "9 HTTP3", Reason: tiered.ReasonNodeFailed, Since: chosen.Unix()}, "9 HTTP3", nil, true},
		{"slow", tiered.State{Node: "2 gRPC", Reason: tiered.ReasonSlow, Since: chosen.Unix()}, "2 gRPC", nil, true},
		{"waiting for the user", tiered.State{Tier: 4, Node: "10 WG", Reason: tiered.ReasonConfirm, Confirm: "10 WG", Since: chosen.Unix()}, "10 WG", nil, false},
		{"nothing works", tiered.State{Tier: -1, Node: "10 WG", Reason: tiered.ReasonNone, Since: chosen.Unix()}, "10 WG", nil, false},
		{"a walk checks it", tiered.State{Node: "10 WG", Reason: tiered.ReasonChecking, Checking: true}, "10 WG", nil, false},
		{"offline", tiered.State{Node: "10 WG", Reason: tiered.ReasonOffline, Since: chosen.Unix()}, "10 WG", nil, false},
	} {
		if got := tierChoiceStands(c.state, c.tag, c.history); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
