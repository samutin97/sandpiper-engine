package hcore

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hiddify/hiddify-core/v2/tiered"
)

// twoServerSetup is the setup of a subscription of two servers, A (1-10) and B (11-20), each with
// an AmneziaWG last resort that waits for the user's agreement (the ranking of the two-server
// acceptance, 19.11.2026).
func twoServerSetup(t *testing.T, profile, policy string) *tierSetup {
	t.Helper()
	p, err := tiered.Parse(policy)
	require.NoError(t, err)
	tags := []string{"12 gRPC", "13 XHTTP", "2 gRPC", "3 XHTTP", "11 TLS", "14 TLS", "1 TLS", "4 TLS",
		"19 HTTP3", "9 HTTP3", "20 AmneziaWG", "10 AmneziaWG"}
	udp := func(tag string) bool { return strings.Contains(tag, "HTTP3") || strings.Contains(tag, "AmneziaWG") }
	plan := p.Bind(tags, udp)
	return &tierSetup{plan: plan, consentKeys: tierConsentKeys(plan, profile, policy, nil)}
}

// The monitoring holds back the last resorts that wait for the user's agreement, and only those:
// both of them with two servers, from the start of the config; the one agreed to is let go, and
// held again when its agreement ends (another ranking, another profile); during a hot reload the
// running config's and the new one's. The sp.12 emulator saw AmneziaWG handshakes to both servers
// once the group moved to the second tier: keep top tested them (fixed in the engine, fb46d82ab);
// this hold is what keeps any test of the monitoring from them, whatever is selected or marked.
func TestTierHoldsTheLastResortsBack(t *testing.T) {
	forgetConsents(t)
	var held [][]string
	saved := tierHoldBack
	tierHoldBack = func(_ context.Context, tags []string) { held = append(held, tags) }
	savedPlan := runningTierPlan.Load()
	t.Cleanup(func() {
		tierHoldBack = saved
		runningTierPlan.Store(savedPlan)
		tierReloading.Store(nil)
	})
	last := func() []string {
		require.NotEmpty(t, held, "nothing told the monitoring")
		return held[len(held)-1]
	}

	const policy = "v=1;t=auto:12,13;t=auto:2,3;t=auto:11,14,1,4;t=fallback:19,9;t=last-resort,confirm,max=60:20,10;fail=2"
	setup := twoServerSetup(t, "/profiles/p1.json", policy)
	require.ElementsMatch(t, []string{"20 AmneziaWG", "10 AmneziaWG"}, setup.plan.Reserves())

	runningTierPlan.Store(setup)
	keepTierConsents(setup) // the start of the controller
	require.Equal(t, []string{"10 AmneziaWG", "20 AmneziaWG"}, last(), "both last resorts, nothing else")

	// the user agrees to 20: it may be tested now, 10 still not
	rememberTierConsent(setup.consentKeys["20 AmneziaWG"])
	require.Equal(t, []string{"10 AmneziaWG"}, last())

	// a hot reload to a new ranking: both configs' last resorts that wait are held while it runs
	next := twoServerSetup(t, "/profiles/p1.json", policy+";up=900")
	tierReloading.Store(next)
	syncTierHold()
	require.Equal(t, []string{"10 AmneziaWG", "20 AmneziaWG"}, last(), "the agreement was to the old ranking's 20")
	tierAfterReload(next)
	keepTierConsents(next) // the new controller's start: the old agreement ends
	require.Equal(t, []string{"10 AmneziaWG", "20 AmneziaWG"}, last())
	require.Nil(t, tierReloading.Load())

	// a config without the ranking holds nothing back
	runningTierPlan.Store(nil)
	keepTierConsents(nil)
	require.Empty(t, last())
}
