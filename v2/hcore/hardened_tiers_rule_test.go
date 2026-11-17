package hcore

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hiddify/hiddify-core/v2/config"
	"github.com/hiddify/hiddify-core/v2/tiered"
)

// The rule of the last resort in the core (tierSelect, tierSettle, around a reload, at the stop),
// the keys of the user's agreement, and what the check of a proxy takes for a transfer. No engine:
// the tiered selector is a fake that records its choices.

type fakeChoice struct {
	now     string
	members []string
	picks   []string
}

func (f *fakeChoice) SelectOutbound(tag string) bool {
	for _, m := range f.members {
		if m == tag {
			f.now = tag
			f.picks = append(f.picks, tag)
			return true
		}
	}
	return false
}

const (
	ruleTwo  = "2 Bravo § 2"
	ruleNine = "9 India § 9"
	ruleTen  = "10 Juliet § 10"
	rulePol  = "v=1;t=auto:2;t=fallback:9;t=last-resort,confirm:10"
)

// ruleSetup is the setup of a profile with 2, 9 and the last resort 10, by profile path and the
// fingerprint of 10.
func ruleSetup(t *testing.T, profile, policy, fingerprint string, below ...string) *tierSetup {
	t.Helper()
	p, err := tiered.Parse(policy)
	if err != nil {
		t.Fatal(err)
	}
	tags := append([]string{ruleTwo, ruleNine, ruleTen}, below...)
	plan := p.Bind(tags, func(tag string) bool { return tag != ruleTwo })
	return &tierSetup{plan: plan, consentKeys: tierConsentKeys(plan, profile, policy, map[string]string{ruleTen: fingerprint})}
}

func ruleChoice(now string) *fakeChoice {
	return &fakeChoice{now: now, members: []string{ruleTwo, ruleNine, ruleTen, config.OutboundTieredWaitTag}}
}

func forgetConsents(t *testing.T) {
	keepTierConsents(nil)
	t.Cleanup(func() { keepTierConsents(nil) })
}

// The group starts on the last resort (the cache of a run killed while it was in use, a crash, a
// stop that alerted): it moves off before anything goes through it, to the first proxy that needs
// no agreement; with only the last resort left, to the wait. Once the user agreed, it stays.
func TestTierSettleNeverStartsOnALastResort(t *testing.T) {
	forgetConsents(t)
	setup := ruleSetup(t, "/profiles/a.json", rulePol, "fp")
	sel := ruleChoice(ruleTen)
	tierSettle(sel, sel.now, setup)
	if sel.now != ruleTwo {
		t.Fatalf("starts on %q", sel.now)
	}
	// left on the wait by a run that waited for the user: the top again
	sel = ruleChoice(config.OutboundTieredWaitTag)
	tierSettle(sel, sel.now, setup)
	if sel.now != ruleTwo {
		t.Fatalf("starts on %q", sel.now)
	}
	// nothing but the last resort in the plan (the proxies above gone): the wait
	only := ruleSetup(t, "/profiles/a.json", "v=1;t=auto:77;t=last-resort,confirm:10", "fp")
	sel = ruleChoice(ruleTen)
	tierSettle(sel, sel.now, only)
	if sel.now != config.OutboundTieredWaitTag {
		t.Fatalf("starts on %q", sel.now)
	}
	// a group without a plan: held
	sel = ruleChoice(ruleTen)
	tierSettle(sel, sel.now, nil)
	if sel.now != config.OutboundTieredWaitTag {
		t.Fatalf("without a plan: %q", sel.now)
	}
	// agreed in this run: it stays
	rememberTierConsent(setup.consentKeys[ruleTen])
	sel = ruleChoice(ruleTen)
	tierSettle(sel, sel.now, setup)
	if sel.now != ruleTen || len(sel.picks) != 0 {
		t.Fatalf("an agreed last resort moved to %q", sel.now)
	}
	// the stop ends the agreements, and settles the choice the cache keeps for the next start
	keepTierConsents(nil)
	tierSettle(sel, sel.now, setup)
	if sel.now != ruleTwo {
		t.Fatalf("after the stop: %q", sel.now)
	}
}

// Every selection the controller makes goes through the rule: the last resort without the agreement
// gets the wait, never the proxy.
func TestTierSelectHoldsAnUnagreedLastResort(t *testing.T) {
	forgetConsents(t)
	setup := ruleSetup(t, "/profiles/a.json", rulePol, "fp")
	sel := ruleChoice(ruleNine)
	if err := tierSelect(sel, setup, ruleTen); err == nil || sel.now != config.OutboundTieredWaitTag {
		t.Fatalf("selected %q, err %v", sel.now, err)
	}
	if err := tierSelect(sel, setup, ruleNine); err != nil || sel.now != ruleNine {
		t.Fatalf("selected %q, err %v", sel.now, err)
	}
	rememberTierConsent(setup.consentKeys[ruleTen])
	if err := tierSelect(sel, setup, ruleTen); err != nil || sel.now != ruleTen {
		t.Fatalf("after the agreement: %q, err %v", sel.now, err)
	}
	if untestable := func() map[string]bool {
		runningTierPlan.Store(setup)
		defer runningTierPlan.Store(nil)
		keepTierConsents(nil)
		return tierUntestable()
	}(); !untestable[ruleTen] || len(untestable) != 1 {
		t.Fatalf("untestable %v", untestable)
	}
}

// An agreement is for that proxy of that profile under that policy: another profile with a proxy of
// the same tag, a new policy, or new options of the proxy under its tag ask again; a reload of the
// same keeps it. keepTierConsents (the start of a config) drops the others.
func TestTierAgreementIsForThatProxyOfThatProfile(t *testing.T) {
	forgetConsents(t)
	a := ruleSetup(t, "/profiles/a.json", rulePol, "fp1")
	rememberTierConsent(a.consentKeys[ruleTen])
	for name, other := range map[string]*tierSetup{
		"another profile":     ruleSetup(t, "/profiles/b.json", rulePol, "fp1"),
		"another policy":      ruleSetup(t, "/profiles/a.json", rulePol+";up=1200", "fp1"),
		"the proxy's options": ruleSetup(t, "/profiles/a.json", rulePol, "fp2"),
	} {
		if !other.needsConsent(ruleTen) {
			t.Fatalf("%s: the agreement carried over", name)
		}
	}
	same := ruleSetup(t, "/profiles/a.json", rulePol, "fp1")
	if same.needsConsent(ruleTen) {
		t.Fatal("a reload of the same profile asks again")
	}
	// a hot reload: to another profile holds the group first; to the same does not
	if !tierReloadHolds(ruleTen, a, ruleSetup(t, "/profiles/b.json", rulePol, "fp1")) || tierReloadHolds(ruleTen, a, same) {
		t.Fatal("reload hold")
	}
	// to a config without the group: the old last resort is not left in the cache
	if !tierReloadHolds(ruleTen, a, nil) || tierReloadHolds(ruleTwo, a, nil) {
		t.Fatal("reload to no group")
	}
	keepTierConsents(ruleSetup(t, "/profiles/b.json", rulePol, "fp1"))
	if !same.needsConsent(ruleTen) {
		t.Fatal("the start of another profile kept the agreement")
	}
}

// The check takes only the file for a transfer: an error page, a redirect, an empty or short answer
// fail (and, the proxy having connected, the neutral check decides); a header that does not end
// fails at its limit.
func TestTierTransferCheckNeedsTheFile(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"404, empty": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(http.StatusNotFound)
		},
		"403 page": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			w.Write(make([]byte, 65536))
		},
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/elsewhere", http.StatusMovedPermanently)
		},
		"200, 100 bytes": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "100")
			w.Write(make([]byte, 100))
		},
		"chunked, 1 KiB": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write(make([]byte, 1024))
			w.(http.Flusher).Flush()
		},
		"a header line of 1 MiB": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Long", strings.Repeat("a", 1<<20))
			w.WriteHeader(http.StatusPartialContent)
			w.Write(make([]byte, 65536))
		},
		"headers of 40 KiB": func(w http.ResponseWriter, r *http.Request) {
			for i := range 40 {
				w.Header().Set("X-Part-"+string(rune('a'+i%26))+string(rune('a'+i/26)), strings.Repeat("b", 1000))
			}
			w.WriteHeader(http.StatusPartialContent)
			w.Write(make([]byte, 65536))
		},
	} {
		dialer := tierTestServer(t, handler)
		start := time.Now()
		r, dialed := transferCheck(context.Background(), dialer, "example.com", "/files/sample.bin")
		if r.Outcome != tiered.NoConnect || !dialed {
			t.Errorf("%s: %s, dialed %v", name, r.Outcome, dialed)
		}
		if took := time.Since(start); took > tierCheckAnswer {
			t.Errorf("%s: took %s", name, took)
		}
	}
	// the whole file, 200 or 206: it works
	for _, code := range []int{http.StatusOK, http.StatusPartialContent} {
		dialer := tierTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "65536")
			w.WriteHeader(code)
			w.Write(make([]byte, 65536))
		})
		if r, _ := transferCheck(context.Background(), dialer, "example.com", "/files/sample.bin"); r.Outcome != tiered.OK {
			t.Fatalf("%d: %s", code, r.Outcome)
		}
	}
}
