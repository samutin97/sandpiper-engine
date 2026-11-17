package hcore

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/monitoring"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/hiddify/hiddify-core/v2/config"
	"github.com/hiddify/hiddify-core/v2/db"
	hcommon "github.com/hiddify/hiddify-core/v2/hcommon"
	"github.com/hiddify/hiddify-core/v2/tiered"
)

// The tiered controller (package v2/tiered) runs while the core runs a config with the tiered group
// (config.TierPlan): from the start or a hot reload until the next one or the stop, beside the
// connectivity watcher. It acts only while select has the tiered group selected; the user's own
// pick in select stops it. Its checks: a transfer of 64 KiB through the proxy checked (to the
// subscription's host and test path, never another host), and DpiProbe to that host directly.

// Limits of a check through a proxy.
const (
	tierCheckAnswer   = 6 * time.Second  // connection, TLS and the answer's header
	tierCheckStall    = 4 * time.Second  // no byte of the body for that long: it stalled
	tierCheckTotal    = 10 * time.Second // the whole check
	tierCheckBytes    = 64 << 10
	tierSlowBelow     = 16 << 10 // bytes a second: slower is "slow" (it works, but degraded)
	tierPoll          = 3 * time.Second
	tierNetworkSettle = 2 * time.Second
)

// pendingTierPlan is the plan of the config built last (buildRunningConfig); runningTierPlan the
// plan of the config the core runs, from its start (or the reload that brought it) on. nil: no
// tiered group.
var pendingTierPlan, runningTierPlan atomic.Pointer[tierSetup]

type tierSetup struct {
	plan    *tiered.Plan
	host    string
	path    string
	testURL string
	// consentKeys name the user's agreement to each last resort that asks for one (and only those):
	// the profile, its policy and the proxy itself (its options). An agreement holds for that proxy
	// of that profile, in this run of the core: another profile with a proxy of the same tag, a new
	// policy, or a proxy whose options changed under its tag asks again.
	consentKeys map[string]string
}

// noteTierPlan keeps the tiered plan of a config built from the profile at profilePath, nil
// without a tiered group.
func noteTierPlan(hopt *config.HiddifyOptions, opts *option.Options, profilePath string) {
	if opts == nil || hopt == nil {
		pendingTierPlan.Store(nil)
		return
	}
	plan := config.TierPlan(opts, hopt)
	if plan == nil {
		pendingTierPlan.Store(nil)
		return
	}
	setup := &tierSetup{plan: plan, testURL: hopt.ConnectionTestUrl}
	if tp := hopt.TierPolicy; tp != nil && config.ValidProbeHost(tp.ProbeHost) {
		setup.host = tp.ProbeHost
		if config.ValidProbePath(tp.ProbePath) {
			setup.path = tp.ProbePath
		}
	}
	setup.consentKeys = tierConsentKeys(plan, profilePath, hopt.TierPolicy.Policy, profileFingerprints(profilePath))
	pendingTierPlan.Store(setup)
}

// tierConsentKeys are the keys of the agreements to plan's last resorts (see tierSetup).
func tierConsentKeys(plan *tiered.Plan, profile, policy string, fingerprints map[string]string) map[string]string {
	keys := map[string]string{}
	for _, tag := range plan.Reserves() {
		sum := sha256.Sum256([]byte(profile + "\x00" + policy + "\x00" + tag + "\x00" + fingerprints[tag]))
		keys[tag] = hex.EncodeToString(sum[:])
	}
	return keys
}

// reserve: tag is a last resort of this config that asks for the user's agreement.
func (s *tierSetup) reserve(tag string) bool {
	if s == nil {
		return false
	}
	_, ok := s.consentKeys[tag]
	return ok
}

// needsConsent: tag is such a last resort, and the user has not agreed to it.
func (s *tierSetup) needsConsent(tag string) bool {
	if s == nil {
		return false
	}
	key, ok := s.consentKeys[tag]
	return ok && !tierConsented(key)
}

// The rule of the last resort, kept here and only here: the tiered group is never on a last resort
// that asks for the user's agreement before the user gave it (for that proxy of that profile, in
// this run), so neither the apps' connections nor the monitoring's tests reach its server. Every
// selection in the group goes through tierSelect or tierSettle: the controller's own, at the start
// of a config before its inbounds start (tierStartGuard), around a reload, at the stop. Until the
// agreement, the group waits on config.OutboundTieredWaitTag, whose connections are refused.

// tierChoice is the tiered selector, as the rule uses it.
type tierChoice interface {
	SelectOutbound(tag string) bool
}

// tierSelect selects tag in the group; a last resort waiting for the agreement gets the wait instead.
func tierSelect(sel tierChoice, setup *tierSetup, tag string) error {
	if setup.needsConsent(tag) {
		sel.SelectOutbound(config.OutboundTieredWaitTag)
		return errors.New("waits for the user's agreement: " + tag)
	}
	if !sel.SelectOutbound(tag) {
		return errors.New("not in the tiered group: " + tag)
	}
	return nil
}

// tierSettle checks the group's choice now (from the cache of an earlier run, carried by a reload,
// or left by the stop): a last resort waiting for the agreement, or the wait, gives way to the first
// proxy that needs no agreement (the wait when there is none), the group's start; setup nil (a group
// without a plan) holds the group.
func tierSettle(sel tierChoice, now string, setup *tierSetup) {
	target := now
	switch {
	case setup == nil:
		target = config.OutboundTieredWaitTag
	case now == config.OutboundTieredWaitTag || setup.needsConsent(now):
		target = config.OutboundTieredWaitTag
		for _, cand := range setup.plan.Candidates {
			if !setup.needsConsent(cand.Tag) {
				target = cand.Tag
				break
			}
		}
	}
	if target != now {
		sel.SelectOutbound(target)
		Log(LogLevel_INFO, LogType_CORE, "tiers: the group starts on ", target, ", not on ", now)
	}
}

// tierStartGuard keeps the rule when a config starts. The selectors take their choice from the
// cache file once the outbounds start (a run that ended without a stop, the app killed by the
// system or a crash, left the last resort there); an extra service starts after them and before the
// inbounds, the monitoring's first tests and the lazy endpoints' first connection, and settles the
// group there. A config without the group overwrites the group's cached choice, so that a later
// config with one never takes it up.
type tierStartGuard struct {
	service *daemon.StartedService
}

func (g *tierStartGuard) Name() string { return "tierStartGuard" }

func (g *tierStartGuard) Start(stage adapter.StartStage, _ *adapter.Scope) error {
	if stage != adapter.StartStateStart || g.service == nil {
		return nil
	}
	instance := g.service.Instance()
	if instance == nil || instance.Box() == nil {
		return nil
	}
	setup := pendingTierPlan.Load()
	runningTierPlan.Store(setup)
	if out, ok := instance.Box().Outbound().Outbound(config.OutboundTieredTag); ok {
		if sel, ok := out.(*group.Selector); ok {
			tierSettle(sel, groupNow(sel), setup)
		}
		return nil
	}
	if cache := instance.CacheFile(); cache != nil {
		if now := cache.LoadSelected(config.OutboundTieredTag); now != "" && now != config.OutboundTieredWaitTag {
			if err := cache.StoreSelected(config.OutboundTieredTag, config.OutboundTieredWaitTag); err != nil {
				Log(LogLevel_WARNING, LogType_CORE, "tiers: cache: ", err.Error())
			}
		}
	}
	return nil
}

func (g *tierStartGuard) Close() error { return nil }

// tierBeforeReload keeps the rule over a hot reload, which carries the group's choice into the new
// config (and the cache): a choice the new config would have to ask the user for again (another
// profile, policy or proxy), or the old config's last resort when the new one has no group, goes to
// the wait first. restore puts it back when the reload fails and the old config runs on.
func tierBeforeReload(next *tierSetup) (restore func()) {
	sel := (&tierEnv{}).tieredGroup()
	if sel == nil {
		return func() {}
	}
	now := groupNow(sel)
	if !tierReloadHolds(now, runningTierPlan.Load(), next) {
		return func() {}
	}
	sel.SelectOutbound(config.OutboundTieredWaitTag)
	return func() { sel.SelectOutbound(now) }
}

// tierReloadHolds: the group's choice now must wait before a reload from running to next.
func tierReloadHolds(now string, running, next *tierSetup) bool {
	if next == nil {
		return running.reserve(now)
	}
	return next.needsConsent(now)
}

// tierAfterReload: the reloaded config runs; its group is settled as at a start.
func tierAfterReload(next *tierSetup) {
	runningTierPlan.Store(next)
	if sel := (&tierEnv{}).tieredGroup(); sel != nil {
		tierSettle(sel, groupNow(sel), next)
	}
}

var tierRun struct {
	sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	ctl     *tiered.Controller
	confirm chan string
}

// startTieredRuntime starts the controller of the config the core runs now, if it has a tiered
// group; static.lock must be held.
func startTieredRuntime() {
	stopTieredRuntime()
	setup := runningTierPlan.Load()
	// the agreements of another profile, policy or proxy end here
	keepTierConsents(setup)
	ctx := static.Context()
	if setup == nil || ctx == nil || static.Box() == nil {
		return
	}
	sel := (&tierEnv{}).tieredGroup()
	if sel == nil {
		return
	}
	tierSettle(sel, groupNow(sel), setup)
	runCtx, cancel := context.WithCancel(ctx)
	env := &tierEnv{setup: setup}
	ctl := tiered.New(env, setup.plan, tierStore{})
	ctl.OnChange = notifyTierState
	// the user's agreement to a last resort holds for the core's run with this profile, over reloads
	ctl.OnConsent = func(tag string) { rememberTierConsent(setup.consentKeys[tag]) }
	for tag, key := range setup.consentKeys {
		if tierConsented(key) {
			ctl.Consent(tag)
		}
	}
	tierRun.Lock()
	tierRun.cancel, tierRun.done, tierRun.ctl = cancel, make(chan struct{}), ctl
	tierRun.confirm = make(chan string, 1)
	done, confirm := tierRun.done, tierRun.confirm
	tierRun.Unlock()
	adoptTieredGroup()
	go func() {
		defer close(done)
		defer config.DeferPanicToError("tiers", func(err error) {
			Log(LogLevel_ERROR, LogType_CORE, "tiers: ", err.Error())
		})
		runTiers(runCtx, ctl, env, confirm)
	}()
}

// stopTieredRuntime ends the controller; static.lock must be held. A check under way ends with its
// context; the wait is bounded so that a stop is never held up for long.
func stopTieredRuntime() {
	tierRun.Lock()
	cancel, done := tierRun.cancel, tierRun.done
	tierRun.cancel, tierRun.done, tierRun.ctl, tierRun.confirm = nil, nil, nil, nil
	tierRun.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
}

// tierWatchers are the proxy lists sent to the app: a new state of the controller is sent at once,
// not with the next result of the monitoring.
var tierWatchers struct {
	sync.Mutex
	chans map[chan struct{}]bool
}

func subscribeTierState() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	tierWatchers.Lock()
	if tierWatchers.chans == nil {
		tierWatchers.chans = map[chan struct{}]bool{}
	}
	tierWatchers.chans[ch] = true
	tierWatchers.Unlock()
	return ch, func() {
		tierWatchers.Lock()
		delete(tierWatchers.chans, ch)
		tierWatchers.Unlock()
	}
}

func notifyTierState() {
	tierWatchers.Lock()
	defer tierWatchers.Unlock()
	for ch := range tierWatchers.chans {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// tierConsents are the user's agreements to last resorts in this run of the core, by their keys
// (tierSetup.consentKeys).
var tierConsents struct {
	sync.Mutex
	keys map[string]bool
}

func rememberTierConsent(key string) {
	if key == "" {
		return
	}
	tierConsents.Lock()
	defer tierConsents.Unlock()
	if tierConsents.keys == nil {
		tierConsents.keys = map[string]bool{}
	}
	tierConsents.keys[key] = true
}

func tierConsented(key string) bool {
	tierConsents.Lock()
	defer tierConsents.Unlock()
	return tierConsents.keys[key]
}

// keepTierConsents keeps the agreements to setup's last resorts only (none for nil): the config the
// core runs now.
func keepTierConsents(setup *tierSetup) {
	tierConsents.Lock()
	defer tierConsents.Unlock()
	kept := map[string]bool{}
	if setup != nil {
		for _, key := range setup.consentKeys {
			if tierConsents.keys[key] {
				kept[key] = true
			}
		}
	}
	tierConsents.keys = kept
}

// tierUntestable are the proxies nothing may test now: the last resorts still waiting for the user's
// agreement (a test is a handshake with the server).
func tierUntestable() map[string]bool {
	setup := runningTierPlan.Load()
	if setup == nil {
		return nil
	}
	untestable := map[string]bool{}
	for tag := range setup.consentKeys {
		if setup.needsConsent(tag) {
			untestable[tag] = true
		}
	}
	return untestable
}

// endTieredRun is the core's stop, after the controller's (also on a stop that alerts, an error or a
// panic): the agreements end with the run, and the group's choice, which the cache keeps, is settled
// for the next start, never a last resort the user will have to agree to again. static.lock must be
// held.
func endTieredRun() {
	keepTierConsents(nil)
	if sel := (&tierEnv{}).tieredGroup(); sel != nil {
		tierSettle(sel, groupNow(sel), runningTierPlan.Load())
	}
}

// tierState is the controller's state for the app, "" without a controller.
func tierState() string {
	tierRun.Lock()
	ctl := tierRun.ctl
	tierRun.Unlock()
	if ctl == nil {
		return ""
	}
	return ctl.State().JSON()
}

// tierConfirm is the user's agreement to a last-resort proxy: kept at once (whatever the controller
// does now, a later try included), then the controller chooses again in its loop (one pending
// choice covers several taps).
func tierConfirm(tag string) bool {
	tierRun.Lock()
	ctl, confirm := tierRun.ctl, tierRun.confirm
	tierRun.Unlock()
	if ctl == nil || !ctl.Agree(tag) {
		return false
	}
	select {
	case confirm <- tag:
	default:
	}
	return true
}

// adoptTieredGroup: the first time a policy comes, select moves from the automatic choice (lowest,
// the default before) to the tiered group, once; from then on the user's pick stays.
func adoptTieredGroup() {
	settings := db.GetTable[hcommon.AppSettings]()
	if v, err := settings.Get("tieredAdopted"); err == nil && v != nil {
		return
	}
	settings.UpdateInsert(&hcommon.AppSettings{Id: "tieredAdopted", Value: "1"})
	box := static.Box()
	if box == nil {
		return
	}
	if out, ok := box.Outbound().Outbound(config.OutboundSelectTag); ok {
		if sel, ok := out.(*group.Selector); ok && groupNow(sel) == config.OutboundURLTestTag {
			sel.SelectOutbound(config.OutboundTieredTag)
			Log(LogLevel_INFO, LogType_CORE, "tiers: select moves to the server's ranking (first policy)")
		}
	}
}

// runTiers is the controller's loop: its own wakes, a look every tierPoll at the network, the
// user's pick in select and the monitoring's result of the proxy in use, and the user's agreement.
func runTiers(ctx context.Context, ctl *tiered.Controller, env *tierEnv, confirm <-chan string) {
	// the network as the first walk finds it: a change during that walk is seen by the first poll
	lastNetwork := env.Network()
	ctl.SetEnabled(ctx, env.tieredSelected())
	lastResult, _ := env.activeResult() // a failure before this run was looked at by its start
	var passive passiveWatch
	poll := time.NewTicker(tierPoll)
	defer poll.Stop()
	wake := time.NewTimer(time.Hour)
	defer wake.Stop()
	for ctx.Err() == nil {
		wakeAt := ctl.NextWake()
		if !wake.Stop() {
			select {
			case <-wake.C:
			default:
			}
		}
		var wakeC <-chan time.Time
		if !wakeAt.IsZero() {
			wake.Reset(max(time.Until(wakeAt), 0))
			wakeC = wake.C
		}
		select {
		case <-ctx.Done():
			return
		case <-confirm:
			// the agreement is kept already (tierConfirm)
			ctl.Evaluate(ctx, "the user agreed to the last resort")
		case <-wakeC:
			ctl.Tick(ctx)
		case <-poll.C:
			ctl.SetEnabled(ctx, env.tieredSelected())
			if now := env.Network(); now != lastNetwork {
				// let the change settle: a Wi-Fi to mobile switch reports several steps
				if tierSleep(ctx, tierNetworkSettle) != nil {
					return
				}
				lastNetwork = env.Network()
				ctl.NetworkChanged(ctx)
				continue
			}
			if at, failed := env.activeResult(); at.After(lastResult) {
				lastResult = at
				if failed {
					ctl.ActiveFailed(ctx)
					continue
				}
			}
			// the apps' connections through the proxy in use get nothing back: check it now
			if tag := env.activeTag(); tag != "" && tag != config.OutboundTieredWaitTag {
				now := time.Now()
				if passive.observe(now, tag, outboundDown(tag), connViews(now)) {
					env.Log("tiers: " + tag + ": the connections through it get nothing back, checking it now")
					ctl.ActiveFailed(ctx)
				}
			}
		}
	}
}

// tierEnv is the controller's world: the running core.
type tierEnv struct {
	setup *tierSetup
}

func (e *tierEnv) Now() time.Time { return time.Now() }

func (e *tierEnv) Sleep(ctx context.Context, d time.Duration) error { return tierSleep(ctx, d) }

func tierSleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (e *tierEnv) Log(message string) {
	level := LogLevel_INFO
	if strings.HasPrefix(message, "tiers: using") || strings.Contains(message, "TCP to the server") || strings.Contains(message, "last resort") ||
		strings.Contains(message, "no proxy") || strings.Contains(message, "get nothing back") {
		level = LogLevel_WARNING
	}
	Log(level, LogType_CORE, message)
}

func (e *tierEnv) tieredGroup() *group.Selector {
	box := static.Box()
	if box == nil {
		return nil
	}
	out, ok := box.Outbound().Outbound(config.OutboundTieredTag)
	if !ok {
		return nil
	}
	sel, _ := out.(*group.Selector)
	return sel
}

// tieredSelected: select has the tiered group selected.
func (e *tierEnv) tieredSelected() bool {
	box := static.Box()
	if box == nil {
		return false
	}
	if out, ok := box.Outbound().Outbound(config.OutboundSelectTag); ok {
		if sel, ok := out.(adapter.OutboundGroup); ok {
			return groupNow(sel) == config.OutboundTieredTag
		}
	}
	return false
}

func (e *tierEnv) Select(tag string) error {
	sel := e.tieredGroup()
	if sel == nil {
		return errors.New("no tiered group")
	}
	return tierSelect(sel, e.setup, tag)
}

func (e *tierEnv) Hold() error { return e.Select(config.OutboundTieredWaitTag) }

func (e *tierEnv) Picked() bool { return e.tieredSelected() }

// activeTag is the proxy the tiered group uses while it is the user's pick, else "".
func (e *tierEnv) activeTag() string {
	if !e.tieredSelected() {
		return ""
	}
	if sel := e.tieredGroup(); sel != nil {
		return groupNow(sel)
	}
	return ""
}

// activeResult is the time of the monitoring's last result of the proxy the tiered group uses, and
// whether it failed.
func (e *tierEnv) activeResult() (time.Time, bool) {
	sel := e.tieredGroup()
	ctx := static.Context()
	if sel == nil || ctx == nil {
		return time.Time{}, false
	}
	monitor := monitoring.Get(ctx)
	if monitor == nil {
		return time.Time{}, false
	}
	his := monitor.OutboundsHistory("")[groupNow(sel)]
	if his == nil || his.IsFromCache {
		return time.Time{}, false
	}
	return his.Time, his.Delay >= monitoring.TimeoutDelay
}

// Network is the device's default network: offline without one; its id is a hash of its type,
// name, gateways and Wi-Fi name, so the name never reaches a log or the store.
func (e *tierEnv) Network() tiered.Network {
	box := static.Box()
	if box == nil {
		return tiered.Network{}
	}
	nm := box.Network()
	iface := nm.DefaultNetworkInterface()
	if iface == nil {
		return tiered.Network{}
	}
	h := sha256.New()
	io.WriteString(h, strconv.Itoa(int(iface.Type))+"|"+iface.Name+"|")
	gateways := make([]string, 0, len(iface.Gateways))
	for _, gw := range iface.Gateways {
		gateways = append(gateways, gw.String())
	}
	slices.Sort(gateways)
	io.WriteString(h, strings.Join(gateways, ",")+"|"+nm.WIFIState().SSID)
	return tiered.Network{ID: hex.EncodeToString(h.Sum(nil)[:4]), Online: true}
}

// Check sends a request through the proxy tag: the first 64 KiB of the subscription's test file,
// or, without one, the URL test of the settings.
func (e *tierEnv) Check(ctx context.Context, tag string) tiered.CheckResult {
	box := static.Box()
	if box == nil {
		return tiered.CheckResult{Outcome: tiered.NoConnect}
	}
	proxy, ok := box.Outbound().Outbound(tag)
	if !ok {
		return tiered.CheckResult{Outcome: tiered.NoConnect}
	}
	out := boundedDialer{proxy}
	// a tunnel (AmneziaWG, WireGuard) reaches what its server lets its clients reach, which need not
	// be the server's own site: its check is the neutral one at once
	if e.setup.host == "" || e.setup.path == "" || tunnelEndpoint(proxy) {
		return neutralCheck(ctx, out, e.setup.testURL)
	}
	r, dialed := transferCheck(ctx, out, e.setup.host, e.setup.path)
	if r.Outcome == tiered.NoConnect && dialed {
		// the proxy connected, but the subscription's host did not answer through it: the
		// server's exit may not lead back to the server itself. Not the proxy's fault.
		e.Log("tiers: " + tag + ": the test path does not answer through it, a neutral check")
		return neutralCheck(ctx, out, e.setup.testURL)
	}
	return r
}

// boundedDialer dials through a proxy for a check, giving up at the end of the dial's context even
// when the proxy's dial does not: a gRPC proxy's dials wait for the one already under way
// (hiddify-sing-box transport/v2raygrpc Client.connect, under connAccess), and that one may wait for
// as long as an app's connection asked for it, while the server does not answer. A check is never
// held longer than its time; a connection that comes after that is closed.
type boundedDialer struct{ N.Dialer }

func (d boundedDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	type dialed struct {
		conn net.Conn
		err  error
	}
	done := make(chan dialed, 1)
	go func() {
		conn, err := d.Dialer.DialContext(ctx, network, destination)
		done <- dialed{conn, err}
	}()
	select {
	case r := <-done:
		return r.conn, r.err
	case <-ctx.Done():
		go func() {
			if r := <-done; r.conn != nil {
				r.conn.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

// tunnelEndpoint: an AmneziaWG or WireGuard endpoint (or the lazy stand-in of one).
func tunnelEndpoint(out adapter.Outbound) bool {
	switch out.Type() {
	case C.TypeAwg, C.TypeWireGuard:
		return true
	}
	return false
}

// neutralCheck is a check through the proxy that needs nothing of the subscription's server: 64 KiB
// from the speed test's host the app already uses (enough to see a freeze), else the URL test of the
// settings, which the monitoring makes anyway.
func neutralCheck(ctx context.Context, out N.Dialer, testURL string) tiered.CheckResult {
	if r, _ := transferCheck(ctx, out, neutralHost, neutralTransferPath); r.Outcome != tiered.NoConnect {
		return r
	}
	return urlTestCheck(ctx, out, testURL)
}

// neutralHost is the speed test's host (a test's own server in tests).
var neutralHost = speedTestHost

// neutralTransferPath asks the speed test's host for exactly tierCheckBytes.
var neutralTransferPath = "/__down?bytes=" + strconv.Itoa(tierCheckBytes)

func urlTestCheck(ctx context.Context, dialer N.Dialer, link string) tiered.CheckResult {
	if link == "" {
		link = "https://www.google.com/generate_204"
	}
	ctx, cancel := context.WithTimeout(ctx, tierCheckAnswer)
	defer cancel()
	delay, err := urltest.URLTest(ctx, link, dialer)
	if err != nil {
		return tiered.CheckResult{Outcome: tiered.NoConnect}
	}
	return tiered.CheckResult{Outcome: tiered.OK, Latency: time.Duration(delay) * time.Millisecond}
}

// tierRootCAs are the roots a check trusts inside the tunnel: the system's (nil), a test's own.
var tierRootCAs *x509.CertPool

// transferCheck downloads the first 64 KiB of path from host through dialer, over TLS inside the
// tunnel; see the limits above. A watchdog closes the connection when nothing came for its time (a
// tunnel's connection may not keep a deadline): the answer within tierCheckAnswer, then a byte of
// the body at least every tierCheckStall, all within tierCheckTotal.
func transferCheck(ctx context.Context, dialer N.Dialer, host, path string) (result tiered.CheckResult, dialed bool) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, tierCheckTotal)
	defer cancel()
	dialCtx, dialCancel := context.WithTimeout(ctx, tierCheckAnswer)
	conn, err := dialer.DialContext(dialCtx, N.NetworkTCP, M.ParseSocksaddrHostPort(host, 443))
	dialCancel()
	if err != nil {
		return tiered.CheckResult{Outcome: tiered.NoConnect}, false
	}
	defer conn.Close()
	var stalled atomic.Bool
	watchdog := time.AfterFunc(max(time.Until(start.Add(tierCheckAnswer)), 0), func() {
		stalled.Store(true)
		conn.Close()
	})
	defer watchdog.Stop()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	conn.SetDeadline(start.Add(tierCheckAnswer))
	tlsConn := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, RootCAs: tierRootCAs})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return tiered.CheckResult{Outcome: tiered.NoConnect}, true
	}
	request := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nRange: bytes=0-" +
		strconv.Itoa(tierCheckBytes-1) + "\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(tlsConn, request); err != nil {
		return tiered.CheckResult{Outcome: tiered.NoConnect}, true
	}
	reader := bufio.NewReaderSize(tlsConn, tierHeaderLine)
	headerRoom := tierHeaderBytes
	status, err := readHeaderLine(reader, &headerRoom)
	if err != nil || !strings.HasPrefix(status, "HTTP/1.") {
		return tiered.CheckResult{Outcome: tiered.NoConnect}, true
	}
	latency := time.Since(start)
	// the file itself or nothing: an error page, a redirect, a limit of requests is no transfer
	// (whatever its size); the neutral check decides then (see Check)
	if code := statusCode(status); code != 200 && code != 206 {
		return tiered.CheckResult{Outcome: tiered.NoConnect, Latency: latency}, true
	}
	watchdog.Reset(tierCheckStall)
	conn.SetDeadline(time.Time{})
	length := int64(-1)
	for {
		line, err := readHeaderLine(reader, &headerRoom)
		if errors.Is(err, errHeaderTooLong) {
			return tiered.CheckResult{Outcome: tiered.NoConnect, Latency: latency}, true
		}
		if err != nil {
			return tiered.CheckResult{Outcome: tiered.Stall, Latency: latency}, true
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if name, value, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(name), "content-length") {
			if n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil {
				length = n
			}
		}
	}
	want := int64(tierCheckBytes)
	if length >= 0 && length < want {
		want = length
	}
	buffer := make([]byte, 16<<10)
	var got int64
	bodyStart := time.Now()
	for got < want {
		conn.SetReadDeadline(minTime(time.Now().Add(tierCheckStall), start.Add(tierCheckTotal)))
		n, err := reader.Read(buffer)
		got += int64(n)
		if n > 0 {
			watchdog.Reset(tierCheckStall)
		}
		if err != nil {
			if errors.Is(err, io.EOF) && length < 0 {
				break // the whole body, of a length not given
			}
			if ctx.Err() != nil && !stalled.Load() && got >= freezeWindowEnd {
				// still coming when the time was up, past where a freeze stops a transfer: slow
				return tiered.CheckResult{Outcome: tiered.Slow, Latency: latency}, true
			}
			var netErr net.Error
			if got > 0 || stalled.Load() || errors.As(err, &netErr) && netErr.Timeout() {
				return tiered.CheckResult{Outcome: tiered.Stall, Latency: latency}, true
			}
			return tiered.CheckResult{Outcome: tiered.NoConnect, Latency: latency}, true
		}
	}
	if got < freezeWindowEnd {
		// an answer too short to show a freeze (an empty one, a page instead of the file) proves
		// nothing about the proxy: the neutral check decides
		return tiered.CheckResult{Outcome: tiered.NoConnect, Latency: latency}, true
	}
	result = tiered.CheckResult{Outcome: tiered.OK, Latency: latency}
	if took := time.Since(bodyStart); took > 0 && float64(got)/took.Seconds() < tierSlowBelow {
		result.Outcome = tiered.Slow
	}
	return result, true
}

// freezeWindowEnd: a transfer that got this far went past where the "16 KB" freeze stops one
// (14 to 25 KB); a check that works got at least this much.
const freezeWindowEnd = 32 << 10

// Limits of the answer's header: a line, and the status line with every header line.
const (
	tierHeaderLine  = 4 << 10
	tierHeaderBytes = 16 << 10
)

var errHeaderTooLong = errors.New("the answer's header is too long")

// readHeaderLine reads a line of the answer's header within what room is left of it.
func readHeaderLine(r *bufio.Reader, room *int) (string, error) {
	line, err := r.ReadSlice('\n')
	*room -= len(line)
	if errors.Is(err, bufio.ErrBufferFull) || *room < 0 {
		return "", errHeaderTooLong
	}
	if err != nil {
		return "", err
	}
	return string(line), nil
}

// statusCode is the code of an HTTP/1 status line, 0 when there is none.
func statusCode(status string) int {
	fields := strings.Fields(status)
	if len(fields) < 2 || len(fields[1]) != 3 {
		return 0
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0
	}
	return code
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// CheckPath runs DpiProbe to the subscription's host, the download only, one connection: TCP to
// the server freezing or cut makes every TCP proxy useless here.
func (e *tierEnv) CheckPath(ctx context.Context) tiered.PathVerdict {
	if e.setup.host == "" || e.setup.path == "" {
		return tiered.PathUnknown
	}
	response := DpiProbe(ctx, &DpiProbeRequest{Host: e.setup.host, Path: e.setup.path, Attempts: 1, TimeoutMs: 5000})
	return pathVerdictOf(response.GetOutcome())
}

// pathVerdictOf is what a probe's outcome says of the path: only a failure on the path itself
// blocks it; "busy" (another probe, or the budget spent waiting for a turn in the handshake gate),
// "budget" and errors say nothing.
func pathVerdictOf(outcome string) tiered.PathVerdict {
	switch outcome {
	case "ok":
		return tiered.PathOK
	case "freeze_16k", "stall", "reset", "tcp_timeout", "tcp_reset", "tls_timeout", "tls_reset":
		return tiered.PathBlocked
	}
	return tiered.PathUnknown
}

// tierStore keeps the controller's memory of networks in the core's settings database.
type tierStore struct{}

func (tierStore) Load() []byte {
	v, err := db.GetTable[hcommon.AppSettings]().Get("tieredMemory")
	if err != nil || v == nil {
		return nil
	}
	s, _ := v.Value.(string)
	return []byte(s)
}

func (tierStore) Save(data []byte) {
	db.GetTable[hcommon.AppSettings]().UpdateInsert(&hcommon.AppSettings{Id: "tieredMemory", Value: string(data)})
}

// tieredConnectivity: with the tiered group in use, a working ping of the proxy it selected is a
// working connection, whatever lowest's pings say.
func tieredConnectivity(histories map[string]*adapter.URLTestHistory) bool {
	env := &tierEnv{}
	if !env.tieredSelected() {
		return false
	}
	sel := env.tieredGroup()
	if sel == nil {
		return false
	}
	return pingAlive(historyDelay(histories[groupNow(sel)]))
}
