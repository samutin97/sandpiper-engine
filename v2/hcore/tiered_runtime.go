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

// pendingTierPlan is the plan of the config built last (buildRunningConfig); the runtime started
// with the connectivity watcher takes it.
var pendingTierPlan atomic.Pointer[tierSetup]

type tierSetup struct {
	plan      *tiered.Plan
	host      string
	path      string
	testURL   string
	configTag string
}

// noteTierPlan keeps the tiered plan of a built config, nil without a tiered group.
func noteTierPlan(hopt *config.HiddifyOptions, opts *option.Options) {
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
	pendingTierPlan.Store(setup)
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
	setup := pendingTierPlan.Load()
	ctx := static.Context()
	if setup == nil || ctx == nil || static.Box() == nil {
		return
	}
	box := static.Box()
	sel, ok := box.Outbound().Outbound(config.OutboundTieredTag)
	if !ok {
		return
	}
	if _, isSelector := sel.(*group.Selector); !isSelector {
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	env := &tierEnv{setup: setup}
	ctl := tiered.New(env, setup.plan, tierStore{})
	ctl.OnChange = notifyTierState
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

// tierConfirm passes the user's agreement to a last-resort proxy to the controller.
func tierConfirm(tag string) bool {
	tierRun.Lock()
	ctl, confirm := tierRun.ctl, tierRun.confirm
	tierRun.Unlock()
	if ctl == nil || ctl.State().Confirm != tag {
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
	ctl.SetEnabled(ctx, env.tieredSelected())
	lastNetwork := env.Network()
	lastResult, _ := env.activeResult() // a failure before this run was looked at by its start
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
		case tag := <-confirm:
			ctl.Confirm(ctx, tag)
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
	if strings.HasPrefix(message, "tiers: using") || strings.Contains(message, "TCP to the server") || strings.Contains(message, "last resort") || strings.Contains(message, "no proxy") {
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
	if !sel.SelectOutbound(tag) {
		return errors.New("not in the tiered group: " + tag)
	}
	return nil
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
	out, ok := box.Outbound().Outbound(tag)
	if !ok {
		return tiered.CheckResult{Outcome: tiered.NoConnect}
	}
	if e.setup.host == "" || e.setup.path == "" {
		return urlTestCheck(ctx, out, e.setup.testURL)
	}
	return transferCheck(ctx, out, e.setup.host, e.setup.path)
}

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
func transferCheck(ctx context.Context, dialer N.Dialer, host, path string) tiered.CheckResult {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, tierCheckTotal)
	defer cancel()
	dialCtx, dialCancel := context.WithTimeout(ctx, tierCheckAnswer)
	conn, err := dialer.DialContext(dialCtx, N.NetworkTCP, M.ParseSocksaddrHostPort(host, 443))
	dialCancel()
	if err != nil {
		return tiered.CheckResult{Outcome: tiered.NoConnect}
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
		return tiered.CheckResult{Outcome: tiered.NoConnect}
	}
	request := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nRange: bytes=0-" +
		strconv.Itoa(tierCheckBytes-1) + "\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(tlsConn, request); err != nil {
		return tiered.CheckResult{Outcome: tiered.NoConnect}
	}
	reader := bufio.NewReader(tlsConn)
	status, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(status, "HTTP/1.") {
		return tiered.CheckResult{Outcome: tiered.NoConnect}
	}
	latency := time.Since(start)
	watchdog.Reset(tierCheckStall)
	conn.SetDeadline(time.Time{})
	length := int64(-1)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return tiered.CheckResult{Outcome: tiered.Stall, Latency: latency}
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
				return tiered.CheckResult{Outcome: tiered.Slow, Latency: latency}
			}
			var netErr net.Error
			if got > 0 || stalled.Load() || errors.As(err, &netErr) && netErr.Timeout() {
				return tiered.CheckResult{Outcome: tiered.Stall, Latency: latency}
			}
			return tiered.CheckResult{Outcome: tiered.NoConnect, Latency: latency}
		}
	}
	result := tiered.CheckResult{Outcome: tiered.OK, Latency: latency}
	if took := time.Since(bodyStart); got >= freezeWindowEnd && took > 0 && float64(got)/took.Seconds() < tierSlowBelow {
		result.Outcome = tiered.Slow
	}
	return result
}

// freezeWindowEnd: a transfer that got this far went past where the "16 KB" freeze stops one
// (14 to 25 KB).
const freezeWindowEnd = 32 << 10

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
	switch response.GetOutcome() {
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
