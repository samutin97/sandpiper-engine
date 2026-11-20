package hcore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/experimental/clashapi/trafficontrol"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"

	"github.com/hiddify/hiddify-core/v2/config"
	"github.com/hiddify/hiddify-core/v2/hcommon/constants"
	"github.com/hiddify/hiddify-core/v2/tiered"
)

// What the block journal (journal.go) is told while a config runs: from the start of the
// connectivity watcher (a start or a hot reload) to its stop, a look every journalPoll at the
// network and at the connections that closed, and every journalMinute the sums of the connections
// and the handshake gate's counts. The checks and the choices of the tiered controller are written
// as they happen (tiered_runtime.go).

const (
	journalPoll   = 5 * time.Second
	journalMinute = time.Minute
	// a connection through a proxy gets a line of its own when it got nothing back, or lived this
	// long, or brought this much; at most journalConnLines a minute, the others only in the sums
	journalLongConn  = time.Minute
	journalLargeConn = 1 << 20
	journalConnLines = 30
)

// pendingJournalProxies are the proxies of the config built last (buildRunningConfig).
var pendingJournalProxies atomic.Pointer[map[string]config.JournalProxy]

// journalProxies are the proxies of the config the journal watches now.
var journalProxies atomic.Pointer[map[string]config.JournalProxy]

// noteJournalProxies keeps the proxies of a config built to run.
func noteJournalProxies(options *option.Options) {
	proxies := config.JournalProxies(options)
	pendingJournalProxies.Store(&proxies)
}

// journalProxyOf is what the journal knows of the proxy tag in the config it watches.
func journalProxyOf(tag string) config.JournalProxy {
	if proxies := journalProxies.Load(); proxies != nil {
		return (*proxies)[tag]
	}
	return config.JournalProxy{}
}

var journalWatch struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// startJournalWatch starts the journal of the config that runs now; static.lock must be held.
func startJournalWatch() {
	stopJournalWatch()
	proxies := map[string]config.JournalProxy{}
	if pending := pendingJournalProxies.Load(); pending != nil {
		proxies = *pending
	}
	journalProxies.Store(&proxies)
	journalStart(proxies, runningTierPlan.Load())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	journalWatch.cancel, journalWatch.done = cancel, done
	go func() {
		defer close(done)
		defer config.DeferPanicToError("journal", func(err error) {
			Log(LogLevel_ERROR, LogType_CORE, "journal: ", err.Error())
		})
		runJournalWatch(ctx)
	}()
}

// stopJournalWatch ends it, with the sums of the last minute and the connections still open;
// static.lock must be held.
func stopJournalWatch() {
	if journalWatch.cancel == nil {
		return
	}
	journalWatch.cancel()
	select {
	case <-journalWatch.done:
	case <-time.After(3 * time.Second):
	}
	journalWatch.cancel, journalWatch.done = nil, nil
}

// journalExit is the way out to the internet the profile is on, "main" or "warp", as the app
// sent it: nothing for anything else (a profile without a pair, a value this core does not know).
func journalExit(options *config.HiddifyOptions) string {
	if options == nil {
		return ""
	}
	switch options.ExitChoice {
	case "main", "warp":
		return options.ExitChoice
	}
	return ""
}

// journalStart writes the start of a config: the core, the tiered group, each proxy.
func journalStart(proxies map[string]config.JournalProxy, setup *tierSetup) {
	candidates := map[string]tiered.Candidate{}
	if setup != nil && setup.plan != nil {
		for _, cand := range setup.plan.Candidates {
			candidates[cand.Tag] = cand
		}
	}
	gate := static.HiddifyOptions == nil || static.HiddifyOptions.HandshakeGate == nil || *static.HiddifyOptions.HandshakeGate
	head := []any{"core", constants.Version, "proxies", len(proxies), "tiered", setup != nil, "gate", gate}
	if exit := journalExit(static.HiddifyOptions); exit != "" {
		head = append(head, "exit", exit)
	}
	journalWrite("start", head...)
	for _, tag := range sortedKeys(proxies) {
		p := proxies[tag]
		fields := []any{"tag", tag, "srv", p.Server, "proto", p.Protocol, "tr", p.Transport, "sni", p.ServerName}
		if cand, ok := candidates[tag]; ok {
			fields = append(fields, "tier", cand.Tier+1, "mode", cand.Mode)
		}
		journalWrite("proxy", fields...)
	}
}

func runJournalWatch(ctx context.Context) {
	watch := &connWatch{since: time.Now()}
	var last journalNet
	poll := time.NewTicker(journalPoll)
	defer poll.Stop()
	minute := time.NewTicker(journalMinute)
	defer minute.Stop()
	look := func() {
		if !journalEnabled() {
			return
		}
		if now := currentJournalNet(); now != last {
			last = now
			// the operator is not known to the core (no platform call for it): not written
			journalWrite("net", "net", now.id, "kind", now.kind, "online", now.online)
		}
		if manager := static.TrafficManager(); manager != nil {
			watch.observe(manager.ClosedConnections(), journalProxies.Load())
		}
	}
	look()
	for {
		select {
		case <-ctx.Done():
			look()
			watch.flush()
			journalGate()
			journalOpen(journalProxies.Load())
			journalWrite("stop")
			return
		case <-poll.C:
			look()
		case <-minute.C:
			watch.flush()
			journalGate()
		}
	}
}

// journalNet is the default network as the journal tells it.
type journalNet struct {
	id     string // the tiered controller's network id (a hash, never the name)
	kind   string // wifi, cellular, ethernet, other; "" offline
	online bool
}

func currentJournalNet() journalNet {
	network, kind := defaultNetwork()
	return journalNet{id: network.ID, kind: kind, online: network.Online}
}

// defaultNetwork is the device's default network (see tierEnv.Network) and its kind.
func defaultNetwork() (tiered.Network, string) {
	box := static.Box()
	if box == nil {
		return tiered.Network{}, ""
	}
	nm := box.Network()
	iface := nm.DefaultNetworkInterface()
	if iface == nil {
		return tiered.Network{}, ""
	}
	h := sha256.New()
	io.WriteString(h, strconv.Itoa(int(iface.Type))+"|"+iface.Name+"|")
	gateways := make([]string, 0, len(iface.Gateways))
	for _, gw := range iface.Gateways {
		gateways = append(gateways, gw.String())
	}
	slices.Sort(gateways)
	io.WriteString(h, strings.Join(gateways, ",")+"|"+nm.WIFIState().SSID)
	return tiered.Network{ID: hex.EncodeToString(h.Sum(nil)[:4]), Online: true}, iface.Type.String()
}

// journalGate writes what the handshake gate did to each server since the last time.
func journalGate() {
	stats := tls.TakeHandshakeGateStats()
	if !journalEnabled() {
		return
	}
	for _, stat := range stats {
		fields := []any{"srv", stat.Server, "turns", stat.Turns, "hellos", stat.Hellos}
		if stat.Waited > 0 {
			fields = append(fields, "waited", stat.Waited, "wait_max_ms", stat.WaitMax, "wait_ms", stat.WaitTotal, "full", stat.Full, "window", stat.Window)
		}
		if stat.ConnectFailed > 0 {
			fields = append(fields, "connect_failed", stat.ConnectFailed)
		}
		journalWrite("gate", fields...)
	}
}

// journalOpen writes the connections through each proxy still open at the end of a config.
func journalOpen(proxies *map[string]config.JournalProxy) {
	manager := static.TrafficManager()
	if manager == nil || proxies == nil || !journalEnabled() {
		return
	}
	now := time.Now()
	sums := map[string]*connSums{}
	for _, md := range manager.Connections() {
		if _, ok := (*proxies)[md.Outbound]; !ok {
			continue
		}
		s := sums[md.Outbound]
		if s == nil {
			s = &connSums{}
			sums[md.Outbound] = s
		}
		s.add(now.Sub(md.CreatedAt), md.Upload.Load(), md.Download.Load())
	}
	for _, tag := range sortedKeys(sums) {
		s := sums[tag]
		journalWrite("open", "tag", tag, "srv", (*proxies)[tag].Server, "n", s.n, "noreply", s.noreply, "up", s.up, "down", s.down, "life_max_s", int64(s.lifeMax/time.Second))
	}
}

// connSums are the connections through one proxy in a minute.
type connSums struct {
	n, noreply, empty, skipped int
	up, down                   int64
	lifeMax                    time.Duration
}

func (s *connSums) add(life time.Duration, up, down int64) {
	s.n++
	s.up += up
	s.down += down
	s.lifeMax = max(s.lifeMax, life)
	switch {
	case up == 0 && down == 0:
		s.empty++
	case down == 0:
		s.noreply++
	}
}

// connWatch follows the connections that closed: each one once.
type connWatch struct {
	since time.Time         // the connections closed after it are new
	seen  map[[16]byte]bool // the ones closed at since, already counted
	sums  map[string]*connSums
	lines int
}

// connWhy is what a closed connection says: noreply (it sent, nothing came back), empty (nothing
// either way), long, large or ok.
func connWhy(life time.Duration, up, down int64) string {
	switch {
	case up == 0 && down == 0:
		return "empty"
	case down == 0:
		return "noreply"
	case life >= journalLongConn:
		return "long"
	case down >= journalLargeConn:
		return "large"
	}
	return "ok"
}

// observe counts the connections of closed (the oldest first) that closed since the last look and
// went through one of proxies. Only their proxy, network, times and counters are read: never their
// destination, domain, process or rule.
func (w *connWatch) observe(closed []*trafficontrol.TrackerMetadata, proxies *map[string]config.JournalProxy) {
	if proxies == nil {
		return
	}
	newest := w.since
	seen := map[[16]byte]bool{}
	for _, md := range closed {
		if md.ClosedAt.Before(w.since) || md.ClosedAt.Equal(w.since) && w.seen[[16]byte(md.ID)] {
			continue
		}
		if md.ClosedAt.After(newest) {
			newest, seen = md.ClosedAt, map[[16]byte]bool{}
		}
		if md.ClosedAt.Equal(newest) {
			seen[[16]byte(md.ID)] = true
		}
		proxy, ok := (*proxies)[md.Outbound]
		if !ok {
			continue // direct, blocked, DNS: not through a proxy
		}
		life := md.ClosedAt.Sub(md.CreatedAt)
		up, down := md.Upload.Load(), md.Download.Load()
		if w.sums == nil {
			w.sums = map[string]*connSums{}
		}
		s := w.sums[md.Outbound]
		if s == nil {
			s = &connSums{}
			w.sums[md.Outbound] = s
		}
		s.add(life, up, down)
		why := connWhy(life, up, down)
		if why == "ok" {
			continue
		}
		if w.lines >= journalConnLines {
			s.skipped++
			continue
		}
		w.lines++
		network := "tcp"
		if md.Metadata.Network == N.NetworkUDP {
			network = "udp"
		}
		journalWrite("conn", "tag", md.Outbound, "srv", proxy.Server, "tr", proxy.Transport, "net", network,
			"open", md.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"), "life_s", int64(life/time.Second),
			"up", up, "down", down, "why", why)
	}
	if newest.After(w.since) {
		w.since, w.seen = newest, seen
	} else {
		for id := range seen {
			if w.seen == nil {
				w.seen = map[[16]byte]bool{}
			}
			w.seen[id] = true
		}
	}
}

// flush writes the sums of the minute, a line a proxy, and starts them again.
func (w *connWatch) flush() {
	proxies := journalProxies.Load()
	for _, tag := range sortedKeys(w.sums) {
		s := w.sums[tag]
		server := ""
		if proxies != nil {
			server = (*proxies)[tag].Server
		}
		fields := []any{"tag", tag, "srv", server, "n", s.n, "noreply", s.noreply, "empty", s.empty, "up", s.up, "down", s.down, "life_max_s", int64(s.lifeMax / time.Second)}
		if s.skipped > 0 {
			fields = append(fields, "not_shown", s.skipped)
		}
		journalWrite("conns", fields...)
	}
	w.sums, w.lines = nil, 0
}

// journalNote writes a decision of the tiered controller.
func journalNote(n tiered.Note) {
	fields := []any{"tag", n.Tag, "srv", n.Server, "mode", n.Mode, "from", n.From, "why", n.Why}
	if n.Tier > 0 {
		fields = append(fields, "tier", n.Tier)
	}
	if n.Wait > 0 {
		fields = append(fields, "wait_s", int64(n.Wait/time.Second))
	}
	journalWrite(n.Kind, fields...)
}

// checkTrace follows a check of the proxy tag through its kinds (transfer, neutral, urltest): each
// writes a check line.
type checkTrace struct {
	tag  string
	kind string
}

type checkTraceKey struct{}

func withCheckTrace(ctx context.Context, trace *checkTrace) context.Context {
	return context.WithValue(ctx, checkTraceKey{}, trace)
}

func checkTraceOf(ctx context.Context) *checkTrace {
	trace, _ := ctx.Value(checkTraceKey{}).(*checkTrace)
	return trace
}

// setKind names the kind of the check that follows, when ctx has a trace.
func setCheckKind(ctx context.Context, kind string) {
	if trace := checkTraceOf(ctx); trace != nil {
		trace.kind = kind
	}
}

// outerStage is where a dial through a proxy failed, by its trace: tcp (the TCP connect to the
// server), handshake (connected, the handshake did not end), connect (no TCP connect of its own
// seen: a multiplexed connection, QUIC, a tunnel).
func outerStage(info tls.DialTraceInfo) string {
	switch {
	case info.Connects == 0:
		return "connect"
	case !info.Connected:
		return "tcp"
	}
	return "handshake"
}

// record writes one check: the stage it reached (connect for the dial, refined by the dial's
// trace; tls, http, body inside the tunnel), what it found, how long it took and what came.
func (t *checkTrace) record(result tiered.CheckResult, stage string, got int64, code int, failure error, dial *tls.DialTrace, took time.Duration) {
	var info tls.DialTraceInfo
	if dial != nil {
		info = dial.Info()
	}
	if stage == "connect" {
		stage = outerStage(info)
	}
	proxy := journalProxyOf(t.tag)
	fields := []any{"tag", t.tag, "srv", proxy.Server, "tr", proxy.Transport, "kind", t.kind, "stage", stage,
		"out", result.Outcome.String(), "ms", took}
	if result.Latency > 0 {
		fields = append(fields, "first_ms", result.Latency)
	}
	if got > 0 {
		fields = append(fields, "rx", got)
	}
	if code > 0 {
		fields = append(fields, "code", code)
	}
	if !result.Outcome.Works() {
		fields = append(fields, "err", errClass(failure))
	}
	if info.Waited > 0 {
		fields = append(fields, "gate_ms", info.Waited)
	}
	if info.Connected {
		fields = append(fields, "tcp_ms", info.Connect)
	}
	journalWrite("check", fields...)
}

// journalPathCheck writes a check of the path to the server of the proxy tag: nil request, none
// made.
func journalPathCheck(tag string, request *DpiProbeRequest, response *DpiProbeResponse, verdict tiered.PathVerdict) {
	proxy := journalProxyOf(tag)
	if request == nil {
		journalWrite("path", "tag", tag, "srv", proxy.Server, "out", "none", "verdict", "unknown")
		return
	}
	var stages []string
	for _, st := range response.GetStages() {
		stage := st.GetName() + "=" + st.GetOutcome() + "/" + strconv.FormatInt(st.GetMillis(), 10) + "ms"
		if st.GetBytes() > 0 {
			stage += "/" + strconv.FormatInt(st.GetBytes(), 10) + "B"
		}
		stages = append(stages, stage)
	}
	journalWrite("path", "tag", tag, "srv", proxy.Server, "sni", request.GetServerName(), "out", response.GetOutcome(),
		"verdict", [...]string{"unknown", "ok", "blocked"}[verdict], "stages", strings.Join(stages, ";"))
}
