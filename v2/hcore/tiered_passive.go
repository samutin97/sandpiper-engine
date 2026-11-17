package hcore

import (
	"time"

	N "github.com/sagernet/sing/common/network"
)

// Between two data checks (every 10 minutes) a proxy in use that stopped carrying data is seen in
// the apps' own connections through it: they get nothing back. TCP to the server cut: every
// connection through the proxy closes without a byte from it; frozen: they hang, then the apps give
// up. When that is so for several connections and the proxy brought no byte for a while, the
// controller checks the proxy at once (ActiveFailed), at most once a minute. Nothing is sent for
// this: it reads the counters of the connections the core already keeps.

const (
	passiveWindow = 30 * time.Second // connections that closed this recently count
	passiveQuiet  = 15 * time.Second // the proxy brought no byte for this long
	passiveFailed = 3                // connections through it without a byte back
	passiveStuck  = 10 * time.Second // an open connection this old that sent and got nothing back counts
	passiveEvery  = time.Minute      // at most one early check this often
)

// connView is what the watch reads of a connection.
type connView struct {
	tcp             bool
	outbound        string // the proxy it went through (the leaf)
	created, closed time.Time
	up, down        int64
}

type passiveSample struct {
	at   time.Time
	tag  string
	down int64
}

// passiveWatch decides, from samples taken every few seconds, when the proxy in use deserves an
// early check.
type passiveWatch struct {
	samples   []passiveSample
	lastAlarm time.Time
}

// observe takes a sample: active is the proxy in use, down the bytes it brought so far, conns the
// open and recently closed connections. True when the proxy is to be checked now.
func (p *passiveWatch) observe(now time.Time, active string, down int64, conns []connView) bool {
	if active == "" {
		p.samples = nil
		return false
	}
	if n := len(p.samples); n > 0 && p.samples[n-1].tag != active {
		p.samples = nil // another proxy: start again
	}
	p.samples = append(p.samples, passiveSample{at: now, tag: active, down: down})
	for len(p.samples) > 1 && now.Sub(p.samples[1].at) >= passiveQuiet {
		p.samples = p.samples[1:] // keep one sample at least passiveQuiet old
	}
	first := p.samples[0]
	if now.Sub(first.at) < passiveQuiet || first.down != down {
		return false // not quiet for long enough, or it brought something meanwhile
	}
	failed := 0
	for _, c := range conns {
		if !c.tcp || c.outbound != active || c.down > 0 {
			continue
		}
		switch {
		case !c.closed.IsZero() && now.Sub(c.closed) <= passiveWindow:
			failed++
		case c.closed.IsZero() && c.up > 0 && now.Sub(c.created) >= passiveStuck:
			failed++
		}
	}
	if failed < passiveFailed || now.Sub(p.lastAlarm) < passiveEvery {
		return false
	}
	p.lastAlarm = now
	return true
}

// connViews are the open connections and those closed in the last passiveWindow, from the core's
// own traffic counters; nil when it keeps none.
func connViews(now time.Time) []connView {
	manager := static.TrafficManager()
	if manager == nil {
		return nil
	}
	var views []connView
	for _, md := range manager.Connections() {
		views = append(views, connView{
			tcp: md.Metadata.Network == N.NetworkTCP, outbound: md.Outbound, created: md.CreatedAt,
			up: md.Upload.Load(), down: md.Download.Load(),
		})
	}
	closed := manager.ClosedConnections()
	for i := len(closed) - 1; i >= 0; i-- {
		md := closed[i]
		if now.Sub(md.ClosedAt) > passiveWindow {
			break // the oldest are first
		}
		views = append(views, connView{
			tcp: md.Metadata.Network == N.NetworkTCP, outbound: md.Outbound, created: md.CreatedAt,
			closed: md.ClosedAt, up: md.Upload.Load(), down: md.Download.Load(),
		})
	}
	return views
}

// outboundDown is the bytes the proxy tag brought so far in this run.
func outboundDown(tag string) int64 {
	manager := static.TrafficManager()
	if manager == nil {
		return 0
	}
	_, down := manager.OutboundUsage(tag)
	return down
}
