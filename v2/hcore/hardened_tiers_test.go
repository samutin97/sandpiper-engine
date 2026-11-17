package hcore

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hiddify/hiddify-core/v2/tiered"
	M "github.com/sagernet/sing/common/metadata"
)

// The check of a proxy, against a local HTTPS server standing for the subscription's host through
// the proxy: no engine, no network beyond 127.0.0.1, no system proxy touched.

type loopDialer struct{ addr string }

func (d loopDialer) DialContext(ctx context.Context, network string, _ M.Socksaddr) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", d.addr)
}

func (d loopDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

func tierTestServer(t *testing.T, handler http.HandlerFunc) loopDialer {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	tierRootCAs = pool
	t.Cleanup(func() { tierRootCAs = nil })
	return loopDialer{strings.TrimPrefix(server.URL, "https://")}
}

func TestTierTransferCheckGetsTheData(t *testing.T) {
	var gotRange string
	dialer := tierTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotRange = r.Header.Get("Range")
		w.Header().Set("Content-Length", "65536")
		w.WriteHeader(http.StatusPartialContent)
		w.Write(make([]byte, 65536))
	})
	r, _ := transferCheck(context.Background(), dialer, "example.com", "/files/sample.bin")
	if r.Outcome != tiered.OK || gotRange != "bytes=0-65535" {
		t.Fatalf("outcome %s, range %q", r.Outcome, gotRange)
	}
}

func TestTierTransferCheckSeesAFreeze(t *testing.T) {
	dialer := tierTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "65536")
		w.WriteHeader(http.StatusPartialContent)
		w.Write(make([]byte, 18<<10)) // about 18 KB, then nothing, the connection open
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(15 * time.Second):
		}
	})
	start := time.Now()
	r, _ := transferCheck(context.Background(), dialer, "example.com", "/files/sample.bin")
	if r.Outcome != tiered.Stall {
		t.Fatalf("outcome %s", r.Outcome)
	}
	if took := time.Since(start); took > tierCheckAnswer+tierCheckStall {
		t.Fatalf("took %s", took)
	}
}

// a tunnel's connection that keeps no deadline: the watchdog still ends a frozen transfer
type noDeadlineConn struct{ net.Conn }

func (noDeadlineConn) SetDeadline(time.Time) error      { return nil }
func (noDeadlineConn) SetReadDeadline(time.Time) error  { return nil }
func (noDeadlineConn) SetWriteDeadline(time.Time) error { return nil }

type noDeadlineDialer struct{ loopDialer }

func (d noDeadlineDialer) DialContext(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
	conn, err := d.loopDialer.DialContext(ctx, network, dest)
	if err != nil {
		return nil, err
	}
	return noDeadlineConn{conn}, nil
}

func freezingHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Length", "65536")
	w.WriteHeader(http.StatusPartialContent)
	w.Write(make([]byte, 18<<10))
	w.(http.Flusher).Flush()
	select {
	case <-r.Context().Done():
	case <-time.After(15 * time.Second):
	}
}

func TestTierTransferCheckFreezeWithoutDeadlines(t *testing.T) {
	dialer := tierTestServer(t, freezingHandler)
	start := time.Now()
	r, _ := transferCheck(context.Background(), noDeadlineDialer{dialer}, "example.com", "/files/sample.bin")
	if r.Outcome != tiered.Stall || time.Since(start) > tierCheckAnswer+tierCheckStall {
		t.Fatalf("outcome %s after %s", r.Outcome, time.Since(start))
	}
}

func TestTierTransferCheckSlowButFlowing(t *testing.T) {
	dialer := tierTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "65536")
		w.WriteHeader(http.StatusPartialContent)
		for sent := 0; sent < 65536; sent += 2048 {
			if _, err := w.Write(make([]byte, 2048)); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			time.Sleep(250 * time.Millisecond) // 8 KB/s
		}
	})
	if r, _ := transferCheck(context.Background(), dialer, "example.com", "/files/sample.bin"); r.Outcome != tiered.Slow {
		t.Fatalf("outcome %s", r.Outcome)
	}
}

func TestTierTransferCheckWithoutAnAnswer(t *testing.T) {
	// nothing listens
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := listener.Addr().String()
	listener.Close()
	if r, _ := transferCheck(context.Background(), loopDialer{addr}, "example.com", "/x"); r.Outcome != tiered.NoConnect {
		t.Fatalf("outcome %s", r.Outcome)
	}
	// a certificate of another name: no connection to the subscription's host
	dialer := tierTestServer(t, func(w http.ResponseWriter, r *http.Request) {})
	if r, _ := transferCheck(context.Background(), dialer, "other.example.net", "/x"); r.Outcome != tiered.NoConnect {
		t.Fatalf("wrong certificate: %s", r.Outcome)
	}
}

func TestTierTransferCheckEndsWithItsContext(t *testing.T) {
	dialer := tierTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	r, _ := transferCheck(ctx, dialer, "example.com", "/x")
	if r.Outcome.Works() || time.Since(start) > 2*time.Second {
		t.Fatalf("outcome %s after %s", r.Outcome, time.Since(start))
	}
}

// SP5-03: the apps' connections through the proxy in use get nothing back while it brings no byte:
// an early check, at most once a minute; quiet without connections, or with data coming.
func TestTierPassiveWatch(t *testing.T) {
	start := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	failedConns := func(now time.Time, n int) []connView {
		var c []connView
		for i := 0; i < n; i++ {
			c = append(c, connView{tcp: true, outbound: "2 x", created: now.Add(-2 * time.Second), closed: now.Add(-time.Second), up: 500})
		}
		return c
	}
	var p passiveWatch
	fired := time.Duration(-1)
	for s := 0; s <= 45; s += 3 {
		now := start.Add(time.Duration(s) * time.Second)
		// TCP cut at 0 s: the counter stays at 1 MB, the apps' connections close without a byte
		if p.observe(now, "2 x", 1<<20, failedConns(now, 4)) && fired < 0 {
			fired = time.Duration(s) * time.Second
		}
	}
	if fired < passiveQuiet || fired > 20*time.Second {
		t.Fatalf("fired at %s", fired)
	}
	// once a minute at most
	if p.observe(start.Add(48*time.Second), "2 x", 1<<20, failedConns(start.Add(48*time.Second), 4)) {
		t.Fatal("fired again within a minute")
	}

	// data still comes: no alarm, whatever the failed connections
	var q passiveWatch
	for s := 0; s <= 60; s += 3 {
		now := start.Add(time.Duration(s) * time.Second)
		if q.observe(now, "2 x", int64(s)*1000, failedConns(now, 5)) {
			t.Fatalf("alarm while data comes, at %d s", s)
		}
	}
	// no traffic at all (idle): no alarm
	var r passiveWatch
	for s := 0; s <= 60; s += 3 {
		if r.observe(start.Add(time.Duration(s)*time.Second), "2 x", 1<<20, nil) {
			t.Fatal("alarm while idle")
		}
	}
	// connections of another proxy, UDP ones, and open ones that sent nothing do not count
	var u passiveWatch
	for s := 0; s <= 60; s += 3 {
		now := start.Add(time.Duration(s) * time.Second)
		conns := []connView{
			{tcp: true, outbound: "9 y", closed: now, up: 100},
			{tcp: false, outbound: "2 x", closed: now, up: 100},
			{tcp: true, outbound: "2 x", created: now.Add(-time.Minute)},
		}
		if u.observe(now, "2 x", 7, conns) {
			t.Fatal("alarm from connections that do not count")
		}
	}
	// stuck open connections (a freeze) count
	var f passiveWatch
	hit := false
	for s := 0; s <= 30; s += 3 {
		now := start.Add(time.Duration(s) * time.Second)
		conns := []connView{}
		for i := 0; i < 3; i++ {
			conns = append(conns, connView{tcp: true, outbound: "2 x", created: start.Add(-5 * time.Second), up: 700})
		}
		hit = hit || f.observe(now, "2 x", 9, conns)
	}
	if !hit {
		t.Fatal("no alarm for stuck connections")
	}
}

// SP5-04: a proxy that connects while the subscription's host does not answer through it (an
// AmneziaWG server keeps its clients off its own address) is judged by the neutral check.
func TestTierCheckFallsBackToANeutralTarget(t *testing.T) {
	// the "subscription host" is a port nothing listens on, behind a dialer that connects
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := listener.Addr().String()
	listener.Close()
	r, dialed := transferCheck(context.Background(), loopDialer{dead}, "example.com", "/x")
	if r.Outcome != tiered.NoConnect || dialed {
		t.Fatalf("a refused dial: %s, dialed %v", r.Outcome, dialed)
	}
	// connected, but the host's TLS fails: dialed, so the neutral check decides
	dialer := tierTestServer(t, func(w http.ResponseWriter, r *http.Request) {})
	if r, dialed := transferCheck(context.Background(), dialer, "other.example.net", "/x"); r.Outcome != tiered.NoConnect || !dialed {
		t.Fatalf("connected, host failed: %s, dialed %v", r.Outcome, dialed)
	}
	// the neutral check downloads from a host that answers: it works
	neutral := tierTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.RawQuery, "bytes=") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", "65536")
		w.Write(make([]byte, 65536))
	})
	saved := speedTestHostForTests(t, "example.com")
	defer saved()
	if r := neutralCheck(context.Background(), neutral, ""); r.Outcome != tiered.OK {
		t.Fatalf("neutral check: %s", r.Outcome)
	}
}

func speedTestHostForTests(t *testing.T, host string) func() {
	t.Helper()
	saved := neutralHost
	neutralHost = host
	return func() { neutralHost = saved }
}
