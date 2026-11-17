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
	r := transferCheck(context.Background(), dialer, "example.com", "/files/sample.bin")
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
	r := transferCheck(context.Background(), dialer, "example.com", "/files/sample.bin")
	if r.Outcome != tiered.Stall {
		t.Fatalf("outcome %s", r.Outcome)
	}
	if took := time.Since(start); took > tierCheckAnswer+tierCheckStall {
		t.Fatalf("took %s", took)
	}
}

func TestTierTransferCheckWithoutAnAnswer(t *testing.T) {
	// nothing listens
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := listener.Addr().String()
	listener.Close()
	if r := transferCheck(context.Background(), loopDialer{addr}, "example.com", "/x"); r.Outcome != tiered.NoConnect {
		t.Fatalf("outcome %s", r.Outcome)
	}
	// a certificate of another name: no connection to the subscription's host
	dialer := tierTestServer(t, func(w http.ResponseWriter, r *http.Request) {})
	if r := transferCheck(context.Background(), dialer, "other.example.net", "/x"); r.Outcome != tiered.NoConnect {
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
	r := transferCheck(ctx, dialer, "example.com", "/x")
	if r.Outcome.Works() || time.Since(start) > 2*time.Second {
		t.Fatalf("outcome %s after %s", r.Outcome, time.Since(start))
	}
}
