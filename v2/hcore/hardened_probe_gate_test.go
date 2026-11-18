package hcore

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/hiddify/hiddify-core/v2/config"
	"github.com/hiddify/hiddify-core/v2/tiered"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// The check of the path and the handshake gate: a queue of the core's own handshakes to the server
// (one at a time, here) is no sign of the path. No engine: a local TLS server, the gate of the
// process set for the test.

func gateForTest(t *testing.T) {
	t.Helper()
	tls.SetHandshakeGate(&option.HandshakeGateOptions{Enabled: true, MaxInflight: 1, MinGap: badoption.Duration(100 * time.Millisecond)})
	t.Cleanup(func() { tls.SetHandshakeGate(nil) })
}

// holdTheGate starts a handshake with a server on 127.0.0.1 that never answers: it keeps the
// server's only turn for d.
func holdTheGate(t *testing.T, d time.Duration) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { conn.Close() })
		}
	}()
	config, err := tls.NewClient(context.Background(), log.NewNOPFactory().NewLogger("hold"), "example.com",
		option.OutboundTLSOptions{Enabled: true, ServerName: "example.com", Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	go tls.ClientHandshake(ctx, conn, config)
	time.Sleep(300 * time.Millisecond) // it has the turn now
}

func fileServer(t *testing.T) (string, uint32) {
	return probeServer(t, func(w http.ResponseWriter, r *http.Request) { w.Write(make([]byte, 128<<10)) })
}

// The queue is longer than a stage's timeout but within the probe's budget: the probe waits for its
// turn and finds the path working (before, the wait counted in the TLS stage: "tls_timeout", taken
// for TCP to the server cut).
func TestDpiProbeWaitsForTheGateOutsideItsStages(t *testing.T) {
	host, port := fileServer(t)
	gateForTest(t)
	holdTheGate(t, 3*time.Second)
	start := time.Now()
	r := DpiProbe(context.Background(), &DpiProbeRequest{Host: host, Port: port, ServerName: "example.com", Insecure: true, Attempts: 1, TimeoutMs: 2000})
	if r.Outcome != "ok" || pathVerdictOf(r.Outcome) != tiered.PathOK {
		t.Fatalf("%s after %s: %v", r.Outcome, time.Since(start), r.Stages)
	}
	if took := time.Since(start); took < 2*time.Second {
		t.Fatalf("it did not wait for the turn: %s", took)
	}
}

// The queue outlasts the probe (the caller's time ends in it): "busy", no verdict of the path, never
// "blocked"; no packet went to the server.
func TestDpiProbeOutOfTimeInTheGateIsNoVerdict(t *testing.T) {
	host, port := fileServer(t)
	gateForTest(t)
	holdTheGate(t, 20*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	start := time.Now()
	r := DpiProbe(ctx, &DpiProbeRequest{Host: host, Port: port, ServerName: "example.com", Insecure: true, Attempts: 1, TimeoutMs: 2000})
	if r.Outcome != "busy" || pathVerdictOf(r.Outcome) != tiered.PathUnknown || time.Since(start) > 4*time.Second {
		t.Fatalf("%s after %s: %v", r.Outcome, time.Since(start), r.Stages)
	}
	for _, outcome := range []string{"busy", "budget", "error", ""} {
		if pathVerdictOf(outcome) != tiered.PathUnknown {
			t.Fatalf("%q", outcome)
		}
	}
	for _, outcome := range []string{"tls_timeout", "tcp_timeout", "tcp_reset", "freeze_16k", "stall"} {
		if pathVerdictOf(outcome) != tiered.PathBlocked {
			t.Fatalf("%q", outcome)
		}
	}
}

// With a proxy of the profile on the subscription's host, the check of the path dials its address,
// with the host as the server name; without one, the name. The probe sends the name in the TLS
// handshake and in the Host header whatever address it dials (and checks the certificate by it).
func TestDpiProbeDialsTheProxyAddressWithTheName(t *testing.T) {
	byAddress := (&tierSetup{host: "sub.example.net", path: "/files/sample.bin", probeAddress: "192.0.2.10"}).pathRequest()
	if byAddress.Host != "192.0.2.10" || byAddress.ServerName != "sub.example.net" || byAddress.Insecure || byAddress.Path != "/files/sample.bin" {
		t.Fatalf("%+v", byAddress)
	}
	byName := (&tierSetup{host: "sub.example.net", path: "/files/sample.bin"}).pathRequest()
	if byName.Host != "sub.example.net" || byName.ServerName != "sub.example.net" {
		t.Fatalf("%+v", byName)
	}
	var sni, hostHeader string
	host, port := probeServer(t, func(w http.ResponseWriter, r *http.Request) {
		sni, hostHeader = r.TLS.ServerName, r.Host
		w.Write(make([]byte, 128<<10))
	})
	r := DpiProbe(context.Background(), &DpiProbeRequest{Host: host, Port: port, ServerName: "example.com", Insecure: true, TimeoutMs: 3000})
	if r.Outcome != "ok" || sni != "example.com" || hostHeader != "example.com" {
		t.Fatalf("%s: SNI %q, Host %q", r.Outcome, sni, hostHeader)
	}
}

// 5.9.8-sp.11: the check of the path for a proxy goes to its own server, with a name in TLS that
// server answers to: the second server of a subscription is checked by its address and name, not by
// the subscription's. A server without such a name is not checked; a proxy whose server is not known
// checks the subscription's host, as before.
func TestDpiProbePathOfEachServer(t *testing.T) {
	setup := &tierSetup{host: "sub.example.net", path: "/files/sample.bin", probeAddress: "192.0.2.10",
		pathTargets: map[string]config.TierPathTarget{
			"2 gRPC":       {Dial: "192.0.2.10", ServerName: "vpn.example.net"},
			"12 gRPC":      {Dial: "198.51.100.20", ServerName: "vpn2.example.com"},
			"17 Reality C": {Dial: "203.0.113.30"},
		}}
	for tag, want := range map[string]*DpiProbeRequest{
		"2 gRPC":       {Host: "192.0.2.10", ServerName: "vpn.example.net"},
		"12 gRPC":      {Host: "198.51.100.20", ServerName: "vpn2.example.com"},
		"17 Reality C": nil,
		"8 unknown":    {Host: "192.0.2.10", ServerName: "sub.example.net"},
	} {
		got := setup.pathRequestFor(tag)
		if want == nil {
			if got != nil {
				t.Fatalf("%s: %+v, want no check", tag, got)
			}
			continue
		}
		if got == nil || got.Host != want.Host || got.ServerName != want.ServerName || got.Path != "/files/sample.bin" || got.Insecure {
			t.Fatalf("%s: %+v, want %+v", tag, got, want)
		}
	}
	if (&tierSetup{host: "sub.example.net"}).pathRequestFor("2 gRPC") != nil {
		t.Fatal("a check without the probe path")
	}
	if (&tierEnv{setup: &tierSetup{}}).CheckPath(context.Background(), "2 gRPC") != tiered.PathUnknown {
		t.Fatal("a verdict without a check")
	}
}
