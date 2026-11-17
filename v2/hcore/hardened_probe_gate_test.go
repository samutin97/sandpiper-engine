package hcore

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

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
