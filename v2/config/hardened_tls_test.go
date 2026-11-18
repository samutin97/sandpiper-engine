package config

import (
	"context"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func vlessTLSOf(t *testing.T, settings, profile string) map[string]*option.OutboundTLSOptions {
	t.Helper()
	ctx := libbox.BaseContext(nil)
	parsed, err := ParseConfigBytes(ctx, &ReadOptions{Content: profile}, false, DefaultHiddifyOptions(), false)
	if err != nil {
		t.Fatal(err)
	}
	options, err := BuildConfig(ctx, chainTestOptions(t, settings), &ReadOptions{Content: string(parsed)})
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]*option.OutboundTLSOptions{}
	for _, out := range options.Outbounds {
		if v, ok := out.Options.(*option.VLESSOutboundOptions); ok {
			result[out.Tag[:1]] = v.TLS
		}
	}
	return result
}

const fingerprintProfile = `vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls&sni=example.com&type=ws&path=/a#n
vless://00000000-0000-4000-8000-000000000002@192.0.2.2:443?security=tls&sni=example.com&fp=chrome&type=grpc&serviceName=s#c
vless://00000000-0000-4000-8000-000000000003@192.0.2.3:443?security=reality&sni=example.com&pbk=YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE&sid=01#r`

func TestDefaultFingerprintIsFirefox(t *testing.T) {
	tls := vlessTLSOf(t, `{"use-system-tls-engine":false}`, fingerprintProfile)
	if tls["n"].UTLS == nil || tls["n"].UTLS.Fingerprint != "firefox" || tls["n"].UTLS.KeyShare != "" {
		t.Fatalf("no fingerprint in the link: %+v", tls["n"].UTLS)
	}
	if tls["c"].UTLS.Fingerprint != "chrome" {
		t.Fatalf("the link's chrome: %+v", tls["c"].UTLS)
	}
	if tls["r"].Reality == nil || tls["r"].Reality.KeyShare != "" {
		t.Fatalf("reality key share changed: %+v", tls["r"].Reality)
	}
	classical := vlessTLSOf(t, `{"use-system-tls-engine":false,"tls-key-share":"classical"}`, fingerprintProfile)
	if classical["n"].UTLS.KeyShare != "classical" || classical["c"].UTLS.KeyShare != "classical" {
		t.Fatalf("classical: %+v %+v", classical["n"].UTLS, classical["c"].UTLS)
	}
	if classical["r"].UTLS != nil && classical["r"].UTLS.KeyShare != "" || classical["r"].Reality.KeyShare != "" {
		t.Fatal("classical reached REALITY")
	}
}

func TestHandshakeGateOnByDefault(t *testing.T) {
	gate := buildPerApp(t, `{}`).Experimental.HandshakeGate
	if gate == nil || !gate.Enabled {
		t.Fatal("no handshake gate by default")
	}
	// ST4-03: one at a time, a gap drawn in 0.7-1.1 s, at most 4 in 5 s (a window of 5.5 s: E9-01);
	// the hold of a handshake the gate does not see (naive) set here, not left to the fork
	if gate.MaxInflight != 1 || time.Duration(gate.MinGap) != 700*time.Millisecond || time.Duration(gate.MaxGap) != 1100*time.Millisecond ||
		time.Duration(gate.Window) != 5500*time.Millisecond || gate.WindowMax != 4 || time.Duration(gate.UnseenHold) != time.Second {
		t.Fatalf("default %+v", gate)
	}
	// the Windows system proxy's check before it puts the previous one back, set here too
	if proxy := buildPerApp(t, `{}`).Experimental.SystemProxy; proxy == nil || time.Duration(proxy.RestoreCheckTimeout) != time.Second {
		t.Fatalf("system proxy %+v", proxy)
	}
	tuned := buildPerApp(t, `{"handshake-gate-max":2,"handshake-gate-gap-ms":600}`).Experimental.HandshakeGate
	if tuned.MaxInflight != 2 || time.Duration(tuned.MinGap) != 600*time.Millisecond || time.Duration(tuned.MaxGap) != 1000*time.Millisecond || tuned.WindowMax != 4 {
		t.Fatalf("tuned %+v", tuned)
	}
	if buildPerApp(t, `{"handshake-gate":false}`).Experimental.HandshakeGate != nil {
		t.Fatal("handshake-gate false")
	}
}

// gateConn is a connection of a fake dialer: only its addresses matter to the gate.
type gateConn struct {
	net.Conn
	local, remote net.Addr
}

func (c *gateConn) LocalAddr() net.Addr  { return c.local }
func (c *gateConn) RemoteAddr() net.Addr { return c.remote }
func (c *gateConn) Close() error         { return nil }

// slowFirstDialer connects to one server, the first connection slow by slow.
type slowFirstDialer struct {
	slow  time.Duration
	dials atomic.Int32
}

func (d *slowFirstDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	n := d.dials.Add(1)
	if n == 1 {
		time.Sleep(d.slow)
	}
	return &gateConn{
		local:  &net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 40000 + int(n)},
		remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.200"), Port: 443},
	}, nil
}

func (d *slowFirstDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

// E9-01: the gate's window counts the starts of the turns, and a ClientHello follows its start
// after the connect. With a window of exactly 5 s, a first connection slower than the fifth by
// 0.4 s put five ClientHellos within 4.6 s. With the window the core sets, any five ClientHellos
// to a server span 5 s at least. (Each handshake here is one the gate does not see, held for
// unseen_hold, as a naive outbound's.)
func TestHandshakeGateWindowKeepsTheClientHellos(t *testing.T) {
	if testing.Short() {
		t.Skip("takes the gate's window, 5.5 s")
	}
	gate := buildPerApp(t, `{}`).Experimental.HandshakeGate
	tls.SetHandshakeGate(gate)
	defer tls.SetHandshakeGate(nil)
	dialer := tls.GateDialer(&slowFirstDialer{slow: 400 * time.Millisecond})
	var hellos []time.Time
	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		conn, err := dialer.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("192.0.2.200:443"))
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		// the dial returns when the ClientHello may go
		hellos = append(hellos, time.Now())
		_ = conn.Close()
	}
	if span := hellos[4].Sub(hellos[0]); span < 5*time.Second {
		t.Fatalf("five ClientHellos within %v", span)
	}
}
