package config

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
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
	// ST4-03: one at a time, a gap drawn in 0.7-1.1 s, at most 4 in 5 s
	if gate.MaxInflight != 1 || time.Duration(gate.MinGap) != 700*time.Millisecond || time.Duration(gate.MaxGap) != 1100*time.Millisecond ||
		time.Duration(gate.Window) != 5*time.Second || gate.WindowMax != 4 {
		t.Fatalf("default %+v", gate)
	}
	tuned := buildPerApp(t, `{"handshake-gate-max":2,"handshake-gate-gap-ms":600}`).Experimental.HandshakeGate
	if tuned.MaxInflight != 2 || time.Duration(tuned.MinGap) != 600*time.Millisecond || time.Duration(tuned.MaxGap) != 1000*time.Millisecond || tuned.WindowMax != 4 {
		t.Fatalf("tuned %+v", tuned)
	}
	if buildPerApp(t, `{"handshake-gate":false}`).Experimental.HandshakeGate != nil {
		t.Fatal("handshake-gate false")
	}
}
