package hcore

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

// Helpers the upstream tests use (upstream keeps them in an uncommitted file; **/*_test.go is
// ignored there). Synthetic values only.

// freeTCPPort is a TCP port free on 127.0.0.1 now.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// hotReloadSettings are app settings for a test core: proxy mode on mixedPort, no TUN, the
// given log level.
func hotReloadSettings(t *testing.T, mixedPort int, logLevel string) string {
	t.Helper()
	return fmt.Sprintf(`{"mixed-port":%d,"enable-tun":false,"set-system-proxy":false,"log-level":%q,"region":"other","tproxy-port":0,"redirect-port":0,"direct-port":0}`, mixedPort, logLevel)
}

// socks is a socks outbound of a profile, to 127.0.0.1:port.
func socks(tag string, port int) string {
	return fmt.Sprintf(`{"type":"socks","tag":%q,"server":"127.0.0.1","server_port":%d}`, tag, port)
}

// profile is a sing-box profile of these outbounds.
func profile(outbounds ...string) string {
	return `{"outbounds":[` + strings.Join(outbounds, ",") + `]}`
}

// runningOutbound is the outbound of the running core with this tag.
func runningOutbound(t *testing.T, tag string) adapter.Outbound {
	t.Helper()
	box := static.StartedService.Instance().Box()
	out, ok := box.Outbound().Outbound(tag)
	if !ok {
		t.Fatalf("no outbound %q", tag)
	}
	return out
}
