package hcore

import (
	"regexp"
	"testing"

	"github.com/sagernet/sing-box/option"
)

// W4-05: the CLI downloads a subscription with the app's user agent, not upstream's old one
// ("HiddifyNext/4.0.0(windows) like ClashMeta v2ray sing-box").
func TestStandaloneUserAgentIsTheApps(t *testing.T) {
	agent := standaloneUserAgent()
	if !regexp.MustCompile(`^HiddifyNext/\d+\.\d+\.\d+ \((windows|linux|macos|android|ios|freebsd)\) awg31$`).MatchString(agent) {
		t.Fatalf("user agent %q", agent)
	}
}

// W4-05: the CLI reports a Clash API only when the built config opens one.
func TestStandaloneClashController(t *testing.T) {
	for _, experimental := range []*option.ExperimentalOptions{nil, {}, {ClashAPI: &option.ClashAPIOptions{}}} {
		if clashController(experimental) != nil {
			t.Errorf("%+v: a Clash API without a controller", experimental)
		}
	}
	listening := &option.ExperimentalOptions{ClashAPI: &option.ClashAPIOptions{ExternalController: "127.0.0.1:41234", Secret: "s"}}
	if clashController(listening) == nil {
		t.Error("the listening Clash API was not reported")
	}
}
