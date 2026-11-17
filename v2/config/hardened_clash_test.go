package config

import (
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
)

// The settings v5.9.8 sends: the Clash API on, on 16756. No port may open from them (HC-04).
func TestClashAPIOpensNoPortForTheOldSettings(t *testing.T) {
	opts := chainTestOptions(t, `{"enable-clash-api":true,"clash-api-port":16756,"enable-tun":true}`)
	options, err := BuildConfig(libbox.BaseContext(nil), opts, &ReadOptions{Content: oneProxyProfile})
	if err != nil {
		t.Fatal(err)
	}
	if err := libbox.CheckConfigOptions(options); err != nil {
		t.Fatalf("sing-box rejected the config: %v", err)
	}
	api := options.Experimental.ClashAPI
	if api == nil {
		t.Fatal("no clash server: the traffic statistics need it")
	}
	if api.ExternalController != "" {
		t.Fatalf("the Clash API listens on %q", api.ExternalController)
	}
	if options.Experimental.CacheFile == nil || options.Experimental.Monitoring == nil {
		t.Fatal("cache file and monitoring must stay on")
	}
}

func TestClashAPIListenerWhenAskedForOnTheDesktop(t *testing.T) {
	opts := chainTestOptions(t, `{"clash-api-listen":true,"clash-api-port":16756,"web-secret":"short"}`)
	options, err := BuildConfig(libbox.BaseContext(nil), opts, &ReadOptions{Content: oneProxyProfile})
	if err != nil {
		t.Fatal(err)
	}
	api := options.Experimental.ClashAPI
	if C.IsAndroid || C.IsIos {
		if api.ExternalController != "" {
			t.Fatalf("mobile Clash API listens on %q", api.ExternalController)
		}
		return
	}
	if !strings.HasPrefix(api.ExternalController, "127.0.0.1:") || strings.HasSuffix(api.ExternalController, ":16756") || strings.HasSuffix(api.ExternalController, ":0") {
		t.Fatalf("controller %q: want a random loopback port", api.ExternalController)
	}
	if len(api.Secret) != 64 || api.Secret == "short" {
		t.Fatalf("secret %q: want 32 random bytes", api.Secret)
	}
	if len(api.AccessControlAllowOrigin) != 1 || api.AccessControlAllowOrigin[0] == "*" {
		t.Fatalf("CORS %v", api.AccessControlAllowOrigin)
	}
}

func TestGenerateRandomStringIsRandom(t *testing.T) {
	a, b := generateRandomString(16), generateRandomString(16)
	if len(a) != 16 || a == b || a == "hiddify" {
		t.Fatalf("%q %q", a, b)
	}
}
