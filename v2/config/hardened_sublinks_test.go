package config

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestSubscriptionLinksAreNotFetchedByDefault(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	defer server.Close()
	content := []byte("vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls#a\n" + server.URL + "/sub/x\n")
	out := expandSubscriptionLinks(context.Background(), content, false)
	if strings.Contains(string(out), server.URL) || hits.Load() != 0 {
		t.Fatalf("fetched or kept: %q (%d)", out, hits.Load())
	}
	// allowed: still not plain http, nor a loopback address
	out = expandSubscriptionLinks(context.Background(), content, true)
	if hits.Load() != 0 {
		t.Fatal("fetched a plain http loopback URL")
	}
	if _, err := fetchSubscription(context.Background(), "https://127.0.0.1:1/sub"); err == nil {
		t.Fatal("loopback fetched")
	}
	_ = out
}
