package ezytel

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A server with a certificate nobody signed is refused (HC-20).
func TestEzytelChecksTheCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer server.Close()
	if _, err := NewEzytelService(t.TempDir()).client.Get(server.URL); err == nil {
		t.Fatal("self-signed certificate accepted")
	}
}
