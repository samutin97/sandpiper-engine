package hcore

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func probeServer(t *testing.T, handler http.HandlerFunc) (string, uint32) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(server.URL, "https://"))
	p, _ := strconv.Atoi(port)
	return host, uint32(p)
}

func TestDpiProbeOK(t *testing.T) {
	host, port := probeServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			io.Copy(io.Discard, r.Body) // a decoy reads the upload
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Write(make([]byte, 128<<10))
	})
	r := DpiProbe(context.Background(), &DpiProbeRequest{Host: host, Port: port, ServerName: "example.com", Insecure: true, Upload: true, TimeoutMs: 3000})
	if r.Outcome != "ok" || r.Connections != 2 || len(r.Stages) != 6 {
		t.Fatalf("%+v %v", r, r.Stages)
	}
}

// The server stops after 16 KB without closing: the "16 KB" freeze.
func TestDpiProbeFreeze(t *testing.T) {
	host, port := probeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(128<<10))
		w.Write(make([]byte, 16<<10))
		w.(http.Flusher).Flush()
		time.Sleep(6 * time.Second)
	})
	r := DpiProbe(context.Background(), &DpiProbeRequest{Host: host, Port: port, ServerName: "example.com", Insecure: true, TimeoutMs: 3000})
	if r.Outcome != "freeze_16k" {
		t.Fatalf("%+v %v", r, r.Stages)
	}
}

func TestDpiProbeNoServer(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	r := DpiProbe(context.Background(), &DpiProbeRequest{Host: "127.0.0.1", Port: uint32(port), Attempts: 2, TimeoutMs: 1000})
	if !strings.HasPrefix(r.Outcome, "tcp_") || r.Connections != 2 {
		t.Fatalf("%+v", r)
	}
	if r := DpiProbe(context.Background(), &DpiProbeRequest{}); r.Outcome != "error" {
		t.Fatalf("no host: %+v", r)
	}
}

// D-08: the upload POSTs to upload_path (the server's form, which reads the body), the download
// GETs path (a static file); without upload_path both go to path, as before.
func TestDpiProbeUploadPath(t *testing.T) {
	var posts []string
	host, port := probeServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/files/64k.bin":
			w.Write(make([]byte, 100000))
		case r.Method == http.MethodPost && r.URL.Path == "/upload":
			posts = append(posts, r.URL.Path)
			io.Copy(io.Discard, io.LimitReader(r.Body, 256<<10))
			w.WriteHeader(http.StatusOK)
		default:
			posts = append(posts, r.URL.Path)
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	r := DpiProbe(context.Background(), &DpiProbeRequest{Host: host, Port: port, ServerName: "example.com", Insecure: true, Upload: true,
		Path: "/files/64k.bin", UploadPath: "/upload", TimeoutMs: 3000})
	if r.Outcome != "ok" || len(r.Stages) != 6 || r.Stages[5].Name != "upload" || r.Stages[5].Bytes != 64<<10 {
		t.Fatalf("%+v %v", r, r.Stages)
	}
	if len(posts) != 1 || posts[0] != "/upload" {
		t.Fatalf("POSTs %q", posts)
	}
	posts = nil
	DpiProbe(context.Background(), &DpiProbeRequest{Host: host, Port: port, ServerName: "example.com", Insecure: true, Upload: true,
		Path: "/files/64k.bin", TimeoutMs: 3000})
	if len(posts) != 1 || posts[0] != "/files/64k.bin" {
		t.Fatalf("without upload_path: POSTs %q", posts)
	}
	for in, want := range map[string]string{"": "/x", "no-slash": "/x", "/a b": "/x", "/form\r\nX-Injected: 1": "/x", "/ok": "/ok"} {
		if got := newProbe(&DpiProbeRequest{Host: "h", Path: "/x", UploadPath: in}).uploadPath; got != want {
			t.Errorf("upload_path %q: %q, want %q", in, got, want)
		}
	}
	if got := newProbe(&DpiProbeRequest{Host: "h", Path: "/x\r\nX: 1"}).path; got != "/" {
		t.Errorf("path with a line break: %q", got)
	}
}

// D-08: a server that trickles a byte now and then cannot hold the probe beyond the stage's
// timeout (each read alone was under the 4 s stall, so it read on until 64 KiB), and the app
// going away ends it at once; the answer always has an outcome.
func TestDpiProbeEndsInItsBudget(t *testing.T) {
	host, port := probeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(128<<10))
		w.WriteHeader(http.StatusOK)
		for {
			if _, err := w.Write([]byte{0}); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(300 * time.Millisecond):
			}
		}
	})
	start := time.Now()
	r := DpiProbe(context.Background(), &DpiProbeRequest{Host: host, Port: port, ServerName: "example.com", Insecure: true, TimeoutMs: 1500})
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("took %v", elapsed)
	}
	if r.Outcome != "stall" || r.Stages[len(r.Stages)-1].Name != "download" {
		t.Fatalf("%+v %v", r, r.Stages)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	start = time.Now()
	r = DpiProbe(ctx, &DpiProbeRequest{Host: host, Port: port, ServerName: "example.com", Insecure: true, TimeoutMs: 30000, Attempts: 2})
	if elapsed := time.Since(start); elapsed > 3*time.Second || r.Outcome == "" {
		t.Fatalf("the app went away: %v, %+v", elapsed, r)
	}

	p := newProbe(&DpiProbeRequest{Host: "h", Attempts: 2, TimeoutMs: 30000})
	if p.budget() != 2*2*3*30*time.Second+time.Second {
		t.Fatalf("budget %v", p.budget())
	}
	if newProbe(&DpiProbeRequest{Host: "h"}).budget() != 6*probeDefaultTimeout+time.Second {
		t.Fatal("default budget")
	}
}
