package vpnservice

import (
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	hutils "github.com/hiddify/hiddify-core/v2/hutils"
)

func env(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

// W4-03: the app read the service's secret from upstream Hiddify's folder while the service wrote
// it to the fork's. Every place now takes the folder from here; on Windows and Linux it is never
// one of upstream's.
func TestTheServiceFolderIsTheForks(t *testing.T) {
	cases := []struct {
		goos   string
		values map[string]string
		want   string
	}{
		{"windows", map[string]string{"PROGRAMDATA": `D:\Data`}, `D:\Data\Sandpiper\AdminBgService`},
		{"windows", nil, `C:\ProgramData\Sandpiper\AdminBgService`},
		{"linux", nil, "/var/lib/sandpiper-admin-bgservice"},
		{"darwin", nil, "/Library/Application Support/Hiddify/AdminBgService/data"},
		{"linux", map[string]string{DataDirEnv: "/tmp/a", LegacyDataDirEnv: "/tmp/b"}, "/tmp/a"},
		{"windows", map[string]string{LegacyDataDirEnv: `E:\b`}, `E:\b`},
	}
	for _, c := range cases {
		got := dataDirOn(c.goos, env(c.values))
		if c.goos == "windows" {
			// filepath.Join of this host; the test runs on any
			got = strings.ReplaceAll(got, "/", `\`)
		}
		if got != c.want {
			t.Errorf("%s %v: %q, want %q", c.goos, c.values, got, c.want)
		}
	}
	for _, goos := range []string{"windows", "linux"} {
		for _, name := range []string{dataDirOn(goos, env(nil)), ServiceNameOn(goos), ServiceDisplayNameOn(goos),
			ServiceDescriptionOn(goos), TunInterfaceNameOn(goos), CLINameOn(goos) + "-not-linux"} {
			if goos == "linux" && strings.HasSuffix(name, "-not-linux") {
				continue // the Linux launcher keeps upstream's file name
			}
			if strings.Contains(strings.ToLower(name), "hiddify") {
				t.Errorf("%s: %q names upstream Hiddify", goos, name)
			}
		}
	}
}

// W4-01: no fixed port for the service outside macOS (whose app reads a fixed one until it is
// renamed); the service takes a free port and publishes it.
func TestTheServiceHasNoFixedPortOutsideMacOS(t *testing.T) {
	for _, goos := range []string{"windows", "linux", "freebsd"} {
		if port := FixedPortOn(goos); port != 0 {
			t.Errorf("%s: fixed port %d", goos, port)
		}
	}
	if FixedPortOn("darwin") != DarwinServicePort {
		t.Errorf("darwin: %d", FixedPortOn("darwin"))
	}
}

func newCertificate(t *testing.T) (string, tls.Certificate) {
	t.Helper()
	pair, err := hutils.GenerateCertificatePair()
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(pair.Certificate, pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pair.Certificate), certificate
}

func TestEndpointFile(t *testing.T) {
	pem, _ := newCertificate(t)
	endpoint := Endpoint{Address: "127.0.0.1:41234", Certificate: pem}
	raw, err := endpoint.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	read, err := ParseEndpoint(raw)
	if err != nil || read != endpoint || read.Port() != 41234 {
		t.Fatalf("read back %+v, %v", read, err)
	}
	for _, bad := range []Endpoint{
		{Address: "0.0.0.0:41234", Certificate: pem},
		{Address: "192.0.2.1:41234", Certificate: pem},
		{Address: "127.0.0.1:0", Certificate: pem},
		{Address: "127.0.0.1", Certificate: pem},
		{Address: "localhost:41234", Certificate: pem},
		{Address: "127.0.0.1:41234", Certificate: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"},
		{Address: "127.0.0.1:41234", Certificate: "not a certificate"},
	} {
		if _, err := bad.Marshal(); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	if _, err := ParseEndpoint([]byte("{")); err == nil {
		t.Error("broken JSON accepted")
	}
}

// A program that holds the port the endpoint names, but not the service's key, is not the
// service: the client's handshake fails before it sends anything.
func TestEndpointTrustsOnlyItsCertificate(t *testing.T) {
	servicePEM, serviceCertificate := newCertificate(t)
	otherPEM, _ := newCertificate(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serviceCertificate},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				_ = conn.(*tls.Conn).Handshake()
				conn.Close()
			}(conn)
		}
	}()
	address := listener.Addr().String()
	if !(Endpoint{Address: address, Certificate: servicePEM}).Reachable(2 * time.Second) {
		t.Error("the service with its certificate is not reachable")
	}
	if (Endpoint{Address: address, Certificate: otherPEM}).Reachable(2 * time.Second) {
		t.Error("a server with another certificate was taken for the service")
	}
	// nothing listens there once it is closed
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gone := free.Addr().String()
	free.Close()
	if (Endpoint{Address: gone, Certificate: servicePEM}).Reachable(500 * time.Millisecond) {
		t.Error("a closed port answered")
	}
}
