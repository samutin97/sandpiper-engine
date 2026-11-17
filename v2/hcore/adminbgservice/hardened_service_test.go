package adminbgservice

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	hcommon "github.com/hiddify/hiddify-core/v2/hcommon"
	"github.com/hiddify/hiddify-core/v2/hcore/adminbg"
	"github.com/hiddify/hiddify-core/v2/hcore/vpnservice"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const testSecret = "0123456789abcdefghijklmnopqrstuvwxyzABCD"

// serviceDir points the service's folder at a temporary one, writable by the test again afterwards
// (the endpoint and the build stamp get a DACL of their own on Windows).
func serviceDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(vpnservice.DataDirEnv, dir)
	t.Cleanup(func() { makeRemovable(t, dir) })
	return dir
}

func startTestService(t *testing.T) *hiddifyNext {
	t.Helper()
	next := &hiddifyNext{secret: testSecret}
	server, err := next.StartAdminBgGrpcServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Stop)
	return next
}

// W4-01, B-01: the installed service of Windows and Linux listens on a free port with a
// certificate of its own and publishes both; the console launcher (connect, disconnect) finds it
// there, and is let in with the secret only.
func TestTheServiceIsFoundByItsPublishedEndpoint(t *testing.T) {
	if !vpnservice.PublishesEndpoint() {
		t.Skip("the macOS service keeps its fixed port")
	}
	dir := serviceDir(t)
	if err := os.WriteFile(filepath.Join(dir, vpnservice.SecretFile), []byte(testSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	next := startTestService(t)
	if next.endpoint.Certificate == "" || next.endpoint.Port() == 0 {
		t.Fatalf("no certificate or port: %+v", next.endpoint)
	}
	if strings.HasSuffix(next.endpoint.Address, ":18420") || strings.HasSuffix(next.endpoint.Address, ":18020") {
		t.Fatalf("a fixed port: %s", next.endpoint.Address)
	}
	if _, err := vpnservice.ReadEndpoint(); err != vpnservice.ErrNoEndpoint {
		t.Fatalf("an endpoint before it was published: %v", err)
	}
	if err := publishEndpoint(next.endpoint); err != nil {
		t.Fatal(err)
	}
	published, err := vpnservice.ReadEndpoint()
	if err != nil || published != next.endpoint {
		t.Fatalf("published %+v, %v", published, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, callCtx, err := dialTunnel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	reply, err := NewHiddifyAdminBGClient(conn).Status(callCtx, &hcommon.Empty{})
	if err != nil || reply.GetMessage() != "stopped" {
		t.Fatalf("status through the published endpoint: %v %v", reply, err)
	}

	// the right certificate without the secret: refused
	config, _ := published.TLSConfig()
	plain, err := grpc.NewClient(published.Address, grpc.WithTransportCredentials(credentials.NewTLS(config)))
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	if _, err := NewHiddifyAdminBGClient(plain).Status(ctx, &hcommon.Empty{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("without the secret: %v", err)
	}
	// the secret without TLS: the server speaks TLS only
	clear, err := grpc.NewClient(published.Address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer clear.Close()
	secretCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs(adminbg.SecretHeader, testSecret))
	shortCtx, shortCancel := context.WithTimeout(secretCtx, 2*time.Second)
	defer shortCancel()
	if _, err := NewHiddifyAdminBGClient(clear).Status(shortCtx, &hcommon.Empty{}); err == nil {
		t.Fatal("a call without TLS was served")
	}

	// a stopped service withdraws its endpoint: no client is sent to a port another program may take
	withdrawEndpoint()
	if _, err := vpnservice.ReadEndpoint(); err != vpnservice.ErrNoEndpoint {
		t.Fatalf("after the stop: %v", err)
	}
	if _, _, err := dialTunnel(ctx); err == nil {
		t.Fatal("dialled a service that withdrew its endpoint")
	}
}

// B-01: no API without the secret, and no bridge: a start without the app's configuration.
func TestTheServiceRefusesWithoutSecretOrConfiguration(t *testing.T) {
	serviceDir(t)
	if _, err := (&hiddifyNext{}).StartAdminBgGrpcServer("127.0.0.1:0"); err == nil {
		t.Fatal("served without a secret")
	}
	next := startTestService(t)
	if _, err := next.adminBg.Start(context.Background(), &AdminBgStartRequest{ServerPort: 12334}); err == nil {
		t.Fatal("started the bridge")
	}
}

// B-01: every install makes a new secret, as a new file; a secret somebody left there is not taken.
func TestEveryInstallWritesANewSecret(t *testing.T) {
	dir := serviceDir(t)
	planted := strings.Repeat("p", 64)
	if err := os.WriteFile(filepath.Join(dir, vpnservice.SecretFile), []byte(planted), 0o644); err != nil {
		t.Fatal(err)
	}
	first, err := EnsureControlSecret("")
	if err != nil {
		t.Fatal(err)
	}
	second, err := EnsureControlSecret("")
	if err != nil {
		t.Fatal(err)
	}
	if first == planted || first == second || len(first) < adminbg.MinSecretLength {
		t.Fatalf("secrets %q, %q", first, second)
	}
	if loaded, err := LoadControlSecret(); err != nil || loaded != second {
		t.Fatalf("loaded %q, %v", loaded, err)
	}
}

// B-01: the engine the service runs as SYSTEM or root never takes the settings that would let a
// request open a listener of its choice or write a file anywhere.
func TestPrivilegedSettings(t *testing.T) {
	cleaned, err := privilegedSettings(`{"enable-full-config":true,"log-file":"C:\\\\x","mixed-port":0}`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cleaned, "enable-full-config") || strings.Contains(cleaned, "log-file") || !strings.Contains(cleaned, "mixed-port") {
		t.Fatalf("cleaned settings: %s", cleaned)
	}
	if empty, _ := privilegedSettings(""); empty != "{}" {
		t.Fatalf("empty settings: %s", empty)
	}
	if _, err := privilegedSettings("{"); err == nil {
		t.Fatal("broken settings accepted")
	}
}
