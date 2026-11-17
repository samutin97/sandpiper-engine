package hcore

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"google.golang.org/grpc/metadata"
)

func TestInsecureModesNeedASecret(t *testing.T) {
	for _, mode := range []SetupMode{SetupMode_GRPC_NORMAL_INSECURE, SetupMode_GRPC_BACKGROUND_INSECURE} {
		if err := checkGrpcMode(mode, ""); err == nil {
			t.Fatalf("%s without a secret accepted", mode)
		}
		if err := checkGrpcMode(mode, "short-secret"); err == nil {
			t.Fatalf("%s with a short secret accepted", mode)
		}
		err := checkGrpcMode(mode, strings.Repeat("s", 32))
		if (C.IsAndroid || C.IsIos) != (err != nil) {
			t.Fatalf("%s with a secret: %v", mode, err)
		}
	}
	for _, mode := range []SetupMode{SetupMode_GRPC_NORMAL, SetupMode_GRPC_BACKGROUND, SetupMode_OLD} {
		if err := checkGrpcMode(mode, ""); err != nil {
			t.Fatalf("%s refused: %v", mode, err)
		}
	}
	// the old fallback of the Android VPN service: mode 4 with no secret, refused by Setup itself
	if err := Setup(&SetupRequest{Mode: SetupMode_GRPC_BACKGROUND_INSECURE, Listen: "127.0.0.1:0"}, nil); err == nil {
		t.Fatal("Setup accepted the insecure mode without a secret")
	}
}

func TestSecretIsCheckedInEveryCall(t *testing.T) {
	secret := strings.Repeat("k", 40)
	if authenticateSecret(context.Background(), secret) == nil {
		t.Fatal("a call without the secret passed")
	}
	bad := metadata.NewIncomingContext(context.Background(), metadata.Pairs(ControlSecretHeader, "wrong"))
	if authenticateSecret(bad, secret) == nil {
		t.Fatal("a wrong secret passed")
	}
	good := metadata.NewIncomingContext(context.Background(), metadata.Pairs(ControlSecretHeader, secret))
	if err := authenticateSecret(good, secret); err != nil {
		t.Fatal(err)
	}
}

func TestControlListenerAddresses(t *testing.T) {
	l, err := listenControl("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(l.Address, ":0") || !strings.HasPrefix(l.Address, "127.0.0.1:") {
		t.Fatalf("address %q", l.Address)
	}
	l.Close()
	if _, err := listenControl("0.0.0.0:0"); err == nil {
		t.Fatal("listened on every address")
	}
	if _, err := listenControl("unix:relative.sock"); err == nil {
		t.Fatal("relative socket path accepted")
	}
	dir := filepath.Join(t.TempDir(), "ipc")
	path := filepath.Join(dir, "c.sock")
	l, err = listenControl("unix:" + path)
	if err != nil {
		t.Skipf("unix sockets unavailable here: %v", err)
	}
	defer l.Close()
	if l.Address != "unix:"+path {
		t.Fatalf("address %q", l.Address)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("socket mode %v", info.Mode().Perm())
		}
		dinfo, _ := os.Stat(dir)
		if dinfo.Mode().Perm() != 0o700 {
			t.Fatalf("dir mode %v", dinfo.Mode().Perm())
		}
	}
	go func() {
		c, err := l.Accept()
		if err == nil {
			c.Write([]byte("ok"))
			c.Close()
		}
	}()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := c.Read(buf); err != nil || string(buf) != "ok" {
		t.Fatalf("own user refused: %v", err)
	}
	c.Close()
}

func TestSecurityPolicyDeniesEveryGuardedFeature(t *testing.T) {
	if err := (denySecurityPolicy{}).CheckFeature(context.Background(), "Tor outbound"); err == nil {
		t.Fatal("Tor outbound allowed")
	}
}
