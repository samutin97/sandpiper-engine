package hcore

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

// D-10: box.log keeps no destination, server name or address below debug, is rotated at 1 MiB
// with one previous file, and is 0600.
func TestBoxLogIsScrubbedAndRotated(t *testing.T) {
	old := static.logLevel.Load()
	defer static.logLevel.Store(old)
	static.logLevel.Store(int32(LogLevel_WARNING))

	path := filepath.Join(t.TempDir(), "box.log")
	ctx := service.ContextWith[log.FileOpener](service.ContextWithDefaultRegistry(context.Background()), log.FileOpener(boxLogOpener{}))
	factory, err := log.New(log.Options{Context: ctx, Options: option.LogOptions{Output: path, Level: "warn", DisableColor: true}, BaseTime: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if err := factory.Start(); err != nil {
		t.Fatal(err)
	}
	logger := factory.NewLogger("outbound/vless[1 Узел]")
	logger.Error("open connection to 104.26.12.205:443 using outbound/vless[1 Узел]: dial tcp 192.0.2.10:443: i/o timeout")
	logger.Error("open connection to www.example.org:443: reality verification failed for mask.example.net, password=hunter2")
	logger.Error("context.Canceled reading data/box.log")
	factory.Close()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(content)
	for _, leak := range []string{"104.26.12.205", "192.0.2.10", "www.example.org", "mask.example.net", "hunter2"} {
		if strings.Contains(got, leak) {
			t.Fatalf("%q in box.log:\n%s", leak, got)
		}
	}
	for _, kept := range []string{"open connection to <host>:443", "<ipv4>:443", "outbound/vless[1 Узел]", "context.Canceled", "data/box.log"} {
		if !strings.Contains(got, kept) {
			t.Fatalf("%q lost in box.log:\n%s", kept, got)
		}
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", info.Mode().Perm())
		}
	}

	// debug: the addresses stay (a developer reads them), the secrets do not
	static.logLevel.Store(int32(LogLevel_DEBUG))
	if line := scrubLogLine("open connection to www.example.org:443 password=hunter2"); !strings.Contains(line, "www.example.org") || strings.Contains(line, "hunter2") {
		t.Fatalf("debug: %q", line)
	}

	// rotation: never above the size, one previous file
	rotating, err := openRotatingLog(filepath.Join(t.TempDir(), "box.log"), 1000, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Repeat("x", 99) + "\n"
	for i := 0; i < 35; i++ {
		if _, err := rotating.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	rotating.Close()
	current, _ := os.Stat(rotating.path)
	previous, err := os.Stat(rotating.path + ".1")
	if err != nil || current.Size() > 1000 || previous.Size() > 1000 || current.Size()+previous.Size() != 500+1000 {
		t.Fatalf("rotation: current %d, previous %v %v", current.Size(), previous, err)
	}
	if _, err := os.Stat(rotating.path + ".2"); !os.IsNotExist(err) {
		t.Fatal("more than one previous file")
	}
	// a file already at the size is rotated when opened
	reopened, err := openRotatingLog(rotating.path, 500, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	reopened.Close()
	if info, _ := os.Stat(rotating.path); info.Size() != 0 {
		t.Fatalf("reopened at the size: %d", info.Size())
	}
}

// D-10: a release writes no goroutine snapshot or dump unless set up with debug, and removes the
// ones an earlier core left; with debug they are 0600.
func TestGoroutineFilesOnlyInDebug(t *testing.T) {
	if goroutineSnapshotsBuild {
		t.Skip("a debug build of the core")
	}
	if goroutineSnapshotsOn(false) || !goroutineSnapshotsOn(true) {
		t.Fatal("goroutineSnapshotsOn")
	}
	working := t.TempDir()
	data := filepath.Join(working, "data")
	os.MkdirAll(data, 0o700)
	leftovers := []string{
		goroutineSnapshotPath(working, SetupMode_GRPC_NORMAL), goroutinePreviousPath(working, SetupMode_GRPC_NORMAL),
		filepath.Join(data, "goroutine-start.log"), filepath.Join(data, "goroutine-stop-slow.log"),
	}
	for _, path := range leftovers {
		os.WriteFile(path, []byte("stacks"), 0o644)
	}
	removeGoroutineSnapshots(working, SetupMode_GRPC_NORMAL)
	for _, path := range leftovers {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s left", path)
		}
	}

	previous := static.debug
	defer func() { static.debug = previous }()
	static.debug = false
	dump := filepath.Join(data, "goroutine-start.log")
	dumpGoroutinesToFile(dump)
	if _, err := os.Stat(dump); !os.IsNotExist(err) {
		t.Fatal("a release dumped the goroutines")
	}
	static.debug = true
	if err := dumpGoroutinesToFile(dump); err != nil {
		t.Fatal(err)
	}
	writeGoroutineSnapshot(goroutineSnapshotPath(working, SetupMode_GRPC_NORMAL))
	for _, path := range []string{dump, goroutineSnapshotPath(working, SetupMode_GRPC_NORMAL)} {
		info, err := os.Stat(path)
		if err != nil || info.Size() == 0 {
			t.Fatalf("debug: %s %v", path, err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", path, info.Mode().Perm())
		}
	}
}

// Host names are scrubbed below debug, and what only looks like one is not.
func TestScrubHostNames(t *testing.T) {
	cases := map[string]string{
		"dns: exchange failed for www.google.com. IN A":                        "dns: exchange failed for <host>. IN A",
		"x509: certificate is valid for a.example.com, not xn--80ak6aa92e.com": "x509: certificate is valid for <host>, not <host>",
		"reading data/box.log and config.json":                                 "reading data/box.log and config.json",
		"context.Canceled, net.OpError":                                        "context.Canceled, net.OpError",
		"version 1.15.0-alpha.13":                                              "version 1.15.0-alpha.13",
	}
	for in, want := range cases {
		if got := scrubHostNames(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
