package hcore

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	"github.com/hiddify/hiddify-core/v2/config"
)

func TestDataRootOf(t *testing.T) {
	if got := dataRootOf(&SetupRequest{BasePath: "/b", WorkingDir: "/w", DataPath: "/d"}); got != "/d" {
		t.Fatalf("data_path given: %q", got)
	}
	want := "/w"
	if C.IsAndroid {
		want = "/b"
	}
	if got := dataRootOf(&SetupRequest{BasePath: "/b", WorkingDir: "/w"}); got != want {
		t.Fatalf("no data_path: %q, want %q", got, want)
	}
}

func TestMigrateDataDirMovesTheDatabasesAndRemovesTheRest(t *testing.T) {
	old := filepath.Join(t.TempDir(), "external", "data")
	newDir := filepath.Join(t.TempDir(), "internal", "data")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(old, "AppSettings.db"), 0o755))
	must(os.WriteFile(filepath.Join(old, "AppSettings.db", "000001.log"), []byte("settings"), 0o644))
	must(os.WriteFile(filepath.Join(old, "clash.db"), []byte("cache"), 0o644))
	must(os.WriteFile(filepath.Join(old, "current-config.json"), []byte(`{"private_key":"x"}`), 0o644))
	must(os.WriteFile(filepath.Join(old, "box.log"), []byte("log"), 0o644))
	must(os.MkdirAll(newDir, 0o700))

	migrateDataDir(old, newDir)

	if b, err := os.ReadFile(filepath.Join(newDir, "AppSettings.db", "000001.log")); err != nil || string(b) != "settings" {
		t.Fatalf("settings database not moved: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(newDir, "clash.db")); err != nil || string(b) != "cache" {
		t.Fatalf("cache file not moved: %v", err)
	}
	for _, name := range []string{"current-config.json", "box.log"} {
		if _, err := os.Stat(filepath.Join(newDir, name)); err == nil {
			t.Fatalf("%s copied", name)
		}
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("old data directory left: %v", err)
	}
}

func TestReleaseCoreWritesNoCurrentConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "current-config.json")
	if err := config.SaveCurrentConfig(context.Background(), path, option.Options{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("current-config.json written: %v", err)
	}
}
