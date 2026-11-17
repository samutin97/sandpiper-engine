package hcore

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	C "github.com/sagernet/sing-box/constant"
)

// dataRoot is the directory whose data/ holds the core's own files: the settings database (with
// the app's settings, the last profile started, the gRPC server key), the cache file (WARP keys),
// box.log, the stderr logs, goroutine snapshots and libbox's crash reports.
//
// SetupRequest.data_path when the app gives one; else the base path on Android, where the app's
// working directory is the external storage (readable by other apps with the storage permission
// up to Android 10, over USB and by file managers: HC-06); else the working directory, as before.
func dataRootOf(params *SetupRequest) string {
	if params.DataPath != "" {
		return params.DataPath
	}
	if C.IsAndroid && params.BasePath != "" {
		return params.BasePath
	}
	return params.WorkingDir
}

// prepareDataRoot makes the data directory private (0700, and files 0600 on Android through the
// umask), moves the databases an older core left in the working directory, and removes the rest
// of what it left there (current-config.json with every key, the logs).
func prepareDataRoot(params *SetupRequest) string {
	root := dataRootOf(params)
	if C.IsAndroid {
		restrictUmask()
	}
	if root == "" {
		return root
	}
	dataDir := filepath.Join(root, "data")
	os.MkdirAll(dataDir, 0o700)
	if !C.IsWindows {
		os.Chmod(dataDir, 0o700)
	}
	if params.WorkingDir != "" && filepath.Clean(params.WorkingDir) != filepath.Clean(root) {
		migrateDataDir(filepath.Join(params.WorkingDir, "data"), dataDir)
	}
	return root
}

// migrateDataDir moves the databases (*.db: the settings and the cache file) of an old data
// directory to the new one, unless the new one has them already, then removes the old directory:
// what else it holds (current-config.json, logs, snapshots) must not stay readable there.
func migrateDataDir(oldDir, newDir string) {
	entries, err := os.ReadDir(oldDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".db") {
			continue
		}
		dst := filepath.Join(newDir, entry.Name())
		if _, err := os.Stat(dst); err == nil {
			continue
		}
		if err := copyTree(filepath.Join(oldDir, entry.Name()), dst); err != nil {
			Log(LogLevel_WARNING, LogType_CORE, "data migration: ", entry.Name(), ": ", err.Error())
			os.RemoveAll(dst)
		}
	}
	if err := os.RemoveAll(oldDir); err != nil {
		Log(LogLevel_WARNING, LogType_CORE, "data migration: removing the old data directory: ", err.Error())
	}
}

// copyTree copies a file or a directory (a leveldb database is one) with private modes; across
// file systems a rename would fail (the external storage is another one on Android).
func copyTree(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	switch {
	case info.IsDir():
		if err := os.MkdirAll(dst, 0o700); err != nil {
			return err
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err := copyTree(filepath.Join(src, entry.Name()), filepath.Join(dst, entry.Name())); err != nil {
				return err
			}
		}
		return nil
	case info.Mode().IsRegular():
		in, err := os.Open(src)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	}
	return nil // no links or devices
}
