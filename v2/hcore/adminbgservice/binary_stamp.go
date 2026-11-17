package adminbgservice

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hiddify/hiddify-core/v2/hcore/buildid"
	"github.com/hiddify/hiddify-core/v2/hcore/vpnservice"
)

func buildStampPath() string {
	return vpnservice.BuildStampPath()
}

// WriteRunningBinaryStamp records the embedded build id of the service process so the
// app can refuse a mismatched build without hashing large executables.
func WriteRunningBinaryStamp() error {
	id := buildid.Get()
	if !buildid.IsSet() {
		return fmt.Errorf("tunnel service was built without a build id; rebuild hiddify-core so its Makefile embeds one")
	}
	if err := os.MkdirAll(filepath.Dir(buildStampPath()), 0o755); err != nil {
		return err
	}
	// a new file (not one somebody left there), readable by the app, which runs as the user
	return writePublicFile(buildStampPath(), []byte(id+"\n"))
}

// writePublicFile writes path anew, through a new file renamed over it, readable by users and
// written only by SYSTEM, Administrators or root (allowUsersToRead).
func writePublicFile(path string, content []byte) error {
	next := path + ".new"
	if err := writeNewFile(next, content, 0o644); err != nil {
		return err
	}
	if err := allowUsersToRead(next); err != nil {
		_ = os.Remove(next)
		return err
	}
	if err := os.Rename(next, path); err != nil {
		_ = os.Remove(next)
		return err
	}
	return nil
}

// ReadBinaryStamp returns the build id the running service last wrote.
func ReadBinaryStamp() (string, error) {
	raw, err := os.ReadFile(buildStampPath())
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(raw))
	if id == "" || id == "unset" {
		return "", fmt.Errorf("invalid tunnel build stamp")
	}
	return id, nil
}

// SameBuild reports whether expected matches the stamp the service wrote at start.
func SameBuild(expected string) (bool, error) {
	want, err := ReadBinaryStamp()
	if err != nil {
		return false, err
	}
	expected = strings.TrimSpace(expected)
	if expected == "" || expected == "unset" {
		return false, fmt.Errorf("app build id is unset")
	}
	return expected == want, nil
}
