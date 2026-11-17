package adminbgservice

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/hiddify/hiddify-core/v2/hcore/adminbg"
	"github.com/hiddify/hiddify-core/v2/hcore/vpnservice"
)

// controlDataDir is the service's folder (vpnservice.DataDir): a fixed, OS-standard location
// shared by the elevated service and the unelevated app. It must not live next to a debug build
// path (those move) and must not be a copy of the app binary tree (that triggers antivirus
// heuristics on Windows). On Windows and Linux it is the fork's own: upstream Hiddify keeps its
// service's secret in a Hiddify folder, and a Sandpiper service never reads or replaces it.
func controlDataDir() string {
	return vpnservice.DataDir()
}

func controlSecretPath() string {
	return vpnservice.SecretPath()
}

// EnsureControlSecret writes a new random secret the installing user can read and the privileged
// service enforces on every gRPC call. B-01: a secret already there is never taken over (another
// program could have put one there that it knows): every install makes a new file, as this
// elevated process.
func EnsureControlSecret(owner string) (string, error) {
	path := controlSecretPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	raw := make([]byte, 48)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	secret := base64.RawStdEncoding.EncodeToString(raw)
	if err := writeNewFile(path, []byte(secret), 0o600); err != nil {
		return "", err
	}
	if err := restrictSecretFile(path, owner); err != nil {
		return "", err
	}
	return secret, nil
}

// writeNewFile replaces path with a new file this process creates: a file, a link or a junction
// somebody else left there is removed first, never written through.
func writeNewFile(path string, content []byte, mode os.FileMode) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func LoadControlSecret() (string, error) {
	if foregroundSecret != "" {
		return foregroundSecret, nil
	}
	secret, err := os.ReadFile(controlSecretPath())
	if legacy := vpnservice.LegacySecretPath(); err != nil && legacy != "" { // macOS only
		secret, err = os.ReadFile(legacy)
	}
	if err != nil {
		return "", err
	}
	if len(secret) < adminbg.MinSecretLength {
		return "", fmt.Errorf("admin_bgservice control secret is too short")
	}
	return string(secret), nil
}

func restrictSecretFile(path, owner string) error {
	if err := os.Chmod(path, 0o600); err != nil && runtime.GOOS != "windows" {
		return err
	}
	if owner == "" {
		return nil
	}
	return chownSecret(path, owner)
}
