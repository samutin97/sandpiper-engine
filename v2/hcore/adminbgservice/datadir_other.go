//go:build !windows

package adminbgservice

import "os"

// prepareDataDirectory makes the service's folder. On Linux and macOS it is under /var/lib or
// /Library, where only root makes folders.
func prepareDataDirectory(dir string) error {
	return os.MkdirAll(dir, 0o755)
}

// allowUsersToRead: the build stamp and the endpoint are root's, readable by every user.
func allowUsersToRead(path string) error {
	return os.Chmod(path, 0o644)
}
