//go:build linux || android || darwin

package hcore

import "syscall"

// restrictUmask makes the files the process creates from now on private to its user (0600,
// directories 0700): the databases, the cache file and the logs.
func restrictUmask() {
	syscall.Umask(0o077)
}
