//go:build with_debug_files

package hcore

// goroutineSnapshotsBuild: a debug build of the core (with_debug_files) writes the goroutine
// snapshots whatever the app's debug flag.
const goroutineSnapshotsBuild = true
