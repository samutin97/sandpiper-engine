//go:build !with_debug_files

package hcore

// goroutineSnapshotsBuild: a release build writes the goroutine snapshots only when the app sets
// the core up with debug (see goroutineSnapshotsOn).
const goroutineSnapshotsBuild = false
