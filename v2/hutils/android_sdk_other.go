//go:build !(android && cgo)

package hutils

// AndroidSDKInt is 0 off Android (or without cgo).
func AndroidSDKInt() int {
	return 0
}
