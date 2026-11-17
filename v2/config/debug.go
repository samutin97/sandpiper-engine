package config

import (
	context "context"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/sagernet/sing-box/option"
)

// SaveCurrentConfig writes the running config to path, for debugging: only in a core built with
// the tag with_debug_files, sanitized, 0600 (debug_files.go). A release core never writes it: the
// file held every key and password of the profile, in the app's external storage on Android
// (HC-06).
func SaveCurrentConfig(ctx context.Context, path string, options option.Options) error {
	return saveCurrentConfig(ctx, path, options)
}

func DeferPanicToError(name string, err func(error)) {
	if r := recover(); r != nil {
		s := fmt.Errorf("%s panic: %s\n%s", name, r, string(debug.Stack()))
		err(s)
		<-time.After(5 * time.Second)
	}
}
