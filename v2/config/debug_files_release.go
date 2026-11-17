//go:build !with_debug_files

package config

import (
	"context"

	"github.com/sagernet/sing-box/option"
)

// saveCurrentConfig writes nothing in a release build (see SaveCurrentConfig).
func saveCurrentConfig(context.Context, string, option.Options) error {
	return nil
}
