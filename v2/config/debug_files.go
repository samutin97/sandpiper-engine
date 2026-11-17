//go:build with_debug_files

package config

import (
	"context"
	"os"
	"path/filepath"

	"github.com/sagernet/sing-box/option"
)

func saveCurrentConfig(ctx context.Context, path string, options option.Options) error {
	content, err := options.MarshalJSONContext(ctx)
	if err != nil {
		return err
	}
	p, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, SanitizeConfigJSON(content), 0o600)
}
