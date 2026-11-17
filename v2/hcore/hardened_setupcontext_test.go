package hcore

import (
	"context"
	"testing"
)

type setupContextKey struct{}

// A start without the gRPC API (Mobile.Start) built the core in libbox.BaseContext(nil), without the
// platform interface: on Android its "local" DNS server asked [::1]:53 and failed. It now takes the
// context Setup made.
func TestStartWithoutTheAPIUsesTheSetupContext(t *testing.T) {
	saved := static.BaseContext
	defer func() { static.BaseContext = saved }()
	setup := context.WithValue(context.Background(), setupContextKey{}, "setup")
	static.BaseContext = setup
	if SetupContext() != setup {
		t.Fatal("not the context of Setup")
	}
	static.BaseContext = nil
	if ctx := SetupContext(); ctx == nil || ctx.Value(setupContextKey{}) != nil {
		t.Fatal("no fallback context before Setup")
	}
}
