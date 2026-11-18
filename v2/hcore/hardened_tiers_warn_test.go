package hcore

import (
	"strings"
	"testing"
	"time"
)

// Every line of the choice by the server's ranking is a warning (E12-02 of the sp.12 acceptance):
// the app keeps warnings and above in app.log, and the walk's reason, the checks and the way up
// stayed at the info level, so app.log had "using 9" without what led to it.
func TestTierLinesAreWarnings(t *testing.T) {
	saved := static.logLevel.Load()
	static.logLevel.Store(int32(LogLevel_TRACE))
	t.Cleanup(func() { static.logLevel.Store(saved) })
	logs := static.logObserver.Subscribe(64)
	t.Cleanup(func() { static.logObserver.Unsubscribe(logs) })

	env := &tierEnv{}
	lines := []string{
		"tiers: choosing (network changed), network 0a1b2c3d",
		"tiers: 2 gRPC: noconnect",
		"tiers: the path to the server of 2 gRPC: blocked",
		"tiers: way up, second check of 2 gRPC: ok",
		"tiers: the user agreed to 10 WG",
		"tiers: using 9 HTTP3 (tier 2, fallback)",
	}
	for _, line := range lines {
		env.Log(line)
	}
	tierLog("the group starts on ", "2 gRPC", ", not on ", "3 XHTTP")
	tierLog("select moves to the server's ranking (first policy)")

	want := len(lines) + 2
	for got := 0; got < want; {
		select {
		case message := <-logs:
			if !strings.Contains(message.Message, "tiers: ") {
				continue // another part of the core
			}
			got++
			if message.Level != LogLevel_WARNING {
				t.Errorf("%q: %v, want a warning", message.Message, message.Level)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%d of %d lines came", got, want)
		}
	}
}
