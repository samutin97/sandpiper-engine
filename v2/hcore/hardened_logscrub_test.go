package hcore

import (
	"strings"
	"testing"
)

func TestScrubLogLine(t *testing.T) {
	old := static.logLevel.Load()
	defer static.logLevel.Store(old)
	line := `outbound/vless[p1]: vless://00000000-0000-4000-8000-000000000001@192.0.2.10:443?pbk=x dial 192.0.2.10:443 private_key=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU= password: hunter2 uuid=00000000-0000-4000-8000-000000000002 [2001:db8::1]:443`
	static.logLevel.Store(int32(LogLevel_WARNING))
	got := scrubLogLine(line)
	for _, secret := range []string{"00000000-0000-4000-8000", "hunter2", "QUJDREVG", "192.0.2.10", "2001:db8::1", "pbk=x"} {
		if strings.Contains(got, secret) {
			t.Fatalf("%q left in %q", secret, got)
		}
	}
	// debug: addresses stay, secrets do not
	static.logLevel.Store(int32(LogLevel_DEBUG))
	got = scrubLogLine("dial 192.0.2.10:443 password=hunter2 at 12:34:56")
	if !strings.Contains(got, "192.0.2.10") || strings.Contains(got, "hunter2") || !strings.Contains(got, "12:34:56") {
		t.Fatalf("debug: %q", got)
	}
}

// The other subscription of a profile's pair is a secret like the profile's own link: under its key
// or alone, in base64url, it never stays in a line.
func TestScrubLogLinePairLink(t *testing.T) {
	old := static.logLevel.Load()
	defer static.logLevel.Store(old)
	const link = "aHR0cHM6Ly9leGFtcGxlLm9yZy9zdWIvd2FycC10b2tlbg"
	for _, level := range []LogLevel{LogLevel_WARNING, LogLevel_DEBUG} {
		static.logLevel.Store(int32(level))
		for _, line := range []string{
			"profile-exits: v=1;cur=main;alt=warp;alt-url=" + link,
			`{"alt-url": "` + link + `"}`,
			"alt_url=" + link,
			"the other one is " + link + " now",
		} {
			got := scrubLogLine(line)
			if strings.Contains(got, link) || strings.Contains(got, "aHR0cHM6") {
				t.Fatalf("level %v: the link is left in %q", level, got)
			}
		}
	}
}
