package hcore

import (
	"regexp"
	"strings"
)

// The log lines the app shows, copies and sends to support, and box.log (log_file.go), are
// scrubbed (HC-15, D-10): secrets always; links, addresses and host names unless the user asked
// for the debug or trace level, whose lines are for a developer reading them on the device.
var (
	alwaysScrubbed = []struct {
		pattern *regexp.Regexp
		replace string
	}{
		{regexp.MustCompile(`(?i)\b(?:vless|vmess|trojan|ss|ssr|socks5?|hysteria2?|hy2|tuic|wireguard|wg|awg|warp|mieru|naive\+https|naive|anytls|shadowtls|sdns|ssh|sudoku|vpn)://[^\s"'<>]+`), "<link>"},
		{regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`), "<uuid>"},
		{regexp.MustCompile(`(?i)\b(password|passwd|token|auth[_-]?token|secret|private[_-]?key|preshared[_-]?key|header[_-]?protection[_-]?key|psk|public[_-]?key|short[_-]?id|uuid|lan-sharing-password|local-proxy-password|alt[_-]url)(["']?\s*[:=]\s*["']?)[^\s"',;&}]+`), "$1$2<redacted>"},
		// the other subscription of a profile's pair: its link in base64url, which starts the same for any https link
		{regexp.MustCompile(`\baHR0cHM6Ly[A-Za-z0-9_+/-]*=*`), "<link>"},
		// a WireGuard key (32 bytes in base64) or a 32-byte hex key on its own
		{regexp.MustCompile(`\b[A-Za-z0-9+/]{43}=`), "<key>"},
		{regexp.MustCompile(`(?i)\b[0-9a-f]{64}\b`), "<key>"},
	}
	addressScrubbed = []struct {
		pattern *regexp.Regexp
		replace string
	}{
		{regexp.MustCompile(`(?i)\b(https?|wss?)://([^/\s"'<>?#]+)[^\s"'<>]*`), "$1://<host>"},
		{regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`), "<ipv4>"},
		{regexp.MustCompile(`(?i)(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:)+:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?|::[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*`), "<ipv6>"},
	}
	// a host name on its own: a destination ("open connection to www.example.org:443"), a server
	// name (a REALITY mask's SNI in a handshake error), a DNS question. Lower case, as sing-box
	// writes them; a Go name (context.Canceled) or a file (box.log) is not one.
	hostName        = regexp.MustCompile(`\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24}|xn--[a-z0-9-]{1,59})\b`)
	notHostSuffixes = map[string]bool{
		"log": true, "txt": true, "json": true, "db": true, "srs": true, "go": true, "aar": true, "so": true,
		"yaml": true, "yml": true, "conf": true, "pem": true, "crt": true, "key": true, "sock": true,
		"tmp": true, "zip": true, "exe": true, "dll": true, "gz": true, "md": true, "proto": true,
	}
)

// scrubHostNames replaces the host names in message by <host>.
func scrubHostNames(message string) string {
	return hostName.ReplaceAllStringFunc(message, func(name string) string {
		if notHostSuffixes[name[strings.LastIndexByte(name, '.')+1:]] {
			return name
		}
		return "<host>"
	})
}

// scrubLogLine removes secrets from a log line, and the addresses too unless the configured log
// level is debug or trace.
func scrubLogLine(message string) string {
	for _, rule := range alwaysScrubbed {
		message = rule.pattern.ReplaceAllString(message, rule.replace)
	}
	if LogLevel(static.logLevel.Load()) <= LogLevel_DEBUG {
		return message
	}
	for _, rule := range addressScrubbed {
		message = rule.pattern.ReplaceAllString(message, rule.replace)
	}
	return scrubHostNames(message)
}
