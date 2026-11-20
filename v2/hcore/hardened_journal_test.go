package hcore

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/experimental/clashapi/trafficontrol"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"

	"github.com/hiddify/hiddify-core/v2/config"
	"github.com/hiddify/hiddify-core/v2/tiered"
)

// The block journal (journal.go, journal_watch.go): its lines, its ring, its report, and what it
// never holds. No engine runs: the checks go to a local HTTPS server (hardened_tiers_test.go), the
// connections are the traffic manager's records made by hand.

// journalTestDir points the journal at a new working directory, on, and puts everything back after.
func journalTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	savedPath, savedNow, savedProxies := sWorkingPath, journalNow, journalProxies.Load()
	reset := func() {
		journal.access.Lock()
		journal.closeLocked()
		journal.disabled, journal.failed, journal.path = false, time.Time{}, ""
		journal.access.Unlock()
	}
	reset()
	sWorkingPath = dir
	t.Cleanup(func() {
		reset() // the file closed before the directory goes (Windows)
		sWorkingPath, journalNow = savedPath, savedNow
		journalProxies.Store(savedProxies)
	})
	return dir
}

// journalEvents are the events of the journal's current file, each checked to be one JSON object.
func journalEvents(t *testing.T, dir string) (string, []map[string]any) {
	t.Helper()
	content, err := os.ReadFile(journalPath(dir))
	require.NoError(t, err)
	var events []map[string]any
	for _, line := range strings.Split(strings.TrimSuffix(string(content), "\n"), "\n") {
		var event map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &event), line)
		events = append(events, event)
	}
	return string(content), events
}

func eventsOf(events []map[string]any, kind string) []map[string]any {
	var found []map[string]any
	for _, event := range events {
		if event["ev"] == kind {
			found = append(found, event)
		}
	}
	return found
}

func TestJournalLineFormat(t *testing.T) {
	at := time.Date(2026, 11, 18, 13, 1, 22, 987654321, time.FixedZone("UTC+3", 3*3600))
	line := journalLine(at, "check", []any{
		"tag", "2 gRPC", "srv", "192.0.2.10/32", "sni", "", "n", 3, "n32", int32(-1), "n64", int64(1) << 40,
		"u32", uint32(7), "ok", true, "ms", 1500 * time.Millisecond, "ratio", 1.5, "", "no key", 42, "a number for a key", "alone",
	})
	// UTC to the second; an empty text, a value of another type, a pair without a key and a key
	// without a value are left out; a duration is in milliseconds
	require.Equal(t, `{"t":"2026-11-18T10:01:22Z","ev":"check","tag":"2 gRPC","srv":"192.0.2.10/32","n":3,"n32":-1,`+
		`"n64":1099511627776,"u32":7,"ok":true,"ms":1500}`+"\n", string(line))

	quoted := journalLine(at, "proxy", []any{"tag", `say "hi" \ there`})
	require.True(t, json.Valid(bytes.TrimSpace(quoted)), string(quoted))

	for in, want := range map[string]string{
		"2 gRPC vless://0a1b2c3d-1111-2222-3333-444455556666@192.0.2.10:443?security=reality#x": "2 gRPC <link>",
		"user 0a1b2c3d-1111-2222-3333-444455556666":                                             "user <uuid>",
		"9 HTTP3 password=hunter2 extra":                                                        "9 HTTP3 password=<redacted> extra",
		"from https://sub.example.net/sub/abc/def?token=12345 on":                               "from https://<url> on",
		"owner me@example.com":                                                                  "owner <email>",
		"two\nlines\tand a tab":                                                                 "two lines and a tab",
		"  padded  ":                                                                            "padded",
		// the servers stay: they are what the journal is for
		"192.0.2.10/32":   "192.0.2.10/32",
		"vpn.example.net": "vpn.example.net",
	} {
		require.Equal(t, want, journalText(in), in)
	}
	long := journalText(strings.Repeat("я", 200))
	require.Equal(t, journalTextMax, utf8.RuneCountInString(long))
}

// The journal is a ring: journal.jsonl moves to .1 (and on) at about 1 MB, four of them are kept,
// the oldest lines go, no line is torn or lost between the files; a clear starts it again.
func TestJournalRingBySize(t *testing.T) {
	dir := journalTestDir(t)
	pad := strings.Repeat("x", 150)
	written := 0
	for ; written < 50000; written++ {
		journalWrite("fill", "n", written, "pad", pad)
	}

	files := journalFiles(dir)
	base := journalPath(dir)
	require.Equal(t, []string{base + ".4", base + ".3", base + ".2", base + ".1", base}, files)
	require.NoFileExists(t, base+".5")
	var total int64
	for _, path := range files {
		info, err := os.Stat(path)
		require.NoError(t, err)
		require.LessOrEqual(t, info.Size(), int64(journalFileSize), path)
		total += info.Size()
	}
	require.LessOrEqual(t, total, int64((journalBackups+1)*journalFileSize))
	require.Greater(t, total, int64(journalBackups*journalFileSize))
	require.Equal(t, total, journalSize(dir))

	next := -1
	for _, path := range files {
		content, err := os.ReadFile(path)
		require.NoError(t, err)
		for _, line := range strings.Split(strings.TrimSuffix(string(content), "\n"), "\n") {
			var event struct {
				Ev string `json:"ev"`
				N  int    `json:"n"`
			}
			require.NoError(t, json.Unmarshal([]byte(line), &event), "a torn line in %s", path)
			if next >= 0 {
				require.Equal(t, next, event.N, "a line lost before it in %s", path)
			} else {
				require.Greater(t, event.N, 0, "the oldest lines are gone")
			}
			next = event.N + 1
		}
	}
	require.Equal(t, written, next, "the newest line is the last of journal.jsonl")

	require.NoError(t, clearJournal(dir))
	require.Empty(t, journalFiles(dir))
	require.Zero(t, journalSize(dir))
	journalWrite("after")
	_, events := journalEvents(t, dir)
	require.Len(t, events, 1)
	require.Equal(t, "after", events[0]["ev"])
}

// The setting block-journal (on unless false) stops the writing, and the report says so.
func TestJournalSetting(t *testing.T) {
	dir := journalTestDir(t)
	savedOptions, savedLevel := static.HiddifyOptions, static.logLevel.Load()
	t.Cleanup(func() { static.HiddifyOptions = savedOptions; static.logLevel.Store(savedLevel) })

	for _, c := range []struct {
		settings string
		on       bool
	}{
		{`{"block-journal": false}`, false},
		{`{"block-journal": true}`, true},
		{`{"log-level": "warn"}`, true},
		{`{"block-journal": false}`, false},
	} {
		_, err := ChangeHiddifySettings(&ChangeHiddifySettingsRequest{HiddifySettingsJson: c.settings}, false)
		require.NoError(t, err)
		require.Equal(t, c.on, journalEnabled(), c.settings)
	}
	journalWrite("start")
	require.NoFileExists(t, journalPath(dir))
	response, err := blockJournal(dir, t.TempDir(), &BlockJournalRequest{})
	require.NoError(t, err)
	require.False(t, response.Enabled)
	require.Zero(t, response.Size)

	setJournalEnabled(true)
	journalWrite("start")
	_, events := journalEvents(t, dir)
	require.Len(t, events, 1)
}

// gatedDialer dials as a proxy outbound does: the TCP connect to its server through
// tls.DialForHandshake (where a dial's trace sees it), then its own handshake, which fails with
// handshakeErr when set.
type gatedDialer struct {
	inner        N.Dialer
	handshakeErr error
}

func (d gatedDialer) DialContext(ctx context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := tls.DialForHandshake(ctx, d.inner, destination)
	if err != nil {
		return nil, err
	}
	if d.handshakeErr != nil {
		conn.Close()
		return nil, d.handshakeErr
	}
	return conn, nil
}

func (d gatedDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

type failingDialer struct{ err error }

func (d failingDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, d.err
}

func (d failingDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, d.err
}

// secret* are what the user and the subscription hold: none of it may reach the journal.
const (
	secretSite  = "secret-site.example.org"
	secretIP    = "198.51.100.77"
	secretLocal = "198.51.100.5"
	secretUUID  = "0a1b2c3d-1111-2222-3333-444455556666"
	secretToken = "token-secret-xyz"
	secretPass  = "hunter2"
	subHost     = "example.com" // the subscription's host: the test server's certificate is for it
)

var subPath = "/sub/" + secretUUID + "/" + secretToken

func journalTestProxies() map[string]config.JournalProxy {
	return map[string]config.JournalProxy{
		"2 gRPC":                                      {Server: "192.0.2.10/32", Protocol: "vless", Transport: "grpc+tls", ServerName: "vpn.example.net"},
		"5 Naive " + secretUUID:                       {Server: "192.0.2.10/32", Protocol: "naive", Transport: "h2+tls", ServerName: "vpn.example.net"},
		"9 HTTP3 password=" + secretPass:              {Server: "192.0.2.10/32", Protocol: "vless", Transport: "xhttp-h3+tls"},
		"vless://" + secretUUID + "@192.0.2.11:443#7": {Server: "192.0.2.11/32", Protocol: "vless", Transport: "tcp+reality", ServerName: "www.example.org"},
	}
}

// checkThrough runs the transfer check of tag through dialer, with the trace the controller's
// checks carry.
func checkThrough(tag string, dialer N.Dialer) tiered.CheckResult {
	ctx := withCheckTrace(context.Background(), &checkTrace{tag: tag, kind: "transfer"})
	r, _ := transferCheck(ctx, dialer, subHost, subPath)
	return r
}

// A check tells the stage it reached: the TCP connect to the server, the proxy's own handshake, the
// dial without a connect of its own, then TLS, HTTP and the body inside the tunnel.
func TestJournalCheckStages(t *testing.T) {
	dir := journalTestDir(t)
	proxies := journalTestProxies()
	journalProxies.Store(&proxies)

	ok := tierTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "65536")
		w.WriteHeader(http.StatusPartialContent)
		w.Write(make([]byte, 65536))
	})
	require.Equal(t, tiered.OK, checkThrough("2 gRPC", gatedDialer{inner: ok}).Outcome)
	require.Equal(t, tiered.NoConnect, checkThrough("2 gRPC", gatedDialer{
		inner: failingDialer{errors.New("dial tcp " + secretIP + ":443: connectex: the target machine actively refused it")},
	}).Outcome)
	require.Equal(t, tiered.NoConnect, checkThrough("2 gRPC", gatedDialer{
		inner: ok, handshakeErr: errors.New("tls: handshake failure with " + secretSite),
	}).Outcome)
	require.Equal(t, tiered.NoConnect, checkThrough("9 HTTP3 password="+secretPass, failingDialer{context.DeadlineExceeded}).Outcome)

	missing := tierTestServer(t, func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	require.Equal(t, tiered.NoConnect, checkThrough("2 gRPC", gatedDialer{inner: missing}).Outcome)

	_, events := journalEvents(t, dir)
	checks := eventsOf(events, "check")
	require.Len(t, checks, 5)
	for i, want := range []map[string]any{
		{"stage": "body", "out": "ok", "rx": float64(65536), "code": float64(206)},
		{"stage": "tcp", "out": "noconnect", "err": "refused"},
		{"stage": "handshake", "out": "noconnect", "err": "tls"},
		{"stage": "connect", "out": "noconnect", "err": "timeout"},
		{"stage": "http", "out": "noconnect", "code": float64(404)},
	} {
		for key, value := range want {
			require.Equal(t, value, checks[i][key], "check %d: %s in %v", i, key, checks[i])
		}
		require.Equal(t, "transfer", checks[i]["kind"])
		require.Contains(t, checks[i], "ms")
	}
	require.Equal(t, "192.0.2.10/32", checks[0]["srv"])
	require.Equal(t, "grpc+tls", checks[0]["tr"])
	require.Contains(t, checks[0], "tcp_ms", "a connect made is timed")
	require.NotContains(t, checks[1], "tcp_ms", "a connect that failed is not")
}

// The privacy rule of the journal: whatever the connections, the checks, the errors, the proxies'
// names and the choices carry, the destinations the user visits, the user's ID, the subscription's
// link and path, and passwords never reach it; the servers do.
func TestJournalKeepsDestinationsOut(t *testing.T) {
	dir := journalTestDir(t)
	proxies := journalTestProxies()
	journalStart(proxies, nil)
	journalProxies.Store(&proxies)

	// checks whose dial errors and URL name a destination
	ok := tierTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "65536")
		w.WriteHeader(http.StatusPartialContent)
		w.Write(make([]byte, 65536))
	})
	checkThrough("2 gRPC", gatedDialer{inner: ok})
	checkThrough("5 Naive "+secretUUID, gatedDialer{inner: failingDialer{errors.New("dial " + secretSite + " (" + secretIP + "): connection reset by peer")}})
	urlTestCheck(withCheckTrace(context.Background(), &checkTrace{tag: "2 gRPC", kind: "urltest"}), ok, "https://"+secretSite+"/generate_204?"+secretToken)

	// connections through the proxies to a destination, and one that does not go through a proxy
	now := time.Now()
	conn := func(outbound string, network string, life time.Duration, up, down int64) *trafficontrol.TrackerMetadata {
		upload, download := &atomic.Int64{}, &atomic.Int64{}
		upload.Store(up)
		download.Store(down)
		return &trafficontrol.TrackerMetadata{
			ID: uuid.Must(uuid.NewV4()),
			Metadata: adapter.InboundContext{
				Network: network, Source: M.ParseSocksaddr(secretLocal + ":50000"), Destination: M.ParseSocksaddr(secretIP + ":443"),
				Domain: secretSite,
			},
			CreatedAt: now.Add(-life), ClosedAt: now, Upload: upload, Download: download,
			Chain: []string{outbound, config.OutboundTieredTag, config.OutboundSelectTag}, Outbound: outbound,
		}
	}
	watch := &connWatch{since: now.Add(-time.Hour)}
	watch.observe([]*trafficontrol.TrackerMetadata{
		conn("2 gRPC", N.NetworkTCP, 2*time.Minute, 1000, 5<<20),
		conn("5 Naive "+secretUUID, N.NetworkTCP, 3*time.Second, 517, 0),
		conn("9 HTTP3 password="+secretPass, N.NetworkUDP, time.Second, 0, 0),
		conn(config.OutboundDirectTag, N.NetworkTCP, time.Minute, 100, 0),
	}, &proxies)
	watch.flush()

	// the choices, the path's check (its stage's detail names a destination), a passive look
	journalNote(tiered.Note{Kind: tiered.NoteUse, Tag: "2 gRPC", Server: "192.0.2.10/32", Tier: 1, Mode: "auto", From: "5 Naive " + secretUUID, Why: "walk"})
	journalNote(tiered.Note{Kind: tiered.NoteAsk, Tag: "vless://" + secretUUID + "@192.0.2.11:443#7", Wait: time.Minute})
	journalPathCheck("2 gRPC", &DpiProbeRequest{Host: "192.0.2.10", ServerName: "vpn.example.net", Path: subPath},
		&DpiProbeResponse{Outcome: "blocked", Stages: []*DpiProbeStage{{Name: "tcp", Outcome: "timeout", Millis: 5000, Detail: "dial " + secretSite + " " + secretIP}}},
		tiered.PathBlocked)

	content, events := journalEvents(t, dir)
	for _, secret := range []string{secretSite, secretIP, secretLocal, secretUUID, secretToken, secretPass, subHost, "/sub/", "vless://", "generate_204"} {
		require.NotContains(t, content, secret)
	}
	for _, kind := range []string{"start", "proxy", "check", "conn", "conns", "use", "ask", "path"} {
		require.NotEmpty(t, eventsOf(events, kind), "no %s event", kind)
	}
	require.Contains(t, content, `"srv":"192.0.2.10/32"`)
	require.Contains(t, content, `"sni":"vpn.example.net"`)
	require.Contains(t, content, `"tag":"5 Naive <uuid>"`)
	require.Contains(t, content, `"tag":"<link>"`)

	// the connections: through the proxies only, with the reason each is told
	lines := eventsOf(events, "conn")
	require.Len(t, lines, 3)
	whys := map[string]string{}
	for _, line := range lines {
		whys[line["tag"].(string)] = line["why"].(string)
		require.Contains(t, line, "life_s")
		require.Contains(t, line, "open")
	}
	require.Equal(t, map[string]string{"2 gRPC": "long", "5 Naive <uuid>": "noreply", "9 HTTP3 password=<redacted>": "empty"}, whys)
	require.Len(t, eventsOf(events, "conns"), 3, "a line of sums for each proxy, none for direct")
}

// A closed connection is counted once, whichever look sees it first; past journalConnLines a
// minute it is only in the sums.
func TestJournalConnWatchCountsOnce(t *testing.T) {
	dir := journalTestDir(t)
	proxies := map[string]config.JournalProxy{"2 gRPC": {Server: "192.0.2.10/32", Transport: "grpc+tls"}}
	journalProxies.Store(&proxies)
	start := time.Now()
	closed := func(at time.Time, down int64) *trafficontrol.TrackerMetadata {
		upload, download := &atomic.Int64{}, &atomic.Int64{}
		upload.Store(100)
		download.Store(down)
		return &trafficontrol.TrackerMetadata{ID: uuid.Must(uuid.NewV4()), CreatedAt: at.Add(-time.Second), ClosedAt: at,
			Upload: upload, Download: download, Outbound: "2 gRPC"}
	}
	var list []*trafficontrol.TrackerMetadata
	for i := 0; i < journalConnLines+10; i++ {
		list = append(list, closed(start.Add(time.Duration(i)*time.Millisecond), 0)) // got nothing back
	}
	sameTime := closed(start.Add(time.Second), 4096)
	list = append(list, sameTime)
	watch := &connWatch{since: start.Add(-time.Second)}
	watch.observe(list, &proxies)
	// the next look sees the same list and one more closed in the same instant as the last
	late := closed(start.Add(time.Second), 0)
	watch.observe(append(list, late), &proxies)
	watch.flush()

	_, events := journalEvents(t, dir)
	require.Len(t, eventsOf(events, "conn"), journalConnLines)
	sums := eventsOf(events, "conns")
	require.Len(t, sums, 1)
	require.Equal(t, float64(journalConnLines+12), sums[0]["n"])
	require.Equal(t, float64(journalConnLines+11), sums[0]["noreply"])
	require.Equal(t, float64(11), sums[0]["not_shown"])
	require.Equal(t, float64(4096), sums[0]["down"])
}

func zipContents(t *testing.T, content []byte) map[string]string {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	require.NoError(t, err)
	files := map[string]string{}
	for _, file := range reader.File {
		if strings.HasSuffix(file.Name, "/") {
			continue
		}
		r, err := file.Open()
		require.NoError(t, err)
		data, err := io.ReadAll(r)
		r.Close()
		require.NoError(t, err)
		files[file.Name[strings.Index(file.Name, "/")+1:]] = string(data)
	}
	return files
}

// The report: the journal as it is (the servers' addresses kept), its sums a line each, box.log
// and the app's files scrubbed as in the diagnostics, another core's report kept; read back
// inline, no copy stays in the temp directory.
func TestBlockJournalReport(t *testing.T) {
	dir := journalTestDir(t)
	temp := t.TempDir()
	journalNow = func() time.Time { return time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC) }
	journalWrite("check", "tag", "2 gRPC", "srv", "192.0.2.10/32", "stage", "tcp", "out", "noconnect")
	journalWrite("check", "tag", "2 gRPC", "srv", "192.0.2.10/32", "stage", "body", "out", "ok")
	journalWrite("check", "tag", "9 HTTP3", "srv", "192.0.2.10/32", "stage", "body", "out", "slow")
	journalWrite("use", "tag", "2 gRPC", "srv", "192.0.2.10/32")
	journalWrite("gate", "srv", "192.0.2.10/32", "turns", 4, "hellos", 4, "waited", 2, "wait_max_ms", 900*time.Millisecond, "window", 1)
	journalWrite("gate", "srv", "192.0.2.11/32", "turns", 1, "hellos", 1)
	journalWrite("tcp_out", "tag", "2 gRPC", "srv", "192.0.2.10/32")
	journalWrite("net", "net", "0a1b2c3d", "kind", "cellular", "online", true)
	writeTestFile(t, filepath.Join(dir, "data", "box.log"), "ERROR outbound/vless[2 gRPC]: dial "+secretSite+" via "+secretIP+":443 vless://"+secretUUID+"@192.0.2.10:443\n")
	writeTestFile(t, filepath.Join(dir, "data", "box.log.1"), "INFO older to "+secretIP+"\n")

	response, err := blockJournal(dir, temp, &BlockJournalRequest{
		Export: true, Inline: true,
		ExtraFiles: map[string][]byte{
			"app.log":             []byte("WARNING core: tiers: using 2 gRPC; a link https://" + subHost + subPath + "\n"),
			"../../elsewhere.bin": []byte("from " + secretIP),
			"service-core.zip":    []byte("PK\x03\x04 another core's report"),
		},
	})
	require.NoError(t, err)
	require.True(t, response.Enabled)
	require.Empty(t, response.Path, "read back inline: no path")
	entries, err := os.ReadDir(temp)
	require.NoError(t, err)
	require.Empty(t, entries, "no copy left in the temp directory")
	require.Equal(t, journalSize(dir), response.Size)

	files := zipContents(t, response.Content)
	require.Contains(t, files, "README.txt")
	journalFile := files["journal/journal.jsonl"]
	require.Contains(t, journalFile, `"srv":"192.0.2.10/32"`, "the journal as it is")
	require.Contains(t, journalFile, `"t":"2026-11-18T10:00:00Z"`)

	box := files["logs/box.log"] + files["logs/box.1.log"]
	require.Contains(t, box, "<ipv4>")
	for _, secret := range []string{secretSite, secretIP, secretUUID} {
		require.NotContains(t, box, secret)
	}
	require.NotContains(t, files["app/app.log"], secretToken)
	require.NotContains(t, files["app/app.log"], subHost)
	require.Equal(t, "from <ipv4>", files["app/elsewhere.bin.txt"], "a file of another kind is scrubbed as text, by its base name")
	require.Equal(t, "PK\x03\x04 another core's report", files["app/service-core.zip"])

	var summary []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(files["summary.jsonl"]), "\n") {
		var item map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &item), line)
		summary = append(summary, item)
	}
	require.Len(t, summary, 5, "the whole, two proxies, two servers")
	require.Equal(t, "2026-11-18T10:00:00Z", summary[0]["from"])
	require.Equal(t, map[string]any{"0a1b2c3d": "cellular"}, summary[0]["networks"])
	require.Equal(t, "2 gRPC", summary[1]["proxy"])
	require.Equal(t, map[string]any{"noconnect": float64(1), "ok": float64(1)}, summary[1]["checks"])
	require.Equal(t, map[string]any{"tcp": float64(1)}, summary[1]["failed_at"])
	require.Equal(t, float64(1), summary[1]["chosen"])
	require.Equal(t, "9 HTTP3", summary[2]["proxy"])
	require.Equal(t, "192.0.2.10/32", summary[3]["server"], "the servers' addresses kept")
	require.Equal(t, float64(4), summary[3]["turns"])
	require.Equal(t, float64(900), summary[3]["wait_max_ms"])
	require.Equal(t, float64(1), summary[3]["tcp_out"])
	require.Equal(t, "192.0.2.11/32", summary[4]["server"])

	// a clear empties it; the report then has no journal
	response, err = blockJournal(dir, temp, &BlockJournalRequest{Clear: true})
	require.NoError(t, err)
	require.Zero(t, response.Size)
	require.Empty(t, journalFiles(dir))

	// written where asked: the path is answered and the file stays
	destination := filepath.Join(temp, "report.zip")
	response, err = blockJournal(dir, temp, &BlockJournalRequest{Export: true, DestinationPath: destination})
	require.NoError(t, err)
	require.Equal(t, destination, response.Path)
	require.FileExists(t, destination)
	require.Empty(t, response.Content)
}

func TestErrClass(t *testing.T) {
	for want, err := range map[string]error{
		"":            nil,
		"timeout":     context.DeadlineExceeded,
		"canceled":    context.Canceled,
		"eof":         io.ErrUnexpectedEOF,
		"reset":       errors.New("read tcp: connection reset by peer"),
		"refused":     errors.New("dial tcp: connection refused"),
		"unreachable": errors.New("dial tcp: network is unreachable"),
		"cert":        errors.New("x509: certificate signed by unknown authority"),
		"tls":         errors.New("remote error: tls: handshake failure"),
		"closed":      net.ErrClosed,
		"other":       errors.New("something " + strconv.Itoa(42)),
	} {
		require.Equal(t, want, errClass(err), "%v", err)
	}
}

// The start line says which way out to the internet the profile is on (the app's pair of
// subscriptions), and only main or warp: nothing for a profile without a pair or any other text.
func TestJournalStartSaysTheWayOut(t *testing.T) {
	dir := journalTestDir(t)
	saved := static.HiddifyOptions
	t.Cleanup(func() { static.HiddifyOptions = saved })
	for _, c := range []struct{ choice, want string }{
		{"main", "main"},
		{"warp", "warp"},
		{"", ""},
		{"https://example.org/sub/token", ""},
		{"psiphon", ""},
	} {
		static.HiddifyOptions = &config.HiddifyOptions{ExitChoice: c.choice}
		journalStart(nil, nil)
	}
	static.HiddifyOptions = nil
	journalStart(nil, nil)
	_, events := journalEvents(t, dir)
	require.Len(t, events, 6)
	for i, want := range []string{"main", "warp", "", "", "", ""} {
		require.Equal(t, "start", events[i]["ev"], "%v", events[i])
		if want == "" {
			require.NotContains(t, events[i], "exit", "line %d", i)
		} else {
			require.Equal(t, want, events[i]["exit"], "line %d", i)
		}
	}
}
