package hcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/sagernet/sing-box/experimental/libbox"
	E "github.com/sagernet/sing/common/exceptions"
)

// The block journal: what stopped getting through, and how, for a look back when a server or a
// protocol gets blocked. It answers "which proxy, to which server, over what, at which stage, after
// how many bytes, handshakes and seconds, in which network", never "where did the user go".
//
// It is a ring of JSON lines in data/diag of the core's working directory (journal.jsonl, moved to
// journal.jsonl.1 and on at journalFileSize, journalBackups kept: about 5 MB in all), one event a
// line, its time in UTC to the second:
//
//	{"t":"2026-11-18T10:01:22Z","ev":"check","tag":"2 gRPC","srv":"192.0.2.10/32",...}
//
// The events (journal_watch.go writes them):
//   - start, proxy, stop: a config starts (the core's version, the tiered group) with each proxy's
//     server, protocol, transport, name in TLS and tier; the config ends.
//   - check: a check through a proxy (the tiered controller's): kind (transfer, neutral, urltest),
//     stage it reached (tcp, handshake, connect, tls, http, body), outcome, time, bytes received,
//     error class, the wait in the handshake gate and the TCP connect.
//   - path: a check of the path to a proxy's server outside the tunnel (DpiProbe): outcome, verdict,
//     stages.
//   - the controller's decisions (tiered.Note): walk, mark, tcp_out, use, active_failed, ask, agree,
//     none, offline, idle, select_failed, up_failed.
//   - net: the default network changed: its kind (wifi, cellular, ethernet, other), its hash (the
//     tiered controller's network id, never the Wi-Fi name), online or not. Not the operator: the
//     platform does not tell the core.
//   - passive: the connections through the proxy in use got nothing back (the passive watch).
//   - conn: a connection through a proxy closed that says something (nothing came back, long,
//     large): its proxy, network, life, bytes each way and why it counts; conns: each proxy's
//     connections of the minute in sums; open: the connections still open when the config ends.
//   - gate: what the handshake gate did to each server in the minute (turns, waits, ClientHellos,
//     failed connects).
//
// Never written: the addresses and names the apps connect to, DNS questions, user IDs, links,
// passwords or keys. Only fields this file names go in; the text ones (proxy tags, servers, names in
// TLS) are cut to a length and scrubbed of links, UUIDs and secrets on the way. The journal is
// written while the block-journal setting is on (on unless false); a clear empties it.
const (
	journalDirName  = "diag"
	journalFileName = "journal.jsonl"
	journalFileSize = 1 << 20
	journalBackups  = 4
	journalTextMax  = 160
)

type journalState struct {
	access   sync.Mutex
	disabled bool // the block-journal setting is off
	file     *rotatingLog
	path     string
	failed   time.Time // when the file could not be opened last; tried again a minute later
}

var journal journalState

// journalNow is the journal's clock (tests).
var journalNow = time.Now

// journalPath is the journal's file in workingPath.
func journalPath(workingPath string) string {
	return filepath.Join(workingPath, "data", journalDirName, journalFileName)
}

// setJournalEnabled follows the block-journal setting: off closes the file and writes nothing more.
func setJournalEnabled(on bool) {
	journal.access.Lock()
	defer journal.access.Unlock()
	journal.disabled = !on
	if !on {
		journal.closeLocked()
	}
}

func journalEnabled() bool {
	journal.access.Lock()
	defer journal.access.Unlock()
	return !journal.disabled
}

// closeLocked closes the file; journal.access must be held.
func (j *journalState) closeLocked() {
	if j.file != nil {
		j.file.Close()
		j.file = nil
	}
}

// journalWrite writes an event of kind with fields, pairs of a key and its value in the order given:
// a string (scrubbed and cut, left out when empty), a bool, an integer, a time.Duration (as
// milliseconds). Nothing when the journal is off or the core has no working directory.
func journalWrite(kind string, fields ...any) {
	line := journalLine(journalNow(), kind, fields)
	journal.access.Lock()
	defer journal.access.Unlock()
	if journal.disabled || sWorkingPath == "" {
		return
	}
	path := journalPath(sWorkingPath)
	if journal.file != nil && journal.path != path {
		journal.closeLocked()
	}
	if journal.file == nil {
		if !journal.failed.IsZero() && time.Since(journal.failed) < time.Minute {
			return
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			journal.failed = time.Now()
			return
		}
		file, err := openRotatingLog(path, journalFileSize, journalBackups, nil)
		if err != nil {
			journal.failed = time.Now()
			return
		}
		journal.file, journal.path, journal.failed = file, path, time.Time{}
	}
	if _, err := journal.file.Write(line); err != nil {
		// a full disk, a file deleted under it: opened again a minute later
		journal.closeLocked()
		journal.failed = time.Now()
	}
}

// journalLine is one event as a line of JSON.
func journalLine(at time.Time, kind string, fields []any) []byte {
	var b bytes.Buffer
	b.WriteString(`{"t":"`)
	b.WriteString(at.UTC().Format("2006-01-02T15:04:05Z"))
	b.WriteString(`","ev":`)
	writeJournalString(&b, kind)
	for i := 0; i+1 < len(fields); i += 2 {
		key, _ := fields[i].(string)
		if key == "" {
			continue
		}
		var value []byte
		switch v := fields[i+1].(type) {
		case string:
			v = journalText(v)
			if v == "" {
				continue
			}
			var s bytes.Buffer
			writeJournalString(&s, v)
			value = s.Bytes()
		case bool:
			value = []byte(strconv.FormatBool(v))
		case int:
			value = []byte(strconv.Itoa(v))
		case int32:
			value = []byte(strconv.FormatInt(int64(v), 10))
		case int64:
			value = []byte(strconv.FormatInt(v, 10))
		case uint32:
			value = []byte(strconv.FormatUint(uint64(v), 10))
		case time.Duration:
			value = []byte(strconv.FormatInt(v.Milliseconds(), 10))
		default:
			continue // anything else is not written
		}
		b.WriteByte(',')
		writeJournalString(&b, key)
		b.WriteByte(':')
		b.Write(value)
	}
	b.WriteString("}\n")
	return b.Bytes()
}

// writeJournalString writes s as a JSON string; <uuid> stays <uuid>, not <uuid>, which
// encoding/json writes by default for HTML: the journal is read and searched as text.
func writeJournalString(b *bytes.Buffer, s string) {
	encoder := json.NewEncoder(b)
	encoder.SetEscapeHTML(false)
	encoder.Encode(s)
	b.Truncate(b.Len() - 1) // the newline Encode ends with
}

// journalEmail is an email address, which no field of the journal should hold.
var journalEmail = regexp.MustCompile(`(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b`)

// journalURL is a URL, whose host, path and query (a subscription's, with its token) no field of
// the journal should hold.
var journalURL = regexp.MustCompile(`(?i)\b(https?|wss?)://[^\s"'<>]+`)

// journalText is a text field as it is written: links, UUIDs, keys, key=value secrets (scrubLogLine's
// rules that hold at every level), URLs and emails scrubbed, at most journalTextMax characters.
// Addresses and names stay: the fields that hold them hold the proxies' servers.
func journalText(s string) string {
	// the URL first: a token in its query would else be cut short by the key=value rule
	s = journalURL.ReplaceAllString(s, "$1://<url>")
	for _, rule := range alwaysScrubbed {
		s = rule.pattern.ReplaceAllString(s, rule.replace)
	}
	s = journalEmail.ReplaceAllString(s, "<email>")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if utf8.RuneCountInString(s) > journalTextMax {
		s = string([]rune(s)[:journalTextMax])
	}
	return strings.TrimSpace(s)
}

// journalSize is the bytes the journal's files hold in workingPath.
func journalSize(workingPath string) int64 {
	var size int64
	for _, path := range journalFiles(workingPath) {
		if info, err := os.Stat(path); err == nil {
			size += info.Size()
		}
	}
	return size
}

// journalFiles are the journal's files in workingPath, the oldest first.
func journalFiles(workingPath string) []string {
	base := journalPath(workingPath)
	var files []string
	for i := journalBackups + 2; i >= 1; i-- { // a backup past the limit, left by another build, too
		path := base + "." + strconv.Itoa(i)
		if _, err := os.Stat(path); err == nil {
			files = append(files, path)
		}
	}
	if _, err := os.Stat(base); err == nil {
		files = append(files, base)
	}
	return files
}

// clearJournal deletes the journal's files in workingPath; the journal goes on from empty.
func clearJournal(workingPath string) error {
	journal.access.Lock()
	defer journal.access.Unlock()
	if journal.path == journalPath(workingPath) {
		journal.closeLocked()
	}
	var errs []error
	for _, path := range journalFiles(workingPath) {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (s *CoreService) BlockJournal(ctx context.Context, req *BlockJournalRequest) (*BlockJournalResponse, error) {
	return blockJournal(sWorkingPath, sTempPath, req)
}

// blockJournal answers BlockJournal for the core in workingPath.
func blockJournal(workingPath, tempPath string, req *BlockJournalRequest) (*BlockJournalResponse, error) {
	if workingPath == "" {
		return nil, E.New("the core is not set up")
	}
	if req.GetClear() {
		if err := clearJournal(workingPath); err != nil {
			return nil, E.Cause(err, "clear the journal")
		}
	}
	response := &BlockJournalResponse{Enabled: journalEnabled()}
	if req.GetExport() {
		path, err := exportBlockJournal(workingPath, tempPath, req)
		if err != nil {
			return nil, err
		}
		response.Path = path
		if req.GetInline() {
			response.Content, err = os.ReadFile(path)
			if req.GetDestinationPath() == "" {
				// read back by the caller: no copy stays in the temp directory (of a privileged
				// core, too)
				os.Remove(path)
				response.Path = ""
			}
			if err != nil {
				return nil, E.Cause(err, "read the report")
			}
		}
	}
	response.Size = journalSize(workingPath)
	return response, nil
}

// exportBlockJournal writes the block report and answers its path:
//
//	net-report-<time>/
//	  README.txt     what is in it and how to read the journal
//	  summary.jsonl  the journal in sums, a line each: its time span, the events and networks;
//	                 each proxy's checks by outcome, where they failed, its last good one; each
//	                 server's handshakes
//	  journal/       the journal's files as they are (they hold no user data)
//	  logs/          box.log, scrubbed as the diagnostics' logs are
//	  app/           the request's files (app.log, another core's report), text scrubbed
//
// Text files (.log, .txt, .json) are scrubbed of addresses, links and secrets as they are zipped
// (libbox.CreateZipArchive, as in ExportDiagnostics). The journal and its summary keep names it
// leaves as they are (.jsonl, .jsonl.N): their servers' addresses are what a block report is
// for, and they hold nothing else of the kind. A file of the request with another name is
// scrubbed under a .txt one; a .zip (another core's report, made by this function) is kept.
func exportBlockJournal(workingPath, tempPath string, req *BlockJournalRequest) (string, error) {
	if tempPath == "" {
		tempPath = os.TempDir()
	}
	stamp := journalNow().UTC().Format("2006-01-02T15-04-05")
	staging := filepath.Join(tempPath, "net-report-"+stamp)
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return "", E.Cause(err, "create the report's directory")
	}
	defer os.RemoveAll(staging)

	journal.access.Lock()
	files := journalFiles(workingPath)
	for _, path := range files {
		copyLogTail(path, filepath.Join(staging, "journal", filepath.Base(path)))
	}
	journal.access.Unlock()
	var lines [][]byte
	for _, path := range files {
		if content, err := os.ReadFile(filepath.Join(staging, "journal", filepath.Base(path))); err == nil {
			lines = append(lines, bytes.Split(content, []byte("\n"))...)
		}
	}
	os.WriteFile(filepath.Join(staging, "summary.jsonl"), journalSummary(lines), 0o600)
	copyLogTail(filepath.Join(workingPath, "data", "box.log"), filepath.Join(staging, "logs", "box.log"))
	// box.log.1 would keep its name, which the zip does not scrub
	copyLogTail(filepath.Join(workingPath, "data", "box.log.1"), filepath.Join(staging, "logs", "box.1.log"))
	writeAppFiles(filepath.Join(staging, "app"), reportFileNames(req.GetExtraFiles()))
	os.WriteFile(filepath.Join(staging, "README.txt"), []byte(blockReportReadme), 0o600)

	destination := req.GetDestinationPath()
	if destination == "" {
		destination = filepath.Join(tempPath, "net-report-"+stamp+".zip")
	}
	if err := libbox.CreateZipArchive(staging, destination, false); err != nil {
		return "", E.Cause(err, "zip the report")
	}
	return destination, nil
}

// reportFileNames are files of a request as the report keeps them: by their base name, a text
// one under a name the zip scrubs (.log, .txt, .json; else .txt is added), a .zip as it is.
func reportFileNames(files map[string][]byte) map[string][]byte {
	if len(files) == 0 {
		return nil
	}
	named := make(map[string][]byte, len(files))
	for name, content := range files {
		name = filepath.Base(filepath.ToSlash(name))
		switch strings.ToLower(filepath.Ext(name)) {
		case ".log", ".txt", ".json", ".zip":
		default:
			name += ".txt"
		}
		named[name] = content
	}
	return named
}

const blockReportReadme = `What stopped getting through: a report of the network journal.

journal/journal.jsonl (and .1 to .4, older): one event a line, JSON, time in UTC to the second.
  start, proxy, stop  a config started (each proxy: server, protocol, transport, name in TLS,
                      tier); the config ended
  check               a check through a proxy: kind (transfer, neutral, urltest), stage reached
                      (tcp: the TCP connect to the server failed; handshake: connected, the
                      server's handshake did not end; connect: the dial through the proxy failed,
                      no TCP connect of its own seen; tls, http, body: inside the tunnel; request:
                      a URL test that got past the TCP connect), outcome, ms, bytes received,
                      error class, wait in the handshake gate, TCP connect ms
  path                the path to a proxy's server outside the tunnel: outcome, verdict, stages
  walk, mark, tcp_out, use, active_failed, ask, agree, none, offline, idle, select_failed,
  up_failed           the choices of the server's ranking, with the proxy and why
  passive             the connections through the proxy in use got nothing back
  net                 the network changed: kind, hash (never its name), online
  conn, conns, open   connections through the proxies: one that got nothing back, lasted long or
                      carried much; each proxy's sums of the minute; those open at the end
  gate                handshakes to each server in the minute: turns, waits, ClientHellos, failed
                      connects
summary.jsonl: the journal in sums, a line each for the whole, each proxy, each server.
logs/box.log, app/app.log: the logs, with addresses, links and secrets removed.
Not in it: the sites and addresses the apps connect to, DNS questions, user IDs, links, passwords.
`

// journalSummary sums the journal's lines, a JSON line each: the whole ({"from", "to", "events",
// "networks"}), then each proxy ({"proxy": tag, ...}) and each server ({"server": key, ...}), in
// order. It is what an automatic report would send (see the docs of the hardened fork).
func journalSummary(lines [][]byte) []byte {
	type proxySums struct {
		Checks   map[string]int `json:"checks"`
		Stages   map[string]int `json:"failed_at,omitempty"`
		LastOK   string         `json:"last_ok,omitempty"`
		LastFail string         `json:"last_fail,omitempty"`
		Used     int            `json:"chosen"`
		Conns    int            `json:"conns"`
		NoReply  int            `json:"conns_noreply"`
		Down     int64          `json:"bytes_down"`
	}
	type serverSums struct {
		Turns         int   `json:"turns"`
		Waited        int   `json:"waited"`
		Window        int   `json:"window"`
		Hellos        int   `json:"hellos"`
		ConnectFailed int   `json:"connect_failed"`
		TCPOut        int   `json:"tcp_out"`
		WaitMaxMs     int64 `json:"wait_max_ms"`
	}
	proxies := map[string]*proxySums{}
	servers := map[string]*serverSums{}
	networks := map[string]string{}
	events := map[string]int{}
	var first, last string
	proxy := func(tag string) *proxySums {
		if proxies[tag] == nil {
			proxies[tag] = &proxySums{Checks: map[string]int{}, Stages: map[string]int{}}
		}
		return proxies[tag]
	}
	server := func(key string) *serverSums {
		if servers[key] == nil {
			servers[key] = &serverSums{}
		}
		return servers[key]
	}
	for _, line := range lines {
		var e map[string]any
		if len(bytes.TrimSpace(line)) == 0 || json.Unmarshal(line, &e) != nil {
			continue
		}
		at, _ := e["t"].(string)
		kind, _ := e["ev"].(string)
		tag, _ := e["tag"].(string)
		srv, _ := e["srv"].(string)
		number := func(key string) int64 { v, _ := e[key].(float64); return int64(v) }
		if first == "" || at < first {
			first = at
		}
		if at > last {
			last = at
		}
		events[kind]++
		switch kind {
		case "check":
			out, _ := e["out"].(string)
			p := proxy(tag)
			p.Checks[out]++
			if out == "ok" || out == "slow" {
				p.LastOK = at
			} else {
				p.LastFail = at
				if stage, _ := e["stage"].(string); stage != "" {
					p.Stages[stage]++
				}
			}
		case "use":
			proxy(tag).Used++
		case "conns":
			p := proxy(tag)
			p.Conns += int(number("n"))
			p.NoReply += int(number("noreply"))
			p.Down += number("down")
		case "gate":
			s := server(srv)
			s.Turns += int(number("turns"))
			s.Waited += int(number("waited"))
			s.Window += int(number("window"))
			s.Hellos += int(number("hellos"))
			s.ConnectFailed += int(number("connect_failed"))
			s.WaitMaxMs = max(s.WaitMaxMs, number("wait_max_ms"))
		case "tcp_out":
			server(srv).TCPOut++
		case "net":
			id, _ := e["net"].(string)
			kind, _ := e["kind"].(string)
			if id != "" {
				networks[id] = kind
			}
		}
	}
	var out bytes.Buffer
	line := func(value any) {
		encoded, _ := json.Marshal(value)
		out.Write(encoded)
		out.WriteByte('\n')
	}
	line(map[string]any{"from": first, "to": last, "events": events, "networks": networks})
	for _, tag := range sortedKeys(proxies) {
		p := proxies[tag]
		if len(p.Stages) == 0 {
			p.Stages = nil
		}
		line(struct {
			Proxy string `json:"proxy"`
			*proxySums
		}{tag, p})
	}
	for _, key := range sortedKeys(servers) {
		line(struct {
			Server string `json:"server"`
			*serverSums
		}{key, servers[key]})
	}
	return out.Bytes()
}

// errClass is what an error of a check says, in a word: timeout, canceled, eof, reset, refused,
// unreachable, cert, tls, other; "" for none. Never the error's text, which may name a destination.
func errClass(err error) string {
	if err == nil {
		return ""
	}
	var netErr net.Error
	text := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.DeadlineExceeded) || errors.As(err, &netErr) && netErr.Timeout() || strings.Contains(text, "timeout") || strings.Contains(text, "timed out"):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
		return "eof"
	case strings.Contains(text, "reset") || strings.Contains(text, "forcibly closed"):
		return "reset"
	case strings.Contains(text, "refused"):
		return "refused"
	case strings.Contains(text, "unreachable") || strings.Contains(text, "no route"):
		return "unreachable"
	case strings.Contains(text, "certificate") || strings.Contains(text, "x509"):
		return "cert"
	case strings.Contains(text, "tls") || strings.Contains(text, "handshake"):
		return "tls"
	case strings.Contains(text, "closed"):
		return "closed"
	}
	return "other"
}

// sortedKeys are m's keys in order.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
