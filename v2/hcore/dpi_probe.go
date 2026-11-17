package hcore

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hiddify/hiddify-core/v2/config"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// The "16 KB" diagnostic (research dpi_bypass_research.md, 5.2): the path to a server, stage by
// stage, with a strict budget so that the test itself does not trip the limits it looks for. It
// runs only when the app asks (Core.DpiProbe), one at a time, at most probeMaxConnections
// connections; every TLS handshake goes through the handshake gate.

const (
	probeTransferSize   = 64 << 10
	probeMaxConnections = 12
	probeDefaultTimeout = 8 * time.Second
	probeMaxTimeout     = 30 * time.Second
	probeStallAfter     = 4 * time.Second // no byte for that long: the transfer stalled
	probeFreezeFrom     = 14 << 10
	probeFreezeTo       = 25 << 10
)

var probeRunning sync.Mutex

func (s *CoreService) DpiProbe(ctx context.Context, in *DpiProbeRequest) (*DpiProbeResponse, error) {
	return DpiProbe(ctx, in), nil
}

// DpiProbe runs the diagnostic; see DpiProbeRequest. It always answers with an outcome, never
// with an error alone (a panic too becomes the outcome "error" with its text), and within
// p.budget(): every stage of every connection has its own timeout, the transfers included.
func DpiProbe(ctx context.Context, in *DpiProbeRequest) (response *DpiProbeResponse) {
	if !probeRunning.TryLock() {
		return &DpiProbeResponse{Outcome: "busy", Stages: []*DpiProbeStage{{Name: "request", Outcome: "busy", Detail: "another check of the path runs"}}}
	}
	defer probeRunning.Unlock()
	defer func() {
		if recovered := recover(); recovered != nil {
			if response == nil {
				response = &DpiProbeResponse{}
			}
			response.Outcome = "error"
			response.Stages = append(response.Stages, &DpiProbeStage{Name: "internal", Outcome: "error", Detail: scrubLogLine(fmt.Sprint(recovered))})
		}
	}()
	if in == nil || strings.TrimSpace(in.Host) == "" {
		return &DpiProbeResponse{Outcome: "error", Stages: []*DpiProbeStage{{Name: "request", Outcome: "error", Detail: "no host"}}}
	}
	p := newProbe(in)
	ctx, cancel := context.WithTimeout(ctx, p.budget())
	defer cancel()
	response = &DpiProbeResponse{}
	for attempt := 0; attempt < p.attempts; attempt++ {
		response.Stages = nil
		response.Outcome = p.run(ctx, response)
		if response.Outcome == "ok" || ctx.Err() != nil || response.Connections >= probeMaxConnections {
			break
		}
	}
	if response.Outcome == "" {
		response.Outcome = "error"
	}
	return response
}

// probeStagesPerConnection are the stages a connection can spend its timeout on: TCP, TLS and the
// transfer; probeConnectionsPerAttempt the connections of an attempt (download, upload).
const (
	probeStagesPerConnection   = 3
	probeConnectionsPerAttempt = 2
)

// budget is the longest a probe takes: each stage's timeout, for every connection it may open.
func (p *probe) budget() time.Duration {
	return time.Duration(p.attempts*probeConnectionsPerAttempt*probeStagesPerConnection)*p.timeout + time.Second
}

type probe struct {
	host, serverName, fingerprint, path, keyShare string
	uploadPath                                    string
	port                                          uint16
	upload, insecure                              bool
	attempts                                      int
	timeout                                       time.Duration
	pins                                          badoption.Listable[[]byte]
}

func newProbe(in *DpiProbeRequest) *probe {
	p := &probe{
		host: strings.TrimSpace(in.Host), serverName: in.ServerName, fingerprint: in.Fingerprint,
		path: in.Path, upload: in.Upload, insecure: in.Insecure, keyShare: in.KeyShare,
		port: 443, attempts: 1, timeout: probeDefaultTimeout,
	}
	if in.Port > 0 && in.Port < 65536 {
		p.port = uint16(in.Port)
	}
	if p.serverName == "" {
		p.serverName = p.host
	}
	if p.fingerprint == "" {
		p.fingerprint = config.DefaultTLSFingerprint
	}
	if p.path == "" || !strings.HasPrefix(p.path, "/") || strings.ContainsAny(p.path, " \r\n") { // no header of its own in the request
		p.path = "/"
	}
	// the upload goes where the server reads a body (a form's POST), not to the file the download
	// gets: a static file answered the POST before reading it, or not at all
	p.uploadPath = in.UploadPath
	if p.uploadPath == "" || !strings.HasPrefix(p.uploadPath, "/") || strings.ContainsAny(p.uploadPath, " \r\n") {
		p.uploadPath = p.path
	}
	if in.Attempts == 2 {
		p.attempts = 2
	}
	if in.TimeoutMs > 0 {
		p.timeout = min(time.Duration(in.TimeoutMs)*time.Millisecond, probeMaxTimeout)
	}
	for _, pin := range in.CertificateSha256 {
		if b, err := hex.DecodeString(strings.ReplaceAll(pin, ":", "")); err == nil && len(b) == 32 {
			p.pins = append(p.pins, b)
		}
	}
	return p
}

// dialer is the core's direct dialer when it runs (a protected socket on Android, outside the
// VPN), the system's otherwise.
func probeDialer() N.Dialer {
	if box := static.Box(); box != nil {
		if out, ok := box.Outbound().Outbound(config.OutboundDirectTag); ok {
			return out
		}
	}
	return N.SystemDialer
}

func (p *probe) run(ctx context.Context, response *DpiProbeResponse) string {
	stage := func(name string) func(outcome string, bytes int64, err error) *DpiProbeStage {
		start := time.Now()
		return func(outcome string, bytes int64, err error) *DpiProbeStage {
			st := &DpiProbeStage{Name: name, Outcome: outcome, Bytes: bytes, Millis: time.Since(start).Milliseconds()}
			if err != nil {
				st.Detail = scrubLogLine(err.Error())
			}
			response.Stages = append(response.Stages, st)
			return st
		}
	}
	conn, outcome := p.connect(ctx, response, stage)
	if conn == nil {
		return outcome
	}
	end := stage("download")
	got, err := p.download(ctx, conn)
	conn.Close()
	outcome = classifyTransfer(got, err)
	end(outcome, got, err)
	if outcome != "ok" || !p.upload {
		return outcome
	}
	// the upload on a connection of its own: the rest of the answer must not be in the way
	conn, outcome = p.connect(ctx, response, stage)
	if conn == nil {
		return outcome
	}
	defer conn.Close()
	end = stage("upload")
	sent, err := p.uploadBody(ctx, conn)
	outcome = classifyTransfer(sent, err)
	end(outcome, sent, err)
	return outcome
}

// connect opens a TCP connection and makes the TLS handshake, with their stages; nil and the
// outcome when it fails.
func (p *probe) connect(ctx context.Context, response *DpiProbeResponse, stage func(string) func(string, int64, error) *DpiProbeStage) (net.Conn, string) {
	if response.Connections >= probeMaxConnections {
		return nil, "budget"
	}
	response.Connections++

	end := stage("tcp")
	dialCtx, cancel := context.WithTimeout(ctx, p.timeout)
	conn, err := probeDialer().DialContext(dialCtx, N.NetworkTCP, M.ParseSocksaddrHostPort(p.host, p.port))
	cancel()
	if err != nil {
		outcome := classifyNetError(err)
		end(outcome, 0, err)
		return nil, "tcp_" + outcome
	}
	end("ok", 0, nil)

	end = stage("tls")
	tlsOptions := option.OutboundTLSOptions{
		Enabled: true, ServerName: p.serverName, Insecure: p.insecure, CertificateSHA256: p.pins,
		ALPN: badoption.Listable[string]{"http/1.1"},
		UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: p.fingerprint, KeyShare: p.keyShare},
	}
	tlsConfig, err := tls.NewClient(ctx, log.NewNOPFactory().NewLogger("probe"), p.serverName, tlsOptions)
	if err != nil {
		conn.Close()
		end("error", 0, err)
		return nil, "error"
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, p.timeout)
	tlsConn, err := tls.ClientHandshake(handshakeCtx, conn, tlsConfig)
	cancel()
	if err != nil {
		conn.Close()
		outcome := classifyNetError(err)
		if outcome == "error" && errors.Is(err, context.DeadlineExceeded) {
			outcome = "timeout"
		}
		end(outcome, 0, err)
		return nil, "tls_" + outcome
	}
	end("ok", 0, nil)
	return tlsConn, ""
}

// transferDeadline ends a transfer at its stage timeout, or when ctx ends (the app went away, the
// probe's budget is spent), whatever the server sends meanwhile: a server that trickles a byte
// every few seconds kept the probe reading forever.
func (p *probe) transferDeadline(ctx context.Context, conn net.Conn) (time.Time, func() bool) {
	deadline := time.Now().Add(p.timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	return deadline, context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
}

// readDeadline is the deadline of the next read: probeStallAfter from now, or the transfer's.
func readDeadline(deadline time.Time) time.Time {
	if next := time.Now().Add(probeStallAfter); next.Before(deadline) {
		return next
	}
	return deadline
}

// download asks for 64 KiB (Range) and reads until it has them, the server closes, nothing came
// for probeStallAfter, or the stage's timeout.
func (p *probe) download(ctx context.Context, conn net.Conn) (int64, error) {
	deadline, stop := p.transferDeadline(ctx, conn)
	defer stop()
	request := "GET " + p.path + " HTTP/1.1\r\nHost: " + p.serverName +
		"\r\nUser-Agent: Mozilla/5.0 (Android 14; Mobile; rv:148.0) Gecko/148.0 Firefox/148.0\r\nAccept: */*\r\nRange: bytes=0-" +
		strconv.Itoa(probeTransferSize-1) + "\r\nConnection: keep-alive\r\n\r\n"
	conn.SetWriteDeadline(deadline)
	if _, err := io.WriteString(conn, request); err != nil {
		return 0, err
	}
	reader := bufio.NewReader(conn)
	var total int64
	buffer := make([]byte, 4096)
	headerDone := false
	var bodyLength int64 = -1
	var header strings.Builder
	for {
		conn.SetReadDeadline(readDeadline(deadline))
		n, err := reader.Read(buffer)
		total += int64(n)
		if !headerDone {
			header.Write(buffer[:n])
			if i := strings.Index(header.String(), "\r\n\r\n"); i >= 0 {
				headerDone = true
				bodyLength = parseContentLength(header.String()[:i])
			}
		}
		if total >= probeTransferSize || headerDone && bodyLength >= 0 && total >= bodyLength {
			return total, nil
		}
		if err != nil {
			if errors.Is(err, io.EOF) && headerDone {
				return total, nil
			}
			return total, err
		}
	}
}

// uploadBody sends 64 KiB as a POST body to uploadPath and waits for the answer's first line,
// all within the stage's timeout.
func (p *probe) uploadBody(ctx context.Context, conn net.Conn) (int64, error) {
	deadline, stop := p.transferDeadline(ctx, conn)
	defer stop()
	header := "POST " + p.uploadPath + " HTTP/1.1\r\nHost: " + p.serverName + "\r\nContent-Type: application/octet-stream\r\nContent-Length: " +
		strconv.Itoa(probeTransferSize) + "\r\nConnection: close\r\n\r\n"
	conn.SetWriteDeadline(deadline)
	if _, err := io.WriteString(conn, header); err != nil {
		return 0, err
	}
	chunk := make([]byte, 4096)
	rand.Read(chunk)
	var sent int64
	for sent < probeTransferSize {
		conn.SetWriteDeadline(readDeadline(deadline))
		n, err := conn.Write(chunk)
		sent += int64(n)
		if err != nil {
			return sent, err
		}
	}
	conn.SetReadDeadline(deadline)
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && !strings.HasPrefix(line, "HTTP/") {
		return sent, err
	}
	return sent, nil
}

func parseContentLength(header string) int64 {
	for _, line := range strings.Split(header, "\r\n") {
		if name, value, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(name), "content-length") {
			if n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil {
				return n + int64(len(header)) + 4
			}
		}
	}
	return -1
}

// classifyNetError is timeout, reset or error.
func classifyNetError(err error) string {
	var netErr net.Error
	switch {
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.ECONNABORTED),
		strings.Contains(strings.ToLower(err.Error()), "reset"), strings.Contains(strings.ToLower(err.Error()), "forcibly closed"):
		return "reset"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	}
	return "error"
}

// classifyTransfer is ok, freeze_16k (a stop between 14 and 25 KB without a reset), stall or
// reset.
func classifyTransfer(bytes int64, err error) string {
	if err == nil {
		return "ok"
	}
	switch classifyNetError(err) {
	case "reset":
		return "reset"
	case "timeout":
		if bytes >= probeFreezeFrom && bytes <= probeFreezeTo {
			return "freeze_16k"
		}
		return "stall"
	}
	return "reset" // the connection ended otherwise before the data
}
