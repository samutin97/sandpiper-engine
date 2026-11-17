package vpnservice

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

// Endpoint is how a client reaches the running service: the loopback address it listens on and
// the certificate (PEM) it presents. Both are made anew at each start of the service, which keeps
// the certificate's key in memory only. The service publishes them in EndpointFile, which only
// SYSTEM, Administrators and root can write; neither is a secret.
//
// A client trusts exactly that certificate: a program that took the port of a service that
// stopped (its endpoint file still names it) fails the TLS handshake before the client has sent
// anything, the control secret above all. The secret proves the client to the service, the
// certificate the service to the client.
type Endpoint struct {
	Address     string `json:"address"`
	Certificate string `json:"certificate,omitempty"`
}

// ErrNoEndpoint: the service has not published where it listens (not installed, not running, or
// an older service).
var ErrNoEndpoint = errors.New("the VPN service has not published its address")

// ReadEndpoint is the endpoint of the installed service: its fixed address on macOS, else the one
// it published.
func ReadEndpoint() (Endpoint, error) {
	if !PublishesEndpoint() {
		return Endpoint{Address: ServiceListenAddress()}, nil
	}
	raw, err := os.ReadFile(EndpointPath())
	if err != nil {
		if os.IsNotExist(err) {
			return Endpoint{}, ErrNoEndpoint
		}
		return Endpoint{}, err
	}
	return ParseEndpoint(raw)
}

// ParseEndpoint reads an endpoint file: a loopback address with a port, and a PEM certificate.
func ParseEndpoint(raw []byte) (Endpoint, error) {
	var endpoint Endpoint
	if err := json.Unmarshal(raw, &endpoint); err != nil {
		return Endpoint{}, fmt.Errorf("the VPN service's endpoint file is invalid: %w", err)
	}
	if err := endpoint.Validate(); err != nil {
		return Endpoint{}, err
	}
	return endpoint, nil
}

// Validate checks that the address is a loopback one with a port, and that the certificate, when
// there is one, is a PEM certificate.
func (e Endpoint) Validate() error {
	host, portText, err := net.SplitHostPort(e.Address)
	if err != nil {
		return fmt.Errorf("the VPN service's address %q is invalid: %w", e.Address, err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("the VPN service's address %q is not a loopback address", e.Address)
	}
	if port, err := strconv.Atoi(portText); err != nil || port <= 0 || port > 65535 {
		return fmt.Errorf("the VPN service's address %q has no port", e.Address)
	}
	if e.Certificate != "" {
		if _, err := e.certificateDER(); err != nil {
			return err
		}
	}
	return nil
}

// Port is the TCP port of the address (0 when it has none).
func (e Endpoint) Port() int {
	_, portText, err := net.SplitHostPort(e.Address)
	if err != nil {
		return 0
	}
	port, _ := strconv.Atoi(portText)
	return port
}

// Marshal is the content of the endpoint file.
func (e Endpoint) Marshal() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(e)
}

func (e Endpoint) certificateDER() ([]byte, error) {
	block, _ := pem.Decode([]byte(e.Certificate))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("the VPN service's certificate is not a PEM certificate")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return nil, fmt.Errorf("the VPN service's certificate is invalid: %w", err)
	}
	return block.Bytes, nil
}

// TLSConfig is the client side of the service's TLS: only a server presenting exactly the
// endpoint's certificate is accepted. Nil for an endpoint without one (the macOS service, which
// serves without TLS on its fixed port).
func (e Endpoint) TLSConfig() (*tls.Config, error) {
	if e.Certificate == "" {
		return nil, nil
	}
	pinned, err := e.certificateDER()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		// the chain is checked below against the one certificate the service published, which is
		// stricter than a chain to a trusted root and needs no name
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 || !bytes.Equal(rawCerts[0], pinned) {
				return errors.New("the server is not the VPN service: its certificate is not the one the service published")
			}
			return nil
		},
	}, nil
}

// Reachable reports whether the service answers at the endpoint, and is the service: a TLS
// handshake with its certificate, or a TCP connect without one.
func (e Endpoint) Reachable(timeout time.Duration) bool {
	config, err := e.TLSConfig()
	if err != nil {
		return false
	}
	dialer := &net.Dialer{Timeout: timeout}
	if config == nil {
		conn, err := dialer.Dial("tcp", e.Address)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}
	config.NextProtos = []string{"h2"}
	conn, err := tls.DialWithDialer(dialer, "tcp", e.Address, config)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
