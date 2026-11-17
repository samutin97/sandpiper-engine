package hcore

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// ControlSecretHeader carries the secret of an insecure (no TLS) control server, as the admin
// background service's does.
const ControlSecretHeader = "x-hiddify-secret"

// minControlSecret is the shortest secret an insecure control server accepts.
const minControlSecret = 32

func isInsecureMode(mode SetupMode) bool {
	return mode == SetupMode_GRPC_NORMAL_INSECURE || mode == SetupMode_GRPC_BACKGROUND_INSECURE
}

// checkGrpcMode refuses a control server without authentication: an insecure mode on Android
// and iOS, where every app shares the loopback, and anywhere without a secret of 32 characters
// or more. The Android app used to fall back to the insecure mode 4 when its client certificate
// was missing, which gave any app Stop, Start, the servers' IPs and the logs (HC-08).
func checkGrpcMode(mode SetupMode, secret string) error {
	if !isInsecureMode(mode) {
		return nil
	}
	if C.IsAndroid || C.IsIos {
		return fmt.Errorf("insecure gRPC mode %s is not allowed on this platform: use mTLS (mode 1 or 2)", mode)
	}
	if len(secret) < minControlSecret {
		return fmt.Errorf("insecure gRPC mode %s needs a secret of at least %d characters", mode, minControlSecret)
	}
	return nil
}

// authenticateSecret checks the secret header of a call, in constant time.
func authenticateSecret(ctx context.Context, secret string) error {
	md, _ := metadata.FromIncomingContext(ctx)
	values := md.Get(ControlSecretHeader)
	if len(values) != 1 || subtle.ConstantTimeCompare([]byte(values[0]), []byte(secret)) != 1 {
		return status.Error(codes.Unauthenticated, "invalid credentials")
	}
	return nil
}

// secretServerOptions make every call of an insecure control server carry the secret.
func secretServerOptions(secret string) []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			if err := authenticateSecret(ctx, secret); err != nil {
				return nil, err
			}
			return handler(ctx, req)
		}),
		grpc.StreamInterceptor(func(srv any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			if err := authenticateSecret(stream.Context(), secret); err != nil {
				return err
			}
			return handler(srv, stream)
		}),
	}
}

// controlListener is the listener of a control server, with the address it really listens on.
type controlListener struct {
	net.Listener
	Address string
	// path of a unix socket file, removed when the listener closes
	path string
}

func (l *controlListener) Close() error {
	err := l.Listener.Close()
	if l.path != "" {
		os.Remove(l.path)
	}
	return err
}

// listenControl listens on a control address:
//   - "unix:/abs/path": a socket file, in a directory made 0700, the socket 0600, the peer
//     checked to be this user (SO_PEERCRED, Linux and Android): no port another app can find;
//   - "unix-abstract:name" or "@name": a Linux abstract socket, with the same peer check;
//   - "host:port": TCP, on a loopback address only; port 0 takes a free one.
func listenControl(address string) (*controlListener, error) {
	switch {
	case strings.HasPrefix(address, "unix:"):
		path := strings.TrimPrefix(address, "unix:")
		path = strings.TrimPrefix(path, "//")
		if !filepath.IsAbs(path) {
			return nil, fmt.Errorf("unix socket path must be absolute: %q", path)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		if info, err := os.Lstat(path); err == nil {
			if info.Mode()&os.ModeSocket == 0 {
				return nil, fmt.Errorf("%s exists and is not a socket", path)
			}
			os.Remove(path) // a stale socket of a previous run
		}
		lis, err := net.Listen("unix", path)
		if err != nil {
			return nil, err
		}
		if err := os.Chmod(path, 0o600); err != nil && !C.IsWindows {
			lis.Close()
			return nil, err
		}
		return &controlListener{Listener: peerCheckedListener(lis), Address: "unix:" + path, path: path}, nil
	case strings.HasPrefix(address, "unix-abstract:"), strings.HasPrefix(address, "@"):
		name := strings.TrimPrefix(strings.TrimPrefix(address, "unix-abstract:"), "@")
		if name == "" {
			return nil, errors.New("empty abstract socket name")
		}
		if !C.IsLinux {
			return nil, errors.New("abstract unix sockets exist only on Linux and Android")
		}
		lis, err := net.Listen("unix", "@"+name)
		if err != nil {
			return nil, err
		}
		return &controlListener{Listener: peerCheckedListener(lis), Address: "unix-abstract:" + name}, nil
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid listen address %q: %w", address, err)
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, fmt.Errorf("the control server listens on a loopback address only, not %q", host)
	}
	lis, err := net.Listen("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	return &controlListener{Listener: lis, Address: lis.Addr().String()}, nil
}
