//go:build linux || android

package hcore

import (
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// peerCheckedListener accepts only connections from processes of this user (SO_PEERCRED): on
// Android every app has its own uid, so no other app reaches the control socket even if it can
// name it (an abstract socket has no file permissions to stop it).
func peerCheckedListener(l net.Listener) net.Listener {
	return &peerCredListener{Listener: l, uid: uint32(os.Getuid())}
}

type peerCredListener struct {
	net.Listener
	uid uint32
}

func (l *peerCredListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if peerUID(conn) == int64(l.uid) {
			return conn, nil
		}
		Log(LogLevel_WARNING, LogType_CORE, "control socket: refused a connection of another user")
		conn.Close()
	}
}

// peerUID is the uid of the process at the other end of a unix connection, or -1.
func peerUID(conn net.Conn) int64 {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return -1
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return -1
	}
	uid := int64(-1)
	raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err == nil {
			uid = int64(cred.Uid)
		}
	})
	return uid
}
