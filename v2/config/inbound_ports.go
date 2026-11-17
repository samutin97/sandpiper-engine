package config

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"sync"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/auth"

	"github.com/hiddify/hiddify-core/v2/hutils"
)

// ProxyUser is the user name of the LAN sharing port when the app names none (the QR dialog of
// the app shows it); the local port gets a random one (localProxyCredentials).
const ProxyUser = "hiddify"

// minProxyPassword is the shortest password the app may give the local port; a shorter or no
// password is replaced by a random one. minLANPassword is the shortest the LAN port accepts.
const (
	minProxyPassword = 16
	minLANPassword   = 8
)

// isMobile: Android and iOS, where every app on the device shares the loopback, so a local port is
// found by any of them (the "local proxy" leak: an app uses the proxy to learn the VPN server's
// address, and to bypass split tunneling).
const isMobile = C.IsAndroid || C.IsIos

// transparentPortsOpen says whether tproxy, redirect and direct open: they serve no app in VPN
// mode, and take no password, so there only while the VPN is shared (a Linux gateway).
func transparentPortsOpen(hopt *HiddifyOptions) bool {
	return !hopt.EnableTun || hopt.AllowConnectionFromLAN
}

// portEnabled says whether a port opens: set, and its switch on, or unset and on by default.
func portEnabled(enabled *bool, port uint16, byDefault bool) bool {
	if enabled == nil {
		return port > 0 && byDefault
	}
	return port > 0 && *enabled
}

// localPortOpen says whether this device's own proxy port (the mixed port, on loopback) opens: in
// proxy and system proxy mode; in VPN mode never on Android and iOS (every app already goes
// through the TUN, and a port there is what other apps find), on the desktop only when the user
// asked for it. Port 0 with the switch on takes a free port (localProxyPort).
func localPortOpen(hopt *HiddifyOptions) bool {
	if hopt.EnableTun && (isMobile || !hopt.LocalProxyInVpn) {
		return false
	}
	if hopt.MixedPort == 0 {
		return hopt.EnableMixedPort != nil && *hopt.EnableMixedPort
	}
	return portEnabled(hopt.EnableMixedPort, hopt.MixedPort, true)
}

// sessionProxyPort is a free loopback port for the local proxy, once per process: the same
// settings build the same config (hot reload compares them).
var sessionProxyPort = sync.OnceValue(freeLoopbackPort)

// localProxyPort is the port of the local proxy: the app's, or a free one for port 0.
func localProxyPort(hopt *HiddifyOptions) uint16 {
	if hopt.MixedPort == 0 {
		return sessionProxyPort()
	}
	return hopt.MixedPort
}

// sessionProxyCredentials are random credentials of the local proxy for this process: a neutral
// user name of 8 lowercase letters, a password of 24 random bytes.
var sessionProxyCredentials = sync.OnceValue(func() auth.User {
	letters := randomBytes(8)
	name := make([]byte, len(letters))
	for i, b := range letters {
		name[i] = 'a' + b%26
	}
	return auth.User{Username: string(name), Password: base64.RawURLEncoding.EncodeToString(randomBytes(24))}
})

// localProxyCredentials are the user and password of the local proxy: the app's, when it gives a
// password of 16 characters or more, else random ones for this process.
func localProxyCredentials(hopt *HiddifyOptions) auth.User {
	session := sessionProxyCredentials()
	user := auth.User{Username: hopt.LocalProxyUsername, Password: hopt.LocalProxyPassword}
	if len(user.Password) < minProxyPassword {
		user.Password = session.Password
	}
	if user.Username == "" {
		user.Username = session.Username
	}
	return user
}

// localUsers are the users the local port asks for: always on Android and iOS; on the desktop too,
// except the listener the system proxy points at, which can not pass a password (Windows and
// macOS never send one). local-proxy-auth no longer turns the password off.
func localUsers(hopt *HiddifyOptions, systemProxy bool) []auth.User {
	if systemProxy && !isMobile {
		return nil
	}
	return []auth.User{localProxyCredentials(hopt)}
}

// lanUsers is the one user of the LAN sharing port, with the app's password.
func lanUsers(hopt *HiddifyOptions) []auth.User {
	name := hopt.LocalProxyUsername
	if name == "" {
		name = ProxyUser
	}
	return []auth.User{{Username: name, Password: hopt.ProxySecret}}
}

// proxyListener is one address and port a mixed inbound listens on, with the users it asks for.
type proxyListener struct {
	tag   string
	addr  netip.Addr
	port  uint16
	users []auth.User
	// systemProxy: this listener is the one the system proxy points at
	systemProxy bool
	// udp: SOCKS5 UDP ASSOCIATE allowed
	udp bool
}

// proxyListeners are the mixed inbounds: this device's local port on loopback (localPortOpen), and
// while the VPN is shared, the LAN sharing port on every address, always asking for the secret.
// The two are apart; on the same port, the shared one takes both.
//
// Hardened: the local port always asks for a user and password (but for the system proxy's own
// listener on the desktop), listens on 127.0.0.1 only on Android and iOS, and refuses SOCKS5 UDP
// ASSOCIATE unless local-proxy-udp: the UDP relay is not covered by the password. The LAN port
// needs a password of 8 characters or more, or the config fails (HC-17).
//
// Only the IPv4 loopback listener sets the system proxy: each listener that does so overwrites the
// setting as it starts, and the ::1 one, starting last, left Windows pointed at http://[::1]:port,
// which Telegram and other apps that read the system proxy can not use (5.5.1).
func proxyListeners(hopt *HiddifyOptions, ipv6 bool) ([]proxyListener, error) {
	shared := hopt.AllowConnectionFromLAN && hopt.LanSharingPort > 0
	if shared && len(hopt.ProxySecret) < minLANPassword {
		return nil, fmt.Errorf("LAN sharing needs a password of at least %d characters (lan-sharing-password)", minLANPassword)
	}
	port := localProxyPort(hopt)
	var listeners []proxyListener
	if localPortOpen(hopt) && !(shared && hopt.LanSharingPort == port) {
		loopback := []netip.Addr{netip.MustParseAddr("127.0.0.1")}
		if ipv6 && !isMobile {
			loopback = append(loopback, netip.MustParseAddr("::1"))
		}
		for _, addr := range loopback {
			systemProxy := hopt.SetSystemProxy && addr.Is4()
			listeners = append(listeners, proxyListener{
				tag:         InboundMixedTag + addr.String(),
				addr:        addr,
				port:        port,
				users:       localUsers(hopt, systemProxy),
				systemProxy: systemProxy,
				udp:         hopt.LocalProxyUDP,
			})
		}
	}
	if shared {
		every := netip.MustParseAddr("0.0.0.0")
		if ipv6 {
			every = netip.MustParseAddr("::")
		}
		listeners = append(listeners, proxyListener{
			tag:         InboundLanSharingTag + every.String(),
			addr:        every,
			port:        hopt.LanSharingPort,
			users:       lanUsers(hopt),
			systemProxy: hopt.SetSystemProxy && hopt.LanSharingPort == port && localPortOpen(hopt),
			udp:         hopt.LocalProxyUDP,
		})
	}
	return listeners, nil
}

// LocalProxyInfo is what the local proxy of these settings listens on and asks for, for the app
// to show (empty Address when it does not open).
type LocalProxyInfo struct {
	Address  string
	Username string
	Password string
	UDP      bool
}

// GetLocalProxyInfo is the local proxy these settings open: address, user and password.
func GetLocalProxyInfo(hopt *HiddifyOptions) LocalProxyInfo {
	if hopt == nil || !localPortOpen(hopt) {
		return LocalProxyInfo{}
	}
	info := LocalProxyInfo{Address: fmt.Sprintf("127.0.0.1:%d", localProxyPort(hopt)), UDP: hopt.LocalProxyUDP}
	if users := localUsers(hopt, hopt.SetSystemProxy); len(users) == 1 {
		info.Username, info.Password = users[0].Username, users[0].Password
	}
	return info
}

// tproxyAvailable: tproxy needs Linux's transparent sockets, which only root may open.
func tproxyAvailable() bool {
	return C.IsLinux && !C.IsAndroid && hutils.IsAdmin()
}

// redirectAvailable: redirect reads the original address from Linux netfilter or the macOS pf.
func redirectAvailable() bool {
	return (C.IsLinux || C.IsDarwin) && !C.IsAndroid && !C.IsIos
}
