package config

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// A profile can list other subscriptions, one URL per line (Mahsa's profiles do): their content
// takes the place of the URL. Only one level is read, so a subscription cannot list itself.

const (
	subscriptionLinksMax     = 32
	subscriptionFetchTimeout = 20 * time.Second
	subscriptionSizeMax      = 16 << 20
)

// isSubscriptionLink reports a line that is the URL of a subscription, not an HTTP proxy: http or
// https with a path, and without a user or a name (fragment), which proxy links have.
func isSubscriptionLink(line string) bool {
	if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") || strings.ContainsAny(line, " \t") {
		return false
	}
	u, err := url.Parse(line)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	return strings.Trim(u.Path, "/") != ""
}

// expandSubscriptionLinks replaces the subscription URLs of content with their content. A
// subscription that cannot be read is left out; content without subscription URLs is returned
// as is.
//
// Hardened (HC-16): only when the user allows it (expand-subscription-links); otherwise the URLs
// are left out (the app fetches subscriptions itself, through the VPN). When allowed: https only,
// no redirect to another host, no private, loopback or link-local address, a browser's User-Agent.
func expandSubscriptionLinks(ctx context.Context, content []byte, allowed bool) []byte {
	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	var links []int
	for i, line := range lines {
		if isSubscriptionLink(strings.TrimSpace(line)) && len(links) < subscriptionLinksMax {
			links = append(links, i)
		}
	}
	if len(links) == 0 {
		return content
	}
	if !allowed {
		for _, i := range links {
			lines[i] = ""
		}
		return []byte(strings.Join(lines, "\n"))
	}
	var wait sync.WaitGroup
	for _, i := range links {
		wait.Add(1)
		go func(i int) {
			defer wait.Done()
			body, err := fetchSubscription(ctx, strings.TrimSpace(lines[i]))
			if err != nil {
				body = ""
			}
			lines[i] = body
		}(i)
	}
	wait.Wait()
	return []byte(strings.Join(lines, "\n"))
}

// subscriptionUserAgent is a browser's, not the app's ("HiddifyNext/4.0.0 ... like ClashMeta"),
// which named the client to anyone on the path of a plain request.
const subscriptionUserAgent = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Mobile Safari/537.36"

// publicOnlyDialer refuses private, loopback, link-local and unspecified addresses: a profile must
// not make the core reach into the device or the local network.
var publicOnlyDialer = &net.Dialer{
	Timeout: subscriptionFetchTimeout,
	Control: func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return err
		}
		ip = ip.Unmap()
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() || isCGNAT(ip) {
			return E.New("subscription: address not allowed: ", ip)
		}
		return nil
	},
}

func isCGNAT(ip netip.Addr) bool {
	return netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
}

var subscriptionClient = &http.Client{
	Transport: &http.Transport{DialContext: publicOnlyDialer.DialContext, TLSHandshakeTimeout: subscriptionFetchTimeout},
	CheckRedirect: func(request *http.Request, via []*http.Request) error {
		if len(via) >= 3 || request.URL.Scheme != "https" || request.URL.Host != via[0].URL.Host {
			return E.New("subscription: redirect not followed")
		}
		return nil
	},
}

func fetchSubscription(ctx context.Context, link string) (string, error) {
	if !strings.HasPrefix(link, "https://") {
		return "", E.New("subscription: only https is fetched")
	}
	ctx, cancel := context.WithTimeout(ctx, subscriptionFetchTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("User-Agent", subscriptionUserAgent)
	response, err := subscriptionClient.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", E.New("subscription ", link, ": ", response.Status)
	}
	// a base64 subscription is one line, which the share link parser decodes
	body, err := io.ReadAll(io.LimitReader(response.Body, subscriptionSizeMax))
	return strings.TrimSpace(string(body)), err
}
