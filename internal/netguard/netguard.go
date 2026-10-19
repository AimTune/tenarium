// Package netguard builds HTTP clients for URLs chosen by tenants
// (webhooks, SSO issuers), which must not reach the platform's internal
// network (SSRF).
package netguard

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// Options configure a client.
type Options struct {
	Timeout time.Duration
	// AllowPrivate permits loopback/private targets (development only).
	AllowPrivate bool
	// FollowRedirects is off by default: a redirect could point anywhere.
	// When on, every hop is still checked at dial time.
	FollowRedirects bool
}

// NewClient returns a client that refuses internal addresses after DNS
// resolution (so DNS rebinding cannot bypass it), ignores proxies and
// traces requests when tracing is on.
func NewClient(o Options) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if !o.AllowPrivate {
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip, err := netip.ParseAddr(host)
			if err != nil {
				return err
			}
			return CheckAddr(ip)
		}
	}
	transport := &http.Transport{
		Proxy:                 nil, // a proxy would bypass the address check
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: o.Timeout,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
	}
	c := &http.Client{Transport: otelhttp.NewTransport(transport), Timeout: o.Timeout}
	if !o.FollowRedirects {
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return c
}

var (
	cgnat   = netip.MustParsePrefix("100.64.0.0/10")
	thisNet = netip.MustParsePrefix("0.0.0.0/8")
)

// CheckAddr refuses addresses tenants must not reach: loopback, private,
// link-local (cloud metadata), CGNAT, multicast and unspecified.
func CheckAddr(ip netip.Addr) error {
	// Zones ("::%eth0") make the predicates below report false; drop them.
	ip = ip.WithZone("").Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() ||
		cgnat.Contains(ip) || thisNet.Contains(ip) {
		return fmt.Errorf("address %s is not allowed", ip)
	}
	return nil
}

// CheckHost rejects literal internal addresses and local names when a URL
// is registered; resolution is checked again on every connection.
func CheckHost(host string) error {
	if ip, err := netip.ParseAddr(host); err == nil {
		return CheckAddr(ip)
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return errors.New("local hosts are not allowed")
	}
	return nil
}
