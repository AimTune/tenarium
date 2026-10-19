package netguard

import (
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

// FuzzCheckAddr checks that the address filter is consistent across the
// representations of one address: IPv4-mapped IPv6 forms and zones must
// not change the verdict, and the well-known internal ranges are refused.
func FuzzCheckAddr(f *testing.F) {
	for _, s := range []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254",
		"100.64.0.1", "0.0.0.0", "224.0.0.1", "93.184.216.34", "8.8.8.8",
		"::1", "::", "fe80::1", "fc00::1", "ff02::1", "2606:4700::1111",
		"::ffff:127.0.0.1", "::ffff:169.254.169.254", "fe80::1%eth0",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			return
		}
		got := CheckAddr(ip) == nil
		// The IPv4-mapped form must get the same verdict as plain IPv4.
		if ip.Is4() {
			mapped := netip.AddrFrom16(ip.As16())
			if (CheckAddr(mapped) == nil) != got {
				t.Fatalf("%s allowed=%v but mapped %s allowed=%v", ip, got, mapped, !got)
			}
		}
		// A zone does not change where an address routes to.
		if ip.Zone() != "" && (CheckAddr(ip.WithZone("")) == nil) != got {
			t.Fatalf("zone changes verdict for %s", ip)
		}
		u := ip.Unmap()
		if got && (u.IsLoopback() || u.IsPrivate() || u.IsLinkLocalUnicast() || u.IsUnspecified() || u.IsMulticast()) {
			t.Fatalf("internal address %s allowed", ip)
		}
		// CheckHost on the literal must agree with CheckAddr.
		if (CheckHost(s) == nil) != got {
			t.Fatalf("CheckHost(%q) disagrees with CheckAddr", s)
		}
	})
}

// FuzzCheckHost feeds host names the way callers do (url.Parse +
// Hostname) and checks that local names are refused regardless of case or
// a trailing dot, since DNS names are case-insensitive and "localhost." is
// the same name as "localhost".
func FuzzCheckHost(f *testing.F) {
	for _, s := range []string{
		"https://example.com/hook", "https://localhost/x", "https://api.localhost:8443/",
		"https://127.0.0.1/", "https://[::1]:8443/", "https://[fe80::1%25eth0]/",
		"https://[::ffff:127.0.0.1]/", "http://169.254.169.254/latest/meta-data",
		"https://idp.example.com/.well-known/openid-configuration", "https://0x7f.1/",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return
		}
		host := u.Hostname()
		allowed := CheckHost(host) == nil // must never panic
		if !allowed {
			return
		}
		if ip, err := netip.ParseAddr(host); err == nil && CheckAddr(ip) != nil {
			t.Fatalf("CheckHost allowed internal literal %q", host)
		}
		name := strings.TrimSuffix(strings.ToLower(host), ".")
		if name == "localhost" || strings.HasSuffix(name, ".localhost") {
			t.Fatalf("CheckHost allowed local name %q (from %q)", host, raw)
		}
	})
}
