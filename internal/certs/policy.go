package certs

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// DomainChecker decides whether a certificate may be issued (and served) for
// host. It returns nil when host is a verified domain of a live tenant. The
// platform's own hostnames (Config.PlatformHosts) are allowed by the Manager
// without calling it. host is already normalised: lowercase, no port, no
// trailing dot.
//
// Return an error wrapping ErrHostNotAllowed for a definite "no"; any other
// error is treated as a failed lookup (the handshake fails either way, but
// the result is cached for less time, see Config.PolicyErrorTTL).
type DomainChecker func(ctx context.Context, host string) error

// ErrHostNotAllowed is returned by the host policy for hosts that are neither
// platform hostnames nor accepted by the DomainChecker.
var ErrHostNotAllowed = errors.New("certs: host not allowed")

// maxPolicyEntries bounds the decision cache: random SNI values must not grow
// memory without limit. When full the cache is simply reset.
const maxPolicyEntries = 10000

type policyEntry struct {
	err     error
	expires time.Time
}

// hostPolicy wraps a DomainChecker with platform hostnames and a short cache.
type hostPolicy struct {
	exact    map[string]bool
	suffixes []string // ".example.com" for "*.example.com" patterns
	check    DomainChecker
	allowTTL time.Duration
	denyTTL  time.Duration
	errTTL   time.Duration
	now      func() time.Time

	mu      sync.Mutex
	entries map[string]policyEntry
}

func newHostPolicy(platform []string, check DomainChecker, allowTTL, denyTTL, errTTL time.Duration, now func() time.Time) *hostPolicy {
	p := &hostPolicy{exact: map[string]bool{}, check: check, allowTTL: allowTTL, denyTTL: denyTTL, errTTL: errTTL, now: now, entries: map[string]policyEntry{}}
	for _, h := range platform {
		h = normalizeHost(h)
		if rest, ok := strings.CutPrefix(h, "*."); ok {
			p.suffixes = append(p.suffixes, "."+rest)
			continue
		}
		if h != "" {
			p.exact[h] = true
		}
	}
	return p
}

// normalizeHost lowercases host and strips a port and a trailing dot.
func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.TrimSuffix(h, ".")
}

func (p *hostPolicy) platform(host string) bool {
	if p.exact[host] {
		return true
	}
	for _, s := range p.suffixes {
		// "*.example.com" matches exactly one extra label.
		if label, ok := strings.CutSuffix(host, s); ok && label != "" && !strings.Contains(label, ".") {
			return true
		}
	}
	return false
}

// allow is an autocert.HostPolicy.
func (p *hostPolicy) allow(ctx context.Context, host string) error {
	host = normalizeHost(host)
	if host == "" || net.ParseIP(host) != nil {
		return fmt.Errorf("%w: %q", ErrHostNotAllowed, host)
	}
	if p.platform(host) {
		return nil
	}
	if p.check == nil {
		return fmt.Errorf("%w: %s", ErrHostNotAllowed, host)
	}
	now := p.now()
	p.mu.Lock()
	if e, ok := p.entries[host]; ok && now.Before(e.expires) {
		p.mu.Unlock()
		return e.err
	}
	p.mu.Unlock()

	err := p.check(ctx, host)
	ttl := p.allowTTL
	switch {
	case err == nil:
	case errors.Is(err, ErrHostNotAllowed):
		ttl = p.denyTTL
	default:
		if ctx.Err() != nil { // our caller gave up; do not cache that
			return err
		}
		ttl = p.errTTL
	}
	if ttl > 0 {
		p.mu.Lock()
		if len(p.entries) >= maxPolicyEntries {
			p.entries = map[string]policyEntry{}
		}
		p.entries[host] = policyEntry{err: err, expires: now.Add(ttl)}
		p.mu.Unlock()
	}
	return err
}

// forget drops a cached decision, e.g. right after a domain was verified or
// removed.
func (p *hostPolicy) forget(host string) {
	p.mu.Lock()
	delete(p.entries, normalizeHost(host))
	p.mu.Unlock()
}
