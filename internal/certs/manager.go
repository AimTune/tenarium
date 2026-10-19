package certs

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Well-known ACME directories.
const (
	LetsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// Config configures a Manager. Durations left at zero take the defaults
// documented on each field.
type Config struct {
	// Email is the ACME account contact; the CA sends expiry and incident
	// notices there. Strongly recommended.
	Email string `yaml:"email" json:"email"`
	// Directory is the ACME directory: "production", "staging" (Let's
	// Encrypt) or a full URL (e.g. Pebble, ZeroSSL, a private CA). Empty means
	// "staging", so that a half-configured deployment cannot exhaust
	// production rate limits.
	Directory string `yaml:"directory" json:"directory"`
	// CARootsFile optionally names a PEM bundle trusted (in addition to the
	// system roots) when talking to the ACME directory, for private CAs and
	// Pebble's self-signed minica root.
	CARootsFile string `yaml:"ca_roots_file" json:"ca_roots_file"`
	// PlatformHosts are the platform's own hostnames, always allowed without
	// asking the DomainChecker. "*.example.com" allows any single label below
	// example.com (each name still gets its own certificate; wildcard
	// certificates need DNS-01, which autocert does not support).
	PlatformHosts []string `yaml:"platform_hosts" json:"platform_hosts"`
	// RenewBefore is how long before expiry certificates are renewed.
	// Zero lets autocert decide (1/3 of the lifetime, at most 30 days).
	RenewBefore time.Duration `yaml:"renew_before" json:"renew_before"`
	// KeyPrefix namespaces all KV keys. Default "certs/".
	KeyPrefix string `yaml:"key_prefix" json:"key_prefix"`
	// PolicyCacheTTL caches positive host policy answers. Default 1m. It is
	// also how long a removed domain may keep being served by a replica.
	PolicyCacheTTL time.Duration `yaml:"policy_cache_ttl" json:"policy_cache_ttl"`
	// PolicyDenyTTL caches ErrHostNotAllowed answers. Default 30s.
	PolicyDenyTTL time.Duration `yaml:"policy_deny_ttl" json:"policy_deny_ttl"`
	// PolicyErrorTTL caches other DomainChecker errors. Default 5s.
	PolicyErrorTTL time.Duration `yaml:"policy_error_ttl" json:"policy_error_ttl"`
	// LockTTL is how long an issuance lock is honoured before it is
	// considered abandoned. Default 3m (well above a normal ACME round trip).
	LockTTL time.Duration `yaml:"lock_ttl" json:"lock_ttl"`
	// LockWait is how long a replica waits for another replica's issuance
	// before trying on its own. Default 90s.
	LockWait time.Duration `yaml:"lock_wait" json:"lock_wait"`
}

// DirectoryURL resolves Config.Directory.
func (c Config) DirectoryURL() string {
	switch strings.ToLower(strings.TrimSpace(c.Directory)) {
	case "", "staging", "letsencrypt-staging":
		return LetsEncryptStaging
	case "production", "prod", "letsencrypt":
		return LetsEncryptProduction
	default:
		return strings.TrimSpace(c.Directory)
	}
}

func (c *Config) defaults() {
	if c.KeyPrefix == "" {
		c.KeyPrefix = DefaultKeyPrefix
	}
	if c.PolicyCacheTTL == 0 {
		c.PolicyCacheTTL = time.Minute
	}
	if c.PolicyDenyTTL == 0 {
		c.PolicyDenyTTL = 30 * time.Second
	}
	if c.PolicyErrorTTL == 0 {
		c.PolicyErrorTTL = 5 * time.Second
	}
	if c.LockTTL == 0 {
		c.LockTTL = 3 * time.Minute
	}
	if c.LockWait == 0 {
		c.LockWait = 90 * time.Second
	}
}

// Hooks are optional callbacks for metrics and logging. They are called
// synchronously, so they must be quick and must not block.
type Hooks struct {
	// OnIssued is called after this replica stored a newly obtained
	// certificate: first issuance and background renewals alike.
	OnIssued func(host string, notAfter time.Time)
	// OnFailed is called when an issuance attempted during a TLS handshake
	// fails (once per failed handshake). autocert retries failed background
	// renewals internally without reporting them; alert on Status expiry
	// instead.
	OnFailed func(host string, err error)
	// OnDenied is called when the host policy rejects a handshake.
	OnDenied func(host string, err error)
}

// Options are the Manager's runtime dependencies.
type Options struct {
	// KV stores certificates, the account key, challenge tokens and locks.
	// Required.
	KV KV
	// Checker allows tenant hostnames. If nil only PlatformHosts are allowed.
	Checker DomainChecker
	// Seal/Open optionally wrap stored values (encryption at rest).
	Seal func([]byte) ([]byte, error)
	Open func([]byte) ([]byte, error)
	// HTTPClient talks to the ACME directory. Default: a client trusting the
	// system roots plus Config.CARootsFile.
	HTTPClient *http.Client
	Hooks      Hooks
	Logger     *slog.Logger
}

// Manager obtains and renews certificates for platform and verified tenant
// hostnames through ACME. It wraps autocert.Manager, keeping its state in a
// KV shared by all replicas and serialising issuance across replicas with a
// best-effort lock. All methods are safe for concurrent use.
type Manager struct {
	cfg    Config
	kv     KV
	cache  *Cache
	policy *hostPolicy
	ac     *autocert.Manager
	hooks  Hooks
	log    *slog.Logger
	id     string // lock owner identity of this replica
	now    func() time.Time

	ready sync.Map // cache name -> notAfter of a cert known to be in the cache
}

// New builds a Manager. It does not contact the CA; the ACME account is
// registered lazily on the first issuance and its key stored in the KV.
func New(cfg Config, opts Options) (*Manager, error) {
	if opts.KV == nil {
		return nil, errors.New("certs: Options.KV is required")
	}
	cfg.defaults()
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	hc := opts.HTTPClient
	if hc == nil {
		var err error
		if hc, err = httpClient(cfg.CARootsFile); err != nil {
			return nil, err
		}
	}
	idb := make([]byte, 8)
	_, _ = rand.Read(idb)
	hostname, _ := os.Hostname()

	m := &Manager{cfg: cfg, kv: opts.KV, hooks: opts.Hooks, log: log, now: time.Now,
		id: hostname + "/" + hex.EncodeToString(idb)}
	m.cache = NewCache(opts.KV, cfg.KeyPrefix)
	m.cache.Seal, m.cache.Open = opts.Seal, opts.Open
	m.cache.onPut = m.observePut
	m.policy = newHostPolicy(cfg.PlatformHosts, opts.Checker, cfg.PolicyCacheTTL, cfg.PolicyDenyTTL, cfg.PolicyErrorTTL,
		func() time.Time { return m.now() })
	m.ac = &autocert.Manager{
		Prompt:      autocert.AcceptTOS,
		Cache:       m.cache,
		HostPolicy:  m.policy.allow,
		RenewBefore: cfg.RenewBefore,
		Email:       cfg.Email,
		Client: &acme.Client{
			DirectoryURL: cfg.DirectoryURL(),
			HTTPClient:   withOrderLocation(hc),
			UserAgent:    "tenarium",
		},
	}
	return m, nil
}

func httpClient(caFile string) (*http.Client, error) {
	if caFile == "" {
		return &http.Client{Timeout: time.Minute}, nil
	}
	data, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("certs: ca_roots_file: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("certs: ca_roots_file %s: no certificates found", caFile)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: tr, Timeout: time.Minute}, nil
}

// Cache returns the autocert.Cache backing the Manager.
func (m *Manager) Cache() *Cache { return m.cache }

// HostPolicy reports whether certificates may be issued and served for host.
// Answers are cached (see Config.PolicyCacheTTL).
func (m *Manager) HostPolicy(ctx context.Context, host string) error {
	return m.policy.allow(ctx, host)
}

// Forget drops the cached host policy decision for host. Call it after a
// domain was verified or removed so the change applies before the cache TTL.
func (m *Manager) Forget(host string) { m.policy.forget(host) }

// TLSConfig returns a TLS config for the HTTPS listener (port 443). It serves
// certificates on demand and answers tls-alpn-01 challenges, so issuance
// works even without the port-80 HTTPHandler.
func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: m.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1", acme.ALPNProto},
		MinVersion:     tls.VersionTLS12,
	}
}

// HTTPHandler returns the port-80 handler: it answers http-01 challenges
// (on any replica, since tokens live in the shared KV) and passes every
// other request to fallback. A nil fallback redirects GET/HEAD to https and
// answers 400 to other methods.
//
// Calling HTTPHandler enables the http-01 challenge in addition to
// tls-alpn-01; if it is never called only tls-alpn-01 is used.
func (m *Manager) HTTPHandler(fallback http.Handler) http.Handler {
	return m.ac.HTTPHandler(fallback)
}

// GetCertificate implements tls.Config.GetCertificate. Use TLSConfig unless
// you assemble the tls.Config yourself (then add acme.ALPNProto to
// NextProtos for tls-alpn-01).
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := normalizeHost(hello.ServerName)
	if host == "" || wantsTokenCert(hello) || !isASCII(host) {
		// Challenge handshakes, and IDN names autocert converts itself.
		return m.ac.GetCertificate(hello)
	}
	ctx := hello.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	if err := m.policy.allow(ctx, host); err != nil {
		if m.hooks.OnDenied != nil {
			m.hooks.OnDenied(host, err)
		}
		return nil, err
	}
	name := host
	if !supportsECDSA(hello) {
		name += "+rsa"
	}
	if m.isReady(name) || m.cachedValid(ctx, name) {
		return m.ac.GetCertificate(hello)
	}

	// No usable certificate anywhere: this handshake triggers issuance.
	// Take the cross-replica lock, or wait for its holder to finish.
	lk := lockKey(m.cfg.KeyPrefix, name)
	deadline := m.now().Add(m.cfg.LockWait)
	for {
		got, err := m.tryLock(ctx, lk)
		if err != nil {
			m.log.Warn("certs: issuance lock unavailable, issuing without it", "host", host, "err", err)
			break
		}
		if got {
			defer m.unlock(lk)
			break
		}
		if !m.now().Before(deadline) {
			m.log.Warn("certs: gave up waiting for the issuance running on another replica", "host", host)
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
		if m.cachedValid(ctx, name) {
			return m.ac.GetCertificate(hello) // the other replica finished
		}
	}
	// The holder may have finished between our first check and our lock.
	if m.cachedValid(ctx, name) {
		return m.ac.GetCertificate(hello)
	}

	cert, err := m.ac.GetCertificate(hello)
	if err != nil {
		m.log.Error("certs: issuance failed", "host", host, "err", err)
		if m.hooks.OnFailed != nil {
			m.hooks.OnFailed(host, err)
		}
		return nil, err
	}
	if cert.Leaf != nil {
		m.ready.Store(name, cert.Leaf.NotAfter)
	}
	return cert, nil
}

// observePut sees every value autocert stores. A certificate entry means a
// certificate was just issued or renewed by this replica.
func (m *Manager) observePut(_ context.Context, name string, data []byte) {
	host, ok := certName(name)
	if !ok {
		return
	}
	leaf, err := parseCertPEM(data)
	if err != nil {
		return
	}
	m.ready.Store(name, leaf.NotAfter)
	m.log.Info("certs: certificate stored", "host", host, "not_after", leaf.NotAfter, "issuer", leaf.Issuer.CommonName)
	if m.hooks.OnIssued != nil {
		m.hooks.OnIssued(host, leaf.NotAfter)
	}
}

func (m *Manager) isReady(name string) bool {
	v, ok := m.ready.Load(name)
	return ok && m.now().Before(v.(time.Time))
}

// cachedValid reports whether the KV holds a currently valid certificate
// under cache name, remembering a positive answer.
func (m *Manager) cachedValid(ctx context.Context, name string) bool {
	data, err := m.cache.Get(ctx, name)
	if err != nil {
		return false
	}
	leaf, err := parseCertPEM(data)
	if err != nil {
		return false
	}
	now := m.now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return false
	}
	m.ready.Store(name, leaf.NotAfter)
	return true
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// wantsTokenCert reports whether hello is a CA's tls-alpn-01 validation.
func wantsTokenCert(hello *tls.ClientHelloInfo) bool {
	return len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == acme.ALPNProto
}

// supportsECDSA mirrors autocert's choice between the ECDSA and the RSA
// certificate (copied from golang.org/x/crypto/acme/autocert, BSD licence).
func supportsECDSA(hello *tls.ClientHelloInfo) bool {
	if hello.SignatureSchemes != nil {
		ecdsaOK := false
	schemeLoop:
		for _, scheme := range hello.SignatureSchemes {
			const tlsECDSAWithSHA1 tls.SignatureScheme = 0x0203
			switch scheme {
			case tlsECDSAWithSHA1, tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384, tls.ECDSAWithP521AndSHA512:
				ecdsaOK = true
				break schemeLoop
			}
		}
		if !ecdsaOK {
			return false
		}
	}
	if hello.SupportedCurves != nil {
		ecdsaOK := false
		for _, curve := range hello.SupportedCurves {
			if curve == tls.CurveP256 {
				ecdsaOK = true
				break
			}
		}
		if !ecdsaOK {
			return false
		}
	}
	for _, suite := range hello.CipherSuites {
		switch suite {
		case tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:
			return true
		}
	}
	return false
}
