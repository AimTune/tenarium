package certs

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// CertStatus describes a certificate held in the shared cache.
type CertStatus struct {
	Host      string    `json:"host"`
	KeyType   string    `json:"key_type"` // "ecdsa" or "rsa"
	Issuer    string    `json:"issuer"`   // issuer common name
	IssuerOrg string    `json:"issuer_org,omitempty"`
	Serial    string    `json:"serial"` // hex
	DNSNames  []string  `json:"dns_names"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
}

// ExpiresIn returns the time left until expiry, relative to now.
func (s CertStatus) ExpiresIn(now time.Time) time.Duration { return s.NotAfter.Sub(now) }

// Status returns the cached certificate for host (the ECDSA one, or the RSA
// one if only that exists). It returns ErrNotFound when no certificate has
// been issued yet. It reads the shared KV, so it reflects every replica.
func (m *Manager) Status(ctx context.Context, host string) (CertStatus, error) {
	host = normalizeHost(host)
	for _, v := range []struct{ name, typ string }{{host, "ecdsa"}, {host + "+rsa", "rsa"}} {
		data, err := m.cache.Get(ctx, v.name)
		if errors.Is(err, autocert.ErrCacheMiss) {
			continue
		}
		if err != nil {
			return CertStatus{}, err
		}
		leaf, err := parseCertPEM(data)
		if err != nil {
			return CertStatus{}, fmt.Errorf("certs: cached certificate for %s: %w", host, err)
		}
		st := CertStatus{Host: host, KeyType: v.typ, Issuer: leaf.Issuer.CommonName,
			Serial: leaf.SerialNumber.Text(16), DNSNames: leaf.DNSNames,
			NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}
		if len(leaf.Issuer.Organization) > 0 {
			st.IssuerOrg = leaf.Issuer.Organization[0]
		}
		return st, nil
	}
	return CertStatus{}, ErrNotFound
}

// parseCertPEM parses autocert's cache format: a private key block followed
// by the certificate chain, leaf first. It returns the leaf.
func parseCertPEM(data []byte) (*x509.Certificate, error) {
	var chain [][]byte
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			chain = append(chain, b.Bytes)
		}
	}
	if len(chain) == 0 {
		return nil, errors.New("no certificate in PEM data")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, err
	}
	return leaf, nil
}
