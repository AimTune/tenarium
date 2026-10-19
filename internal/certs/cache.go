package certs

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/acme/autocert"
)

// DefaultKeyPrefix namespaces every key this package writes into the KV.
const DefaultKeyPrefix = "certs/"

// Cache implements autocert.Cache on top of a KV. Every key autocert uses is
// stored as Prefix+name, so the same KV (table) can hold other data, or two
// independent managers, without collisions.
//
// autocert stores these names:
//
//	example.com          ECDSA certificate + private key (PEM)
//	example.com+rsa      RSA certificate + private key for legacy clients
//	example.com+token    tls-alpn-01 challenge certificate (short lived)
//	<token>+http-01      http-01 challenge response (short lived)
//	acme_account+key     the ACME account private key
//
// Certificates and the account key contain private keys. Seal and Open, when
// set, wrap every stored value (e.g. envelope encryption by the secrets
// package); they must be inverses of each other.
type Cache struct {
	KV     KV
	Prefix string
	Seal   func([]byte) ([]byte, error)
	Open   func([]byte) ([]byte, error)

	// onPut is called after a successful Put; the Manager uses it to observe
	// newly issued (or renewed) certificates.
	onPut func(ctx context.Context, name string, data []byte)
}

var _ autocert.Cache = (*Cache)(nil)

// NewCache returns a Cache storing values under prefix in kv. An empty prefix
// means DefaultKeyPrefix.
func NewCache(kv KV, prefix string) *Cache {
	if prefix == "" {
		prefix = DefaultKeyPrefix
	}
	return &Cache{KV: kv, Prefix: prefix}
}

func (c *Cache) key(name string) string { return c.Prefix + name }

// Get implements autocert.Cache. A missing key yields autocert.ErrCacheMiss.
func (c *Cache) Get(ctx context.Context, name string) ([]byte, error) {
	data, err := c.KV.Get(ctx, c.key(name))
	if errors.Is(err, ErrNotFound) {
		return nil, autocert.ErrCacheMiss
	}
	if err != nil {
		return nil, err
	}
	if c.Open != nil {
		if data, err = c.Open(data); err != nil {
			return nil, fmt.Errorf("certs: open %s: %w", name, err)
		}
	}
	return data, nil
}

// Put implements autocert.Cache.
func (c *Cache) Put(ctx context.Context, name string, data []byte) error {
	stored := data
	if c.Seal != nil {
		var err error
		if stored, err = c.Seal(data); err != nil {
			return fmt.Errorf("certs: seal %s: %w", name, err)
		}
	}
	if err := c.KV.Put(ctx, c.key(name), stored); err != nil {
		return err
	}
	if c.onPut != nil {
		c.onPut(ctx, name, data)
	}
	return nil
}

// Delete implements autocert.Cache.
func (c *Cache) Delete(ctx context.Context, name string) error {
	err := c.KV.Delete(ctx, c.key(name))
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

// certName classifies an autocert cache name. It returns the hostname and
// true for certificate entries (ECDSA or RSA), false for challenge tokens,
// the account key and anything else.
func certName(name string) (host string, ok bool) {
	if h, found := strings.CutSuffix(name, "+rsa"); found {
		name = h
	}
	if strings.Contains(name, "+") || !strings.Contains(name, ".") {
		return "", false
	}
	return name, true
}
