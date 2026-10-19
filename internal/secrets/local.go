package secrets

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// LocalConfig configures the "local" provider: AES-256-GCM key-encryption
// keys held in configuration. Suitable for development and self-hosted
// installs; the KEKs must be kept out of the database and its backups (env
// vars, a mounted secret file, a sealed config).
type LocalConfig struct {
	// Keys maps key id to a base64 (standard or URL, padded or not)
	// encoded 32-byte key. Keep retired keys here so old values decrypt.
	Keys map[string]string `yaml:"keys" json:"keys"`
	// Primary is the id of the key used for new encryptions.
	Primary string `yaml:"primary" json:"primary"`
}

func (c LocalConfig) validate() error {
	if len(c.Keys) == 0 {
		return errors.New("local.keys: at least one key is required")
	}
	if c.Primary == "" {
		return errors.New("local.primary: required")
	}
	if _, ok := c.Keys[c.Primary]; !ok {
		return fmt.Errorf("local.primary: key %q not in local.keys", c.Primary)
	}
	ids := make([]string, 0, len(c.Keys))
	for id := range c.Keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if strings.TrimSpace(id) == "" || len(id) > 128 {
			return fmt.Errorf("local.keys: invalid key id %q", id)
		}
		if _, err := decodeKey(c.Keys[id]); err != nil {
			return fmt.Errorf("local.keys[%s]: %w", id, err)
		}
	}
	return nil
}

func decodeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			if len(b) != 32 {
				return nil, fmt.Errorf("key must be 32 bytes, got %d", len(b))
			}
			return b, nil
		}
	}
	return nil, errors.New("key is not valid base64")
}

// GenerateLocalKey returns a new random 256-bit key, base64 encoded, for
// LocalConfig.Keys.
func GenerateLocalKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

type localProvider struct {
	primary string
	keys    map[string][]byte
}

// NewLocalProvider builds the "local" KeyProvider.
func NewLocalProvider(c LocalConfig) (KeyProvider, error) {
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	p := &localProvider{primary: c.Primary, keys: map[string][]byte{}}
	for id, v := range c.Keys {
		p.keys[id], _ = decodeKey(v)
	}
	return p, nil
}

func (p *localProvider) Name() string { return "local" }

func (p *localProvider) Wrap(_ context.Context, dek []byte) (string, []byte, error) {
	aead, err := newGCM(p.keys[p.primary])
	if err != nil {
		return "", nil, err
	}
	nonce := make([]byte, nonceSize, nonceSize+len(dek)+tagSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", nil, err
	}
	return p.primary, aead.Seal(nonce, nonce, dek, localAAD(p.primary)), nil
}

func (p *localProvider) Unwrap(_ context.Context, keyID string, wrapped []byte) ([]byte, error) {
	kek, ok := p.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("local key %q not configured", keyID)
	}
	if len(wrapped) < nonceSize+tagSize {
		return nil, ErrDecrypt
	}
	aead, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	dek, err := aead.Open(nil, wrapped[:nonceSize], wrapped[nonceSize:], localAAD(keyID))
	if err != nil {
		return nil, ErrDecrypt
	}
	return dek, nil
}

func localAAD(keyID string) []byte { return []byte(dekContext + "\x00local\x00" + keyID) }
