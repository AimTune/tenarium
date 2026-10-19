package secrets

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// VaultTransitConfig configures the "vault" provider, which wraps data keys
// with HashiCorp Vault's (or OpenBao's) Transit secrets engine.
type VaultTransitConfig struct {
	// Address of the Vault server, e.g. https://vault.internal:8200.
	// Falls back to VAULT_ADDR.
	Address string `yaml:"address" json:"address"`
	// Token used for requests. Falls back to TokenFile, then VAULT_TOKEN.
	// The token needs update on transit/encrypt/<key> and
	// transit/decrypt/<key>.
	Token     string `yaml:"token" json:"token"`
	TokenFile string `yaml:"token_file" json:"token_file"`
	// Namespace (Vault Enterprise / HCP), sent as X-Vault-Namespace.
	Namespace string `yaml:"namespace" json:"namespace"`
	// MountPath of the transit engine. Default "transit".
	MountPath string `yaml:"mount_path" json:"mount_path"`
	// KeyName of the transit key (type aes256-gcm96 recommended).
	KeyName string `yaml:"key_name" json:"key_name"`

	// HTTPClient overrides the HTTP client (custom CA, mTLS, tests).
	HTTPClient *http.Client `yaml:"-" json:"-"`
}

var vaultSegmentRE = regexp.MustCompile(`^[A-Za-z0-9_.\-]+$`)

func validVaultMount(m string) bool {
	for _, seg := range strings.Split(m, "/") {
		if !vaultSegmentRE.MatchString(seg) || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

func (c VaultTransitConfig) withDefaults() VaultTransitConfig {
	if c.Address == "" {
		c.Address = os.Getenv("VAULT_ADDR")
	}
	if c.MountPath == "" {
		c.MountPath = "transit"
	}
	c.MountPath = strings.Trim(c.MountPath, "/")
	c.Address = strings.TrimRight(c.Address, "/")
	return c
}

func (c VaultTransitConfig) validate() error {
	c = c.withDefaults()
	if c.Address == "" {
		return errors.New("vault.address: required (or set VAULT_ADDR)")
	}
	if !strings.HasPrefix(c.Address, "http://") && !strings.HasPrefix(c.Address, "https://") {
		return errors.New("vault.address: must start with http:// or https://")
	}
	if !vaultSegmentRE.MatchString(c.KeyName) {
		return errors.New("vault.key_name: required, letters, digits, '_', '-', '.'")
	}
	if !validVaultMount(c.MountPath) {
		return fmt.Errorf("vault.mount_path: invalid %q", c.MountPath)
	}
	if c.Token != "" && c.TokenFile != "" {
		return errors.New("vault: set only one of token and token_file")
	}
	return nil
}

type vaultProvider struct {
	cfg    VaultTransitConfig
	token  func() (string, error)
	client *http.Client
}

// NewVaultTransitProvider builds the "vault" KeyProvider.
func NewVaultTransitProvider(c VaultTransitConfig, timeout time.Duration) (KeyProvider, error) {
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	c = c.withDefaults()
	p := &vaultProvider{cfg: c, client: httpClientOr(c.HTTPClient, timeout)}
	switch {
	case c.Token != "":
		tok := c.Token
		p.token = func() (string, error) { return tok, nil }
	case c.TokenFile != "":
		// Re-read on every call so an agent-rotated token file is honoured.
		path := c.TokenFile
		p.token = func() (string, error) {
			b, err := os.ReadFile(path)
			if err != nil {
				return "", fmt.Errorf("vault: reading token file: %w", err)
			}
			return strings.TrimSpace(string(b)), nil
		}
		if _, err := p.token(); err != nil {
			return nil, fmt.Errorf("secrets: %w", err)
		}
	default:
		tok := os.Getenv("VAULT_TOKEN")
		if tok == "" {
			return nil, errors.New("secrets: vault.token: required (or token_file, or VAULT_TOKEN)")
		}
		p.token = func() (string, error) { return tok, nil }
	}
	return p, nil
}

func (p *vaultProvider) Name() string { return "vault" }

// Key ids recorded in ciphertexts are "<mount>/<key>".
func (p *vaultProvider) Wrap(ctx context.Context, dek []byte) (string, []byte, error) {
	var out struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	err := p.call(ctx, p.cfg.MountPath, "encrypt", p.cfg.KeyName,
		map[string]string{"plaintext": base64.StdEncoding.EncodeToString(dek)}, &out)
	if err != nil {
		return "", nil, err
	}
	if !strings.HasPrefix(out.Data.Ciphertext, "vault:") {
		return "", nil, errors.New("vault: unexpected ciphertext format")
	}
	return p.cfg.MountPath + "/" + p.cfg.KeyName, []byte(out.Data.Ciphertext), nil
}

func (p *vaultProvider) Unwrap(ctx context.Context, keyID string, wrapped []byte) ([]byte, error) {
	i := strings.LastIndexByte(keyID, '/')
	if i <= 0 {
		return nil, fmt.Errorf("vault: invalid key id %q", keyID)
	}
	mount, key := keyID[:i], keyID[i+1:]
	if !validVaultMount(mount) || !vaultSegmentRE.MatchString(key) {
		return nil, fmt.Errorf("vault: invalid key id %q", keyID)
	}
	var out struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	err := p.call(ctx, mount, "decrypt", key, map[string]string{"ciphertext": string(wrapped)}, &out)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.Data.Plaintext)
}

func (p *vaultProvider) call(ctx context.Context, mount, op, key string, payload any, out any) error {
	url := p.cfg.Address + "/v1/" + mount + "/" + op + "/" + key
	return doJSON(ctx, p.client, "vault", func() (*http.Request, error) {
		req, _, err := jsonRequest(ctx, url, payload)
		if err != nil {
			return nil, err
		}
		tok, err := p.token()
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-Vault-Token", tok)
		req.Header.Set("X-Vault-Request", "true")
		if p.cfg.Namespace != "" {
			req.Header.Set("X-Vault-Namespace", p.cfg.Namespace)
		}
		return req, nil
	}, out)
}
