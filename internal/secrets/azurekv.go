package secrets

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// AzureKeyVaultConfig configures the "azurekv" provider, which wraps data
// keys with an Azure Key Vault (or Managed HSM) RSA key using the
// wrapkey / unwrapkey operations, authenticating with an Entra ID app
// registration (client credentials).
type AzureKeyVaultConfig struct {
	// VaultURL, e.g. https://my-vault.vault.azure.net
	VaultURL string `yaml:"vault_url" json:"vault_url"`
	// KeyName of an RSA key with wrapKey/unwrapKey permitted.
	KeyName string `yaml:"key_name" json:"key_name"`
	// KeyVersion pins a version; empty uses the current version. The
	// version actually used is recorded in each ciphertext.
	KeyVersion string `yaml:"key_version" json:"key_version"`
	// Algorithm: RSA-OAEP-256 (default) or RSA-OAEP.
	Algorithm string `yaml:"algorithm" json:"algorithm"`
	// Entra ID client-credentials settings.
	TenantID     string `yaml:"tenant_id" json:"tenant_id"`
	ClientID     string `yaml:"client_id" json:"client_id"`
	ClientSecret string `yaml:"client_secret" json:"client_secret"`
	// AuthorityHost defaults to https://login.microsoftonline.com
	// (sovereign clouds: login.microsoftonline.us, login.chinacloudapi.cn).
	AuthorityHost string `yaml:"authority_host" json:"authority_host"`
	// Scope defaults to https://vault.azure.net/.default (use
	// https://managedhsm.azure.net/.default for Managed HSM).
	Scope string `yaml:"scope" json:"scope"`
	// APIVersion defaults to 7.4.
	APIVersion string `yaml:"api_version" json:"api_version"`

	// TokenSource overrides client-credentials auth (tests, managed identity
	// adapters).
	TokenSource oauth2.TokenSource `yaml:"-" json:"-"`
	// HTTPClient overrides the HTTP client.
	HTTPClient *http.Client `yaml:"-" json:"-"`
}

var azureNameRE = regexp.MustCompile(`^[A-Za-z0-9-]{1,127}$`)

func (c AzureKeyVaultConfig) withDefaults() AzureKeyVaultConfig {
	c.VaultURL = strings.TrimRight(c.VaultURL, "/")
	if c.Algorithm == "" {
		c.Algorithm = "RSA-OAEP-256"
	}
	if c.AuthorityHost == "" {
		c.AuthorityHost = "https://login.microsoftonline.com"
	}
	c.AuthorityHost = strings.TrimRight(c.AuthorityHost, "/")
	if c.Scope == "" {
		c.Scope = "https://vault.azure.net/.default"
	}
	if c.APIVersion == "" {
		c.APIVersion = "7.4"
	}
	return c
}

func (c AzureKeyVaultConfig) validate() error {
	c = c.withDefaults()
	u, err := url.Parse(c.VaultURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || (u.Path != "" && u.Path != "/") {
		return errors.New("azure_key_vault.vault_url: must be https://<name>.vault.azure.net")
	}
	if !azureNameRE.MatchString(c.KeyName) {
		return errors.New("azure_key_vault.key_name: required, letters, digits and '-'")
	}
	if c.KeyVersion != "" && !azureNameRE.MatchString(c.KeyVersion) {
		return errors.New("azure_key_vault.key_version: invalid")
	}
	switch c.Algorithm {
	case "RSA-OAEP-256", "RSA-OAEP":
	default:
		return fmt.Errorf("azure_key_vault.algorithm: unsupported %q (RSA-OAEP-256 or RSA-OAEP)", c.Algorithm)
	}
	if c.TokenSource == nil && (c.TenantID == "" || c.ClientID == "" || c.ClientSecret == "") {
		return errors.New("azure_key_vault: tenant_id, client_id and client_secret are required")
	}
	return nil
}

type azureKVProvider struct {
	cfg    AzureKeyVaultConfig
	ts     oauth2.TokenSource
	client *http.Client
	// kidRE matches key ids under the configured vault and key name only, so
	// a tampered ciphertext cannot make us send a bearer token elsewhere.
	kidRE *regexp.Regexp
}

// NewAzureKeyVaultProvider builds the "azurekv" KeyProvider.
func NewAzureKeyVaultProvider(ctx context.Context, c AzureKeyVaultConfig, timeout time.Duration) (KeyProvider, error) {
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	c = c.withDefaults()
	client := httpClientOr(c.HTTPClient, timeout)
	ts := c.TokenSource
	if ts == nil {
		cc := &clientcredentials.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			TokenURL:     c.AuthorityHost + "/" + url.PathEscape(c.TenantID) + "/oauth2/v2.0/token",
			Scopes:       []string{c.Scope},
			AuthStyle:    oauth2.AuthStyleInParams,
		}
		tctx := context.WithValue(context.WithoutCancel(ctx), oauth2.HTTPClient, client)
		ts = cc.TokenSource(tctx)
	}
	return &azureKVProvider{
		cfg:    c,
		ts:     oauth2.ReuseTokenSource(nil, ts),
		client: client,
		kidRE:  regexp.MustCompile(`^` + regexp.QuoteMeta(c.VaultURL) + `(?::443)?/keys/` + regexp.QuoteMeta(c.KeyName) + `/[A-Za-z0-9-]{1,127}$`),
	}, nil
}

func (p *azureKVProvider) Name() string { return "azurekv" }

type azureKeyOp struct {
	Alg   string `json:"alg"`
	Value string `json:"value"`
}

type azureKeyOpResult struct {
	Kid   string `json:"kid"`
	Value string `json:"value"`
}

func (p *azureKVProvider) Wrap(ctx context.Context, dek []byte) (string, []byte, error) {
	keyURL := p.cfg.VaultURL + "/keys/" + p.cfg.KeyName
	if p.cfg.KeyVersion != "" {
		keyURL += "/" + p.cfg.KeyVersion
	}
	var out azureKeyOpResult
	if err := p.call(ctx, keyURL+"/wrapkey", azureKeyOp{Alg: p.cfg.Algorithm, Value: b64.EncodeToString(dek)}, &out); err != nil {
		return "", nil, err
	}
	kid := strings.Replace(out.Kid, ":443/", "/", 1)
	if !p.kidRE.MatchString(kid) {
		return "", nil, fmt.Errorf("azure key vault: unexpected kid %q in response", out.Kid)
	}
	wrapped, err := decodeB64Any(out.Value)
	if err != nil {
		return "", nil, fmt.Errorf("azure key vault: bad wrapped key: %w", err)
	}
	// Record the algorithm with the versioned kid so a later default
	// change does not break old values: "<alg> <kid>".
	return p.cfg.Algorithm + " " + kid, wrapped, nil
}

func (p *azureKVProvider) Unwrap(ctx context.Context, keyID string, wrapped []byte) ([]byte, error) {
	alg, kid, ok := strings.Cut(keyID, " ")
	if !ok || (alg != "RSA-OAEP-256" && alg != "RSA-OAEP") || !p.kidRE.MatchString(kid) {
		return nil, fmt.Errorf("azure key vault: key id %q is not a key of the configured vault", keyID)
	}
	var out azureKeyOpResult
	if err := p.call(ctx, kid+"/unwrapkey", azureKeyOp{Alg: alg, Value: b64.EncodeToString(wrapped)}, &out); err != nil {
		return nil, err
	}
	return decodeB64Any(out.Value)
}

func (p *azureKVProvider) call(ctx context.Context, opURL string, payload any, out any) error {
	full := opURL + "?api-version=" + url.QueryEscape(p.cfg.APIVersion)
	return doJSON(ctx, p.client, "azurekv", func() (*http.Request, error) {
		req, _, err := jsonRequest(ctx, full, payload)
		if err != nil {
			return nil, err
		}
		tok, err := p.ts.Token()
		if err != nil {
			return nil, fmt.Errorf("azure key vault: obtaining token: %w", err)
		}
		tok.SetAuthHeader(req)
		return req, nil
	}, out)
}

// decodeB64Any accepts base64url (what Key Vault returns) with or without
// padding, and standard base64.
func decodeB64Any(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}
