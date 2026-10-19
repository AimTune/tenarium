package secrets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// GCPKMSConfig configures the "gcpkms" provider, which wraps data keys with
// a Cloud KMS symmetric CryptoKey via the REST API (:encrypt / :decrypt).
type GCPKMSConfig struct {
	// KeyName is the CryptoKey resource name:
	// projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>.
	// Cloud KMS picks the primary version on encrypt and finds the right
	// version on decrypt, so KMS-side rotation needs no config change.
	KeyName string `yaml:"key_name" json:"key_name"`
	// CredentialsFile / CredentialsJSON hold a service account key (or other
	// google credentials JSON). When both are empty, Application Default
	// Credentials are used (GKE workload identity, GCE metadata, gcloud).
	CredentialsFile string `yaml:"credentials_file" json:"credentials_file"`
	CredentialsJSON string `yaml:"credentials_json" json:"credentials_json"`
	// Endpoint overrides https://cloudkms.googleapis.com.
	Endpoint string `yaml:"endpoint" json:"endpoint"`

	// TokenSource overrides credential discovery (tests).
	TokenSource oauth2.TokenSource `yaml:"-" json:"-"`
	// HTTPClient overrides the HTTP client used for KMS calls.
	HTTPClient *http.Client `yaml:"-" json:"-"`
}

var gcpKeyNameRE = regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$`)

func (c GCPKMSConfig) validate() error {
	if !gcpKeyNameRE.MatchString(c.KeyName) {
		return errors.New("gcp_kms.key_name: must be projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>")
	}
	if c.CredentialsFile != "" && c.CredentialsJSON != "" {
		return errors.New("gcp_kms: set only one of credentials_file and credentials_json")
	}
	return nil
}

const gcpKMSScope = "https://www.googleapis.com/auth/cloudkms"

type gcpKMSProvider struct {
	cfg      GCPKMSConfig
	endpoint string
	ts       oauth2.TokenSource
	client   *http.Client
}

// NewGCPKMSProvider builds the "gcpkms" KeyProvider.
func NewGCPKMSProvider(ctx context.Context, c GCPKMSConfig, timeout time.Duration) (KeyProvider, error) {
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	ts := c.TokenSource
	if ts == nil {
		var err error
		ts, err = gcpTokenSource(ctx, c)
		if err != nil {
			return nil, fmt.Errorf("secrets: gcp_kms: %w", err)
		}
	}
	endpoint := strings.TrimRight(c.Endpoint, "/")
	if endpoint == "" {
		endpoint = "https://cloudkms.googleapis.com"
	}
	return &gcpKMSProvider{
		cfg:      c,
		endpoint: endpoint,
		ts:       oauth2.ReuseTokenSource(nil, ts),
		client:   httpClientOr(c.HTTPClient, timeout),
	}, nil
}

func gcpTokenSource(ctx context.Context, c GCPKMSConfig) (oauth2.TokenSource, error) {
	raw := []byte(c.CredentialsJSON)
	if c.CredentialsFile != "" {
		b, err := os.ReadFile(c.CredentialsFile)
		if err != nil {
			return nil, fmt.Errorf("reading credentials file: %w", err)
		}
		raw = b
	}
	// Token refreshes outlive the constructor's ctx.
	bg := context.WithoutCancel(ctx)
	if len(raw) == 0 {
		creds, err := google.FindDefaultCredentials(bg, gcpKMSScope)
		if err != nil {
			return nil, fmt.Errorf("finding default credentials: %w", err)
		}
		return creds.TokenSource, nil
	}
	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, fmt.Errorf("parsing credentials JSON: %w", err)
	}
	t := google.CredentialsType(head.Type)
	switch t {
	case google.ServiceAccount, google.AuthorizedUser, google.ExternalAccount, google.ImpersonatedServiceAccount:
	default:
		return nil, fmt.Errorf("unsupported credentials type %q", head.Type)
	}
	creds, err := google.CredentialsFromJSONWithType(bg, raw, t, gcpKMSScope)
	if err != nil {
		return nil, err
	}
	return creds.TokenSource, nil
}

func (p *gcpKMSProvider) Name() string { return "gcpkms" }

var gcpAAD = base64.StdEncoding.EncodeToString([]byte(dekContext))

func (p *gcpKMSProvider) Wrap(ctx context.Context, dek []byte) (string, []byte, error) {
	var out struct {
		Name       string `json:"name"`
		Ciphertext string `json:"ciphertext"`
	}
	err := p.call(ctx, p.cfg.KeyName, "encrypt", map[string]string{
		"plaintext":                   base64.StdEncoding.EncodeToString(dek),
		"additionalAuthenticatedData": gcpAAD,
	}, &out)
	if err != nil {
		return "", nil, err
	}
	ct, err := base64.StdEncoding.DecodeString(out.Ciphertext)
	if err != nil {
		return "", nil, fmt.Errorf("gcp kms: bad ciphertext: %w", err)
	}
	// Record the CryptoKey (not the version): :decrypt is addressed to the
	// key and the version is embedded in the ciphertext.
	return p.cfg.KeyName, ct, nil
}

func (p *gcpKMSProvider) Unwrap(ctx context.Context, keyID string, wrapped []byte) ([]byte, error) {
	// keyID comes from the database; only well-formed key names are sent,
	// and only to the configured endpoint.
	if !gcpKeyNameRE.MatchString(keyID) {
		return nil, fmt.Errorf("gcp kms: invalid key name %q", keyID)
	}
	var out struct {
		Plaintext string `json:"plaintext"`
	}
	err := p.call(ctx, keyID, "decrypt", map[string]string{
		"ciphertext":                  base64.StdEncoding.EncodeToString(wrapped),
		"additionalAuthenticatedData": gcpAAD,
	}, &out)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.Plaintext)
}

func (p *gcpKMSProvider) call(ctx context.Context, keyName, method string, payload any, out any) error {
	url := p.endpoint + "/v1/" + keyName + ":" + method
	return doJSON(ctx, p.client, "gcpkms", func() (*http.Request, error) {
		req, _, err := jsonRequest(ctx, url, payload)
		if err != nil {
			return nil, err
		}
		tok, err := p.ts.Token()
		if err != nil {
			return nil, fmt.Errorf("gcp kms: obtaining token: %w", err)
		}
		tok.SetAuthHeader(req)
		return req, nil
	}, out)
}
