package secrets

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Provider names accepted in Config.Provider.
const (
	ProviderNone   = "none"
	ProviderLocal  = "local"
	ProviderAWS    = "awskms"
	ProviderGCP    = "gcpkms"
	ProviderVault  = "vault"
	ProviderAzure  = "azurekv"
	maxDEKMaxUses  = 1 << 32
	minDEKLifetime = time.Second
)

// Config selects and configures the keyring. Example (YAML):
//
//	secrets:
//	  provider: vault
//	  vault:
//	    address: https://vault.internal:8200
//	    token_file: /var/run/secrets/vault-token
//	    key_name: tenarium
//	  # keep decrypting values written while running on the local provider
//	  decrypt_providers: [local]
//	  local:
//	    primary: k2
//	    keys:
//	      k1: "base64..."
//	      k2: "base64..."
type Config struct {
	// Provider used for new encryptions: none, local, awskms, gcpkms,
	// vault, azurekv. Empty means none (values stored as plaintext;
	// encrypted values cannot be read).
	Provider string `yaml:"provider" json:"provider"`
	// DecryptProviders are additional providers kept for decrypting values
	// written before a provider migration. Their sections must be filled in.
	DecryptProviders []string `yaml:"decrypt_providers" json:"decrypt_providers"`

	// DEKTTL is how long one data key is reused for new values (default 1h).
	DEKTTL time.Duration `yaml:"dek_ttl" json:"dek_ttl"`
	// DEKMaxUses caps encryptions per data key (default 2^24).
	DEKMaxUses uint64 `yaml:"dek_max_uses" json:"dek_max_uses"`
	// DecryptCacheSize bounds cached unwrapped data keys (default 1024,
	// negative disables caching: every Decrypt calls the KMS).
	DecryptCacheSize int `yaml:"decrypt_cache_size" json:"decrypt_cache_size"`
	// RejectPlaintext makes Decrypt refuse unencrypted values. Turn on once
	// every row has been migrated with Rotate.
	RejectPlaintext bool `yaml:"reject_plaintext" json:"reject_plaintext"`
	// Timeout per KMS HTTP request (default 30s).
	Timeout time.Duration `yaml:"timeout" json:"timeout"`

	Local         LocalConfig         `yaml:"local" json:"local"`
	AWSKMS        AWSKMSConfig        `yaml:"aws_kms" json:"aws_kms"`
	GCPKMS        GCPKMSConfig        `yaml:"gcp_kms" json:"gcp_kms"`
	Vault         VaultTransitConfig  `yaml:"vault" json:"vault"`
	AzureKeyVault AzureKeyVaultConfig `yaml:"azure_key_vault" json:"azure_key_vault"`
}

// Validate checks the configuration without contacting any KMS.
func (c Config) Validate() error {
	var errs []error
	provider := c.Provider
	if provider == "" {
		provider = ProviderNone
	}
	seen := map[string]bool{}
	for i, name := range append([]string{provider}, c.DecryptProviders...) {
		field := "provider"
		if i > 0 {
			field = fmt.Sprintf("decrypt_providers[%d]", i-1)
			if name == ProviderNone {
				errs = append(errs, fmt.Errorf("secrets.%s: %q cannot decrypt anything", field, name))
				continue
			}
		}
		if seen[name] {
			errs = append(errs, fmt.Errorf("secrets.%s: %q listed twice", field, name))
			continue
		}
		seen[name] = true
		if err := c.validateProvider(name); err != nil {
			errs = append(errs, fmt.Errorf("secrets.%s: %w", field, err))
		}
	}
	if provider == ProviderNone && len(c.DecryptProviders) > 0 {
		errs = append(errs, errors.New("secrets.decrypt_providers: requires an encrypting provider"))
	}
	if c.DEKTTL < 0 || (c.DEKTTL > 0 && c.DEKTTL < minDEKLifetime) {
		errs = append(errs, errors.New("secrets.dek_ttl: must be at least 1s"))
	}
	if c.DEKMaxUses > maxDEKMaxUses {
		errs = append(errs, errors.New("secrets.dek_max_uses: must be at most 2^32 (AES-GCM random nonce limit)"))
	}
	if c.Timeout < 0 {
		errs = append(errs, errors.New("secrets.timeout: must not be negative"))
	}
	return errors.Join(errs...)
}

func (c Config) validateProvider(name string) error {
	switch name {
	case ProviderNone:
		return nil
	case ProviderLocal:
		return c.Local.validate()
	case ProviderAWS:
		return c.AWSKMS.validate()
	case ProviderGCP:
		return c.GCPKMS.validate()
	case ProviderVault:
		return c.Vault.validate()
	case ProviderAzure:
		return c.AzureKeyVault.validate()
	default:
		return fmt.Errorf("unknown provider %q (none, local, awskms, gcpkms, vault, azurekv)", name)
	}
}

// New validates c and builds the keyring. Cloud providers resolve
// credentials here but make no KMS calls until the first Encrypt/Decrypt.
func New(ctx context.Context, c Config) (Keyring, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if c.Provider == "" || c.Provider == ProviderNone {
		return plaintextKeyring{}, nil
	}
	primary, err := c.buildProvider(ctx, c.Provider)
	if err != nil {
		return nil, err
	}
	var extra []KeyProvider
	for _, name := range c.DecryptProviders {
		p, err := c.buildProvider(ctx, name)
		if err != nil {
			return nil, err
		}
		extra = append(extra, p)
	}
	return NewEnvelope(primary, extra, EnvelopeOptions{
		DEKTTL:           c.DEKTTL,
		DEKMaxUses:       c.DEKMaxUses,
		DecryptCacheSize: c.DecryptCacheSize,
		RejectPlaintext:  c.RejectPlaintext,
	})
}

func (c Config) buildProvider(ctx context.Context, name string) (KeyProvider, error) {
	switch name {
	case ProviderLocal:
		return NewLocalProvider(c.Local)
	case ProviderAWS:
		return NewAWSKMSProvider(ctx, c.AWSKMS, c.Timeout)
	case ProviderGCP:
		return NewGCPKMSProvider(ctx, c.GCPKMS, c.Timeout)
	case ProviderVault:
		return NewVaultTransitProvider(c.Vault, c.Timeout)
	case ProviderAzure:
		return NewAzureKeyVaultProvider(ctx, c.AzureKeyVault, c.Timeout)
	}
	return nil, fmt.Errorf("secrets: unknown provider %q", name)
}

// plaintextKeyring is the "none" provider: values are stored as given. It
// exists so callers can always go through a Keyring. It refuses to read
// encrypted values (encryption was configured before and then removed) and
// to write values that would be mistaken for ciphertexts.
type plaintextKeyring struct{}

func (plaintextKeyring) Encrypt(_ context.Context, plaintext []byte, _ string) (string, error) {
	s := string(plaintext)
	if IsEncrypted(s) {
		return "", errors.New("secrets: plaintext value looks like a ciphertext; enable a provider")
	}
	return s, nil
}

func (plaintextKeyring) Decrypt(_ context.Context, stored string, _ string) ([]byte, error) {
	if IsEncrypted(stored) {
		return nil, fmt.Errorf("%w: value is encrypted but secrets.provider is none", ErrUnknownProvider)
	}
	return []byte(stored), nil
}

// NoopKeyring returns the keyring used when no provider is configured.
func NoopKeyring() Keyring { return plaintextKeyring{} }
