package server

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/AimTune/tenarium/internal/plugin"
	"github.com/AimTune/tenarium/internal/secrets"
	"github.com/AimTune/tenarium/internal/social"
	"github.com/AimTune/tenarium/internal/tenant"
	"gopkg.in/yaml.v3"
)

// Config is the server configuration, usually loaded from YAML. ${VAR}
// references are expanded from the environment before parsing so secrets
// can stay out of the file.
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Log       LogConfig       `yaml:"log"`
	Store     StoreConfig     `yaml:"store"`
	Events    EventsConfig    `yaml:"events"`
	Tenants   TenantsConfig   `yaml:"tenants"`
	Scheduler SchedulerConfig `yaml:"scheduler"`
	Usage     UsageConfig     `yaml:"usage"`
	Webhooks  WebhooksConfig  `yaml:"webhooks"`
	Bootstrap BootstrapConfig `yaml:"bootstrap"`
	Users     UsersConfig     `yaml:"users"`
	Auth      AuthConfig      `yaml:"auth"`
	UI        UIConfig        `yaml:"ui"`
	Tracing   TracingConfig   `yaml:"tracing"`
	// Secrets encrypts stored secrets (signing keys, TOTP, webhook and SSO
	// secrets) with a KMS; empty provider stores them as-is.
	Secrets secrets.Config `yaml:"secrets"`
	Plugins []PluginSpec   `yaml:"plugins"`
}

// PluginSpec configures one plugin instance.
type PluginSpec = plugin.Spec

// PluginScope limits a plugin instance to some tenants.
type PluginScope = plugin.Scope

type ServerConfig struct {
	Addr    string   `yaml:"addr"`
	APIKeys []string `yaml:"api_keys"`
	// AllowAnonymous serves the API without authentication when no API
	// keys or authenticator plugins are configured. Development only.
	AllowAnonymous  bool          `yaml:"allow_anonymous"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
	// TLS serves HTTPS with a static certificate or ACME (see TLSConfig).
	TLS TLSConfig `yaml:"tls"`
}

type LogConfig struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Format string `yaml:"format"` // text, json
}

type StoreConfig struct {
	Driver string `yaml:"driver"` // memory | postgres
	// DSN is the PostgreSQL connection string, e.g.
	// postgres://user:pass@host:5432/tenarium?sslmode=disable
	DSN string `yaml:"dsn"`
	// ReadDSN, if set, is a read replica for list queries (tenants, users,
	// events, audit), which may then lag behind writes by the replication
	// delay. Everything else uses DSN.
	ReadDSN string `yaml:"read_dsn"`
}

type EventsConfig struct {
	PollInterval   time.Duration `yaml:"poll_interval"`
	BatchSize      int           `yaml:"batch_size"`
	HandlerTimeout time.Duration `yaml:"handler_timeout"`
	// LeaseTTL bounds failover time when running several instances.
	LeaseTTL time.Duration `yaml:"lease_ttl"`
	// InstanceID names this instance as lease owner (default: random).
	InstanceID string `yaml:"instance_id"`
	// Region is where this instance runs: subscriptions of plugins scoped to
	// regions run on instances in one of those regions when any is up.
	Region string `yaml:"region"`
	// Retention deletes events older than this once every subscription has
	// processed them; 0 keeps them forever. Archive events first with a
	// subscription (e.g. kafka or webhook) if you need them longer.
	Retention time.Duration `yaml:"retention"`
	// PruneInterval is how often retention runs (default 1h).
	PruneInterval time.Duration `yaml:"prune_interval"`
}

type TenantsConfig struct {
	// RequireKnownPlans rejects tenants whose plan is not a defined plan.
	RequireKnownPlans bool `yaml:"require_known_plans"`
	// SettingsSchema is a JSON Schema (as YAML or JSON) every tenant's
	// settings must satisfy. SettingsSchemaFile loads it from a file.
	SettingsSchema     map[string]any `yaml:"settings_schema"`
	SettingsSchemaFile string         `yaml:"settings_schema_file"`
	// MemberRoles are the allowed member roles.
	MemberRoles []string `yaml:"member_roles"`
	// ReservedDomains (and their subdomains) cannot be claimed as custom
	// domains, e.g. the platform's own domain.
	ReservedDomains []string `yaml:"reserved_domains"`
	// DeletionGracePeriod, if set, makes deletion suspend the tenant and
	// schedule the actual deletion after this period; it can be restored
	// until then.
	DeletionGracePeriod time.Duration `yaml:"deletion_grace_period"`
	// PurgeAfter removes the data of deleted tenants (members, usage, keys,
	// domains, webhooks, SSO, roles, groups) after this long; 0 keeps it.
	PurgeAfter time.Duration `yaml:"purge_after"`
	// Regions are the allowed tenant regions (data residency); new tenants
	// must be in one. DefaultRegion is used when neither the request nor
	// the parent tenant names one.
	Regions       []string `yaml:"regions"`
	DefaultRegion string   `yaml:"default_region"`
}

// WebhooksConfig configures self-service tenant webhooks.
type WebhooksConfig struct {
	Enabled bool `yaml:"enabled"`
	// Timeout per request (default 10s); Attempts per event (default 3).
	Timeout  time.Duration `yaml:"timeout"`
	Attempts int           `yaml:"attempts"`
	// MaxFailures disables an endpoint after that many consecutive failed
	// events (0: never).
	MaxFailures  int `yaml:"max_failures"`
	MaxPerTenant int `yaml:"max_per_tenant"`
	// AllowHTTP and AllowPrivateNetworks are for development only: they
	// let tenants target plain-http and internal addresses.
	AllowHTTP            bool          `yaml:"allow_http"`
	AllowPrivateNetworks bool          `yaml:"allow_private_networks"`
	DeliveryRetention    time.Duration `yaml:"delivery_retention"`
}

// UsageConfig configures metered metrics.
type UsageConfig struct {
	// Metrics maps a metric name to its period (day, month, year; empty
	// never resets), overage policy (block, allow) and warning thresholds
	// (percent of the limit).
	Metrics map[string]tenant.MetricPolicy `yaml:"metrics"`
}

// SchedulerConfig configures the runner of scheduled tenant actions.
type SchedulerConfig struct {
	// Interval between checks for due actions; 0 disables the runner on
	// this instance.
	Interval time.Duration `yaml:"interval"`
}

// BootstrapConfig seeds data at startup; existing records are left alone,
// so it is safe to run on every start.
type BootstrapConfig struct {
	Plans []BootstrapPlan `yaml:"plans"`
	// Users are created if their email is unknown, e.g. the first admin.
	Users []BootstrapUser `yaml:"users"`
}

type BootstrapUser struct {
	Email    string   `yaml:"email"`
	Name     string   `yaml:"name"`
	Roles    []string `yaml:"roles"`
	Password string   `yaml:"password"`
}

// UsersConfig configures user management.
type UsersConfig struct {
	// Directory is "internal" (default) or the instance name of a plugin
	// providing a user directory (e.g. keycloak).
	Directory string `yaml:"directory"`
	// Mailer is the instance name of a mailer plugin (e.g. smtp). Default:
	// the only configured mailer, or log the emails.
	Mailer string `yaml:"mailer"`
	// PublicURL is where users reach Tenarium (for links in emails).
	PublicURL         string        `yaml:"public_url"`
	ProductName       string        `yaml:"product_name"`
	PasswordMinLength int           `yaml:"password_min_length"`
	InvitationTTL     time.Duration `yaml:"invitation_ttl"`
	ResetTTL          time.Duration `yaml:"reset_ttl"`
	Lockout           LockoutConfig `yaml:"lockout"`
	// BreachedPasswordCheck rejects new passwords found in the Have I Been
	// Pwned corpus (k-anonymity: only a 5-character hash prefix is sent).
	BreachedPasswordCheck bool `yaml:"breached_password_check"`
	// MagicLinkTTL enables passwordless sign-in by emailed link (e.g. 15m).
	MagicLinkTTL time.Duration `yaml:"magic_link_ttl"`
	// EmailChangeTTL bounds email-change confirmation links (default 24h).
	EmailChangeTTL time.Duration                   `yaml:"email_change_ttl"`
	Templates      map[string]tenant.EmailTemplate `yaml:"templates"`
}

type LockoutConfig struct {
	MaxFailures int           `yaml:"max_failures"`
	Duration    time.Duration `yaml:"duration"`
}

// AuthConfig configures Tenarium-issued tokens and built-in user roles.
type AuthConfig struct {
	Tokens TokensConfig `yaml:"tokens"`
	// RateLimit caps /v1/auth requests per client IP per minute.
	RateLimit int `yaml:"rate_limit"`
	// RateLimitShared counts rate_limit in the database, so the limit holds
	// across replicas instead of per replica.
	RateLimitShared bool `yaml:"rate_limit_shared"`
	// Roles replace the built-in role tables for users signed in with
	// Tenarium tokens: role → action patterns.
	Roles *UserRolesConfig `yaml:"roles"`
	// SSO configures per-tenant OpenID Connect sign-in.
	SSO SSOConfig `yaml:"sso"`
	// WebAuthn configures passkeys.
	WebAuthn WebAuthnConfig `yaml:"webauthn"`
	// Impersonation configures support access to user sessions.
	Impersonation ImpersonationConfig `yaml:"impersonation"`
	// Provider makes Tenarium an OpenID provider.
	Provider ProviderConfig `yaml:"provider"`
	// Social configures sign-in with Google, GitHub, Microsoft or any OpenID
	// provider for internal users (needs auth.tokens.enabled).
	Social social.Config `yaml:"social"`
}

// SSOConfig configures per-tenant single sign-on. It needs Tenarium
// tokens (auth.tokens.enabled).
type SSOConfig struct {
	Enabled bool `yaml:"enabled"`
	// AllowedRedirects are origins (besides users.public_url) the browser
	// may be sent back to after sign-in, e.g. your app's frontend.
	AllowedRedirects []string `yaml:"allowed_redirects"`
	// AllowPrivateIssuers permits identity providers on internal
	// addresses and plain http (development only).
	AllowPrivateIssuers bool `yaml:"allow_private_issuers"`
}

// WebAuthnConfig configures passkeys (needs auth.tokens.enabled).
type WebAuthnConfig struct {
	Enabled bool `yaml:"enabled"`
	// RPID is the domain passkeys are bound to (default: users.public_url's
	// host). Use the registrable domain to share passkeys with subdomains.
	RPID string `yaml:"rp_id"`
	// Origins allowed to run ceremonies (default: users.public_url's origin).
	Origins []string `yaml:"origins"`
}

// ImpersonationConfig configures support access to user sessions.
type ImpersonationConfig struct {
	// RequireConsent makes users issue a consent code before support can
	// act as them (POST /v1/me/impersonation-consent). Default true.
	RequireConsent *bool `yaml:"require_consent"`
	// MaxTTL bounds impersonation sessions (default 1h).
	MaxTTL time.Duration `yaml:"max_ttl"`
}

// ProviderConfig makes Tenarium an OpenID Connect provider for your apps
// (authorization code + PKCE at /oauth; clients at /v1/oauth-clients).
type ProviderConfig struct {
	Enabled bool `yaml:"enabled"`
	// SessionTTL is how long the browser stays signed in (default 12h).
	SessionTTL time.Duration `yaml:"session_ttl"`
}

type TokensConfig struct {
	Enabled bool `yaml:"enabled"`
	// Issuer defaults to users.public_url.
	Issuer     string        `yaml:"issuer"`
	Audience   string        `yaml:"audience"`
	AccessTTL  time.Duration `yaml:"access_ttl"`
	RefreshTTL time.Duration `yaml:"refresh_ttl"`
	// RotationPeriod rotates the signing key when the active one is older;
	// 0 rotates only on request (POST /v1/signing-keys/rotate). Keys whose
	// tokens have all expired are retired automatically.
	RotationPeriod time.Duration `yaml:"rotation_period"`
}

type UserRolesConfig struct {
	Platform map[string][]string `yaml:"platform"`
	Tenant   map[string][]string `yaml:"tenant"`
}

type BootstrapPlan struct {
	ID          string           `yaml:"id"`
	Name        string           `yaml:"name"`
	Description string           `yaml:"description"`
	Features    map[string]bool  `yaml:"features"`
	Limits      map[string]int64 `yaml:"limits"`
}

type UIConfig struct {
	// Enabled serves the admin UI at /ui/.
	Enabled bool `yaml:"enabled"`
}

// DefaultConfig returns a configuration suitable for local development.
func DefaultConfig() Config {
	return Config{
		Server:    ServerConfig{Addr: ":8080", ShutdownTimeout: 15 * time.Second},
		Log:       LogConfig{Level: "info", Format: "text"},
		Store:     StoreConfig{Driver: "memory"},
		Events:    EventsConfig{PollInterval: time.Second, BatchSize: 100, HandlerTimeout: 30 * time.Second, LeaseTTL: 15 * time.Second},
		UI:        UIConfig{Enabled: true},
		Scheduler: SchedulerConfig{Interval: 30 * time.Second},
		Webhooks:  WebhooksConfig{Enabled: true, MaxFailures: 50},
		Users:     UsersConfig{Directory: "internal", PublicURL: "http://localhost:8080"},
		Auth: AuthConfig{
			Tokens:    TokensConfig{Enabled: true, Audience: "tenarium", AccessTTL: 15 * time.Minute, RefreshTTL: 30 * 24 * time.Hour},
			RateLimit: 30,
			SSO:       SSOConfig{Enabled: true},
			WebAuthn:  WebAuthnConfig{Enabled: true},
			Provider:  ProviderConfig{Enabled: true},
		},
	}
}

// LoadConfig reads a YAML file on top of DefaultConfig.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	dec := yaml.NewDecoder(bytes.NewReader([]byte(os.ExpandEnv(string(raw)))))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("parse %s: %w", path, err)
	}
	return cfg, nil
}
