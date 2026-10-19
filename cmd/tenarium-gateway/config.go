package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the gateway's configuration file. ${VAR} references are
// expanded from the environment before parsing.
type Config struct {
	// Listen is the address of the check, health and metrics endpoints.
	Listen string `yaml:"listen"`
	// MetricsListen serves /metrics on a separate address when set.
	MetricsListen string `yaml:"metrics_listen"`

	Tenarium TenariumConfig `yaml:"tenarium"`
	Source   SourceConfig   `yaml:"source"`
	Redis    RedisConfig    `yaml:"redis"`

	// Resolve lists the tenant resolution rules, tried in order.
	Resolve []ResolveRule `yaml:"resolve"`
	// AllowedStatuses default to [active].
	AllowedStatuses []string `yaml:"allowed_statuses"`
	// Optional lets requests without a tenant reference through.
	Optional bool `yaml:"optional"`

	Cell           CellConfig      `yaml:"cell"`
	ExposeFeatures bool            `yaml:"expose_features"`
	Features       []FeatureRule   `yaml:"features"`
	RateLimit      RateLimitConfig `yaml:"rate_limit"`
	Log            LogConfig       `yaml:"log"`
	Timeouts       ServerTimeouts  `yaml:"timeouts"`
}

// TenariumConfig locates the Tenarium API.
type TenariumConfig struct {
	// URL is the Tenarium base URL (API source, custom domains, token
	// discovery).
	URL string `yaml:"url"`
	// APIKey authenticates API calls; defaults to $TENARIUM_API_KEY.
	APIKey string `yaml:"api_key"`
	// Timeout of API calls (default 5s).
	Timeout time.Duration `yaml:"timeout"`
	// JWKSURL and Issuer configure token verification without discovery.
	JWKSURL string `yaml:"jwks_url"`
	Issuer  string `yaml:"issuer"`
	// Audience of access tokens (default "tenarium").
	Audience string `yaml:"audience"`
}

// SourceConfig selects where tenants are loaded from.
type SourceConfig struct {
	// Type is "redis" (the redis plugin's cache) or "api". Default: redis
	// when redis.addr is set, else api.
	Type string `yaml:"type"`
	// CacheTTL of the in-memory cache (default 30s; negative disables).
	CacheTTL time.Duration `yaml:"cache_ttl"`
	// NegativeTTL for unknown tenants (default 5s).
	NegativeTTL time.Duration `yaml:"negative_ttl"`
	// MaxEntries bounds the cache (default 10000).
	MaxEntries int `yaml:"max_entries"`
	// DomainCacheTTL caches custom domain lookups (default 5m).
	DomainCacheTTL time.Duration `yaml:"domain_cache_ttl"`
}

// RedisConfig is shared by the redis source and the redis rate limiter.
type RedisConfig struct {
	Addr     string `yaml:"addr"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
	TLS      bool   `yaml:"tls"`
	// Prefix is the redis plugin's key_prefix (default "tenarium:").
	Prefix string `yaml:"prefix"`
}

// ResolveRule is one resolution source; exactly one field must be set.
type ResolveRule struct {
	Token        bool   `yaml:"token"`
	Subdomain    string `yaml:"subdomain"`
	Header       string `yaml:"header"`
	Path         string `yaml:"path"`
	CustomDomain bool   `yaml:"custom_domain"`
}

func (r ResolveRule) kind() (string, error) {
	var set []string
	if r.Token {
		set = append(set, "token")
	}
	if r.Subdomain != "" {
		set = append(set, "subdomain")
	}
	if r.Header != "" {
		set = append(set, "header")
	}
	if r.Path != "" {
		set = append(set, "path")
	}
	if r.CustomDomain {
		set = append(set, "custom_domain")
	}
	if len(set) != 1 {
		return "", fmt.Errorf("each resolve rule needs exactly one of token, subdomain, header, path, custom_domain (got %v)", set)
	}
	return set[0], nil
}

// CellConfig chooses X-Tenant-Cell.
type CellConfig struct {
	Label   string            `yaml:"label"`
	Default string            `yaml:"default"`
	Plans   map[string]string `yaml:"plans"`
}

// FeatureRule requires a feature for matching requests.
type FeatureRule struct {
	Host       string   `yaml:"host"`
	PathPrefix string   `yaml:"path_prefix"`
	Methods    []string `yaml:"methods"`
	Feature    string   `yaml:"feature"`
}

// RateLimitConfig configures per-tenant rate limiting.
type RateLimitConfig struct {
	// Backend is "" or "off" (disabled), "local" or "redis".
	Backend      string        `yaml:"backend"`
	Metric       string        `yaml:"metric"`
	BurstMetric  string        `yaml:"burst_metric"`
	Period       time.Duration `yaml:"period"`
	DefaultRate  int64         `yaml:"default_rate"`
	DefaultBurst int64         `yaml:"default_burst"`
	// FailOpen allows requests when the limiter fails (default true).
	FailOpen *bool `yaml:"fail_open"`
	// Prefix of the Redis keys (default "tenarium:gw:rl:").
	Prefix string `yaml:"prefix"`
}

// LogConfig configures logging.
type LogConfig struct {
	// Level is debug, info, warn or error (default info).
	Level string `yaml:"level"`
	// Format is text or json (default json).
	Format string `yaml:"format"`
}

// ServerTimeouts of the HTTP server.
type ServerTimeouts struct {
	ReadHeader time.Duration `yaml:"read_header"`
	Idle       time.Duration `yaml:"idle"`
	Shutdown   time.Duration `yaml:"shutdown"`
}

// loadConfig reads path (if not empty) and applies defaults.
func loadConfig(path string) (*Config, error) {
	cfg := &Config{}
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		dec := yaml.NewDecoder(bytes.NewReader([]byte(os.ExpandEnv(string(raw)))))
		dec.KnownFields(true)
		if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) { // io.EOF: empty file
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	return cfg, nil
}

// finish applies defaults and validates.
func (c *Config) finish() error {
	if c.Listen == "" {
		c.Listen = ":8090"
	}
	if c.Tenarium.APIKey == "" {
		c.Tenarium.APIKey = os.Getenv("TENARIUM_API_KEY")
	}
	if c.Tenarium.Timeout <= 0 {
		c.Tenarium.Timeout = 5 * time.Second
	}
	c.Tenarium.URL = strings.TrimRight(c.Tenarium.URL, "/")
	if c.Source.Type == "" {
		c.Source.Type = "api"
		if c.Redis.Addr != "" {
			c.Source.Type = "redis"
		}
	}
	if c.Source.CacheTTL == 0 {
		c.Source.CacheTTL = 30 * time.Second
	}
	if c.Source.NegativeTTL == 0 {
		c.Source.NegativeTTL = 5 * time.Second
	}
	if c.Source.DomainCacheTTL <= 0 {
		c.Source.DomainCacheTTL = 5 * time.Minute
	}
	if c.Timeouts.ReadHeader <= 0 {
		c.Timeouts.ReadHeader = 5 * time.Second
	}
	if c.Timeouts.Idle <= 0 {
		c.Timeouts.Idle = 2 * time.Minute
	}
	if c.Timeouts.Shutdown <= 0 {
		c.Timeouts.Shutdown = 15 * time.Second
	}
	if c.RateLimit.FailOpen == nil {
		t := true
		c.RateLimit.FailOpen = &t
	}

	var errs []error
	switch c.Source.Type {
	case "redis":
		if c.Redis.Addr == "" {
			errs = append(errs, errors.New("source.type redis needs redis.addr"))
		}
	case "api":
		if c.Tenarium.URL == "" {
			errs = append(errs, errors.New("source.type api needs tenarium.url"))
		}
	default:
		errs = append(errs, fmt.Errorf("unknown source.type %q (want redis or api)", c.Source.Type))
	}
	if len(c.Resolve) == 0 {
		errs = append(errs, errors.New("resolve: at least one rule is required"))
	}
	for i, r := range c.Resolve {
		k, err := r.kind()
		if err != nil {
			errs = append(errs, fmt.Errorf("resolve[%d]: %w", i, err))
			continue
		}
		switch k {
		case "token":
			if c.Tenarium.URL == "" && (c.Tenarium.JWKSURL == "" || c.Tenarium.Issuer == "") {
				errs = append(errs, fmt.Errorf("resolve[%d]: token needs tenarium.url or tenarium.jwks_url and tenarium.issuer", i))
			}
		case "custom_domain":
			if c.Tenarium.URL == "" {
				errs = append(errs, fmt.Errorf("resolve[%d]: custom_domain needs tenarium.url", i))
			}
		case "path":
			if !strings.HasPrefix(r.Path, "/") || !strings.HasSuffix(r.Path, "/") {
				errs = append(errs, fmt.Errorf("resolve[%d]: path must start and end with /", i))
			}
		}
	}
	switch c.RateLimit.Backend {
	case "", "off", "local":
	case "redis":
		if c.Redis.Addr == "" {
			errs = append(errs, errors.New("rate_limit.backend redis needs redis.addr"))
		}
	default:
		errs = append(errs, fmt.Errorf("unknown rate_limit.backend %q (want off, local or redis)", c.RateLimit.Backend))
	}
	if on := c.RateLimit.Backend == "local" || c.RateLimit.Backend == "redis"; on && c.RateLimit.Metric == "" && c.RateLimit.DefaultRate == 0 {
		errs = append(errs, errors.New("rate_limit needs a metric or a default_rate"))
	}
	for i, f := range c.Features {
		if f.Feature == "" {
			errs = append(errs, fmt.Errorf("features[%d]: feature is required", i))
		}
	}
	return errors.Join(errs...)
}
