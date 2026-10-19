// Package redis integrates Tenarium with Redis. Three independent features
// are enabled by their own configuration block; at least one is required.
//
// publish writes events to a Redis Stream (XADD with approximate MAXLEN
// trimming) or a Pub/Sub channel (PUBLISH). Stream entries carry the fields
// type, id, tenant, seq and event (the CloudEvent JSON). Delivery from
// Tenarium is at least once, so stream consumers must dedupe by the id
// field. Pub/Sub is at most once on the Redis side: messages published while
// no subscriber is connected are lost. With per_tenant, events of a tenant go
// to "<stream>:<tenant id>" (or "<channel>:<tenant id>"), giving per-tenant
// ordering and consumers.
//
// cache keeps each tenant's state in "<prefix>tenant:<id>" as JSON (see
// CachedTenant) plus "<prefix>tenant-slug:<slug>" holding the ID, so
// applications can read status, plan and entitlements with one GET (see
// ReadTenant). Writes are guarded by the tenant version: an older event never
// overwrites a newer state. Plan changes re-cache every tenant on the plan.
// The cache scripts touch the slug key derived from the stored JSON, so on
// Redis Cluster the cache needs a key_prefix with a hash tag such as
// "{tenarium}:".
//
// acl provisions one Redis ACL user per tenant, restricted to a key and
// channel pattern. Its password is derived as TenantPassword(secret, tenant
// ID), so the application knowing the secret can compute it and Tenarium
// stores no credentials. ACL users are per node: on Redis Cluster or with
// replicas, run one plugin instance per node or manage users with ACL files.
// Without an aclfile, users live in memory only and are lost on restart; with
// one, set save so changes are persisted with ACL SAVE.
package redis

import (
	"cmp"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/redis/go-redis/v9"
)

func init() {
	sdk.Register("redis", func() sdk.Plugin { return &Plugin{} })
}

// Defaults applied to unset configuration fields.
const (
	DefaultKeyPrefix = "tenarium:"
	DefaultStream    = "events"
	DefaultChannel   = "events"
	DefaultMaxLen    = 100000

	DefaultKeyPattern       = "t:{{.Slug}}:*"
	DefaultUsernameTemplate = "tenant-{{.Slug}}"
	DefaultChannels         = "t:{{.Slug}}:*"
	DefaultCommands         = "+@all -@admin -@dangerous"
)

// Publish modes.
const (
	ModeStream = "stream"
	ModePubSub = "pubsub"
)

type Config struct {
	Addr               string `json:"addr"`
	Username           string `json:"username"`
	Password           string `json:"password"`
	DB                 int    `json:"db"`
	TLS                bool   `json:"tls"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
	// KeyPrefix prefixes every key the plugin owns (default "tenarium:").
	KeyPrefix string `json:"key_prefix"`

	Publish *PublishConfig `json:"publish"`
	Cache   *CacheConfig   `json:"cache"`
	ACL     *ACLConfig     `json:"acl"`
}

type PublishConfig struct {
	// Mode is "stream" (default) or "pubsub".
	Mode    string   `json:"mode"`
	Stream  string   `json:"stream"`
	Channel string   `json:"channel"`
	Events  []string `json:"events"`
	// MaxLen caps the stream length approximately (MAXLEN ~).
	MaxLen    int64 `json:"max_len"`
	PerTenant bool  `json:"per_tenant"`
}

type CacheConfig struct {
	// TTL expires cached entries; "0" (default) keeps them forever.
	TTL string `json:"ttl"`
}

type ACLConfig struct {
	// KeyPattern, UsernameTemplate and Channels are text/templates over
	// sdk.Tenant. Patterns may list several space-separated globs.
	KeyPattern       string `json:"key_pattern"`
	UsernameTemplate string `json:"username_template"`
	// PasswordSecret derives tenant passwords; see TenantPassword.
	PasswordSecret string `json:"password_secret"`
	// Commands are ACL command rules, e.g. "+@all -@admin".
	Commands string `json:"commands"`
	// Channels defaults to "t:{{.Slug}}:*"; set it to "" to allow none.
	Channels          *string `json:"channels"`
	PurgeKeysOnDelete bool    `json:"purge_keys_on_delete"`
	// Save runs ACL SAVE after every change (requires an aclfile).
	Save bool `json:"save"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "addr": {"type": "string", "minLength": 1},
    "username": {"type": "string"},
    "password": {"type": "string"},
    "db": {"type": "integer", "minimum": 0},
    "tls": {"type": "boolean"},
    "insecure_skip_verify": {"type": "boolean"},
    "key_prefix": {"type": "string"},
    "publish": {
      "type": "object",
      "properties": {
        "mode": {"enum": ["stream", "pubsub"]},
        "stream": {"type": "string", "minLength": 1},
        "channel": {"type": "string", "minLength": 1},
        "events": {"type": "array", "items": {"type": "string"}},
        "max_len": {"type": "integer", "minimum": 0},
        "per_tenant": {"type": "boolean"}
      },
      "additionalProperties": false
    },
    "cache": {
      "type": "object",
      "properties": {
        "ttl": {"type": "string"}
      },
      "additionalProperties": false
    },
    "acl": {
      "type": "object",
      "properties": {
        "key_pattern": {"type": "string", "minLength": 1},
        "username_template": {"type": "string", "minLength": 1},
        "password_secret": {"type": "string", "minLength": 1},
        "commands": {"type": "string", "minLength": 1},
        "channels": {"type": "string"},
        "purge_keys_on_delete": {"type": "boolean"},
        "save": {"type": "boolean"}
      },
      "required": ["password_secret"],
      "additionalProperties": false
    }
  },
  "required": ["addr"],
  "anyOf": [
    {"required": ["publish"]},
    {"required": ["cache"]},
    {"required": ["acl"]}
  ],
  "additionalProperties": false
}`)

type Plugin struct {
	cfg    Config
	client *redis.Client
	host   sdk.Host
	log    *slog.Logger

	ttl time.Duration
	acl *aclTemplates
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "redis",
		Name:         "Redis",
		Version:      "0.1.0",
		Description:  "Publishes events to Redis Streams or Pub/Sub, caches tenant state and provisions per-tenant ACL users.",
		ConfigSchema: configSchema,
	}
}

func (p *Plugin) Init(_ context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	if err := p.validate(); err != nil {
		return err
	}
	opts := &redis.Options{
		Addr:     p.cfg.Addr,
		Username: p.cfg.Username,
		Password: p.cfg.Password,
		DB:       p.cfg.DB,
	}
	if p.cfg.TLS {
		host, _, _ := net.SplitHostPort(p.cfg.Addr)
		opts.TLSConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			ServerName:         host,
			InsecureSkipVerify: p.cfg.InsecureSkipVerify, //nolint:gosec // explicit opt-in
		}
	}
	// The client connects lazily, so Redis being down does not block
	// startup; deliveries and provisioning retry.
	p.client = redis.NewClient(opts)
	p.host, p.log = r.Host(), r.Logger()

	if c := p.cfg.Publish; c != nil {
		r.Subscribe("publish", sdk.EventFilter{Types: c.Events}, p.publish)
	}
	if p.cfg.Cache != nil {
		r.Subscribe("cache", sdk.EventFilter{Types: []string{"tenant.*", "plan.*", "rollout.*"}}, p.cacheEvent)
		r.Route("GET /tenants/{tenant}", http.HandlerFunc(p.serveTenant))
		r.Route("POST /resync", http.HandlerFunc(p.serveResync))
	}
	if p.acl != nil {
		r.Provisioner(&aclProvisioner{p})
	}
	return nil
}

// validate checks and defaults the configuration.
func (p *Plugin) validate() error {
	c := &p.cfg
	if c.Addr == "" {
		return errors.New("addr is required")
	}
	if _, _, err := net.SplitHostPort(c.Addr); err != nil {
		return fmt.Errorf("addr must be host:port: %w", err)
	}
	if c.Publish == nil && c.Cache == nil && c.ACL == nil {
		return errors.New("at least one of publish, cache or acl must be configured")
	}
	c.KeyPrefix = cmp.Or(c.KeyPrefix, DefaultKeyPrefix)
	if pc := c.Publish; pc != nil {
		switch pc.Mode {
		case "":
			pc.Mode = ModeStream
		case ModeStream, ModePubSub:
		default:
			return fmt.Errorf("publish.mode must be stream or pubsub, got %q", pc.Mode)
		}
		pc.Stream = cmp.Or(pc.Stream, DefaultStream)
		pc.Channel = cmp.Or(pc.Channel, DefaultChannel)
		if pc.MaxLen < 0 {
			return errors.New("publish.max_len must not be negative")
		}
		if pc.MaxLen == 0 {
			pc.MaxLen = DefaultMaxLen
		}
	}
	if cc := c.Cache; cc != nil {
		ttl, err := time.ParseDuration(cmp.Or(cc.TTL, "0"))
		if err != nil || ttl < 0 {
			return fmt.Errorf("cache.ttl must be a non-negative duration, got %q", cc.TTL)
		}
		p.ttl = ttl
	}
	if ac := c.ACL; ac != nil {
		t, err := compileACL(ac)
		if err != nil {
			return err
		}
		p.acl = t
	}
	return nil
}

func (p *Plugin) key(parts ...string) string {
	k := p.cfg.KeyPrefix
	for _, s := range parts {
		k += s
	}
	return k
}

func (p *Plugin) Health(ctx context.Context) error {
	return p.client.Ping(ctx).Err()
}

func (p *Plugin) Stop(context.Context) error {
	if p.client == nil {
		return nil
	}
	return p.client.Close()
}
