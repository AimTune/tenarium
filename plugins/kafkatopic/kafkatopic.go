// Package kafkatopic gives every tenant its own Kafka namespace: topics
// under a tenant-specific prefix and prefixed ACLs that let the tenant's
// principal use exactly those topics, consumer groups and (optionally)
// transactional IDs. Optionally the plugin also manages the principal's
// SCRAM credential and Kafka client quotas.
//
// # Names
//
// name_template (a text/template over sdk.Tenant, default
// "tenant-{{.Slug}}") renders the tenant's name. It is sanitized to
// lowercase letters, digits, "-" and "_"; dots are never part of a name.
// The tenant's prefixes are then
//
//	topics:           <topic_prefix><name>.
//	consumer groups:  <group_prefix><name>.
//	transactional IDs <group_prefix><name>.
//
// Because names contain no dot and every prefix ends with one, the prefix
// of one tenant is never a prefix of another tenant's prefix ("acme." does
// not match "acme-corp."), so prefixed ACLs cannot leak across tenants.
// Each configured topic is created as <topic prefix><topic name>. Names that
// would make topic names exceed Kafka's 249 characters are shortened and
// suffixed with a hash of the tenant ID.
//
// The principal is "User:<user>", where user comes from user_template
// (default: the name).
//
// # Ownership
//
// Kafka topics cannot carry arbitrary metadata, so ownership is recorded
// in the ACL store, which only administrators can change: a DENY DESCRIBE
// ACL on the tenant's topic prefix for the principal
// "User:tenarium-owner-<tenant id>", a principal no client ever
// authenticates as. Provision creates this marker before anything else and
// refuses to claim a prefix that is marked for another tenant, that holds
// retained data of a deleted tenant, or under which unmarked topics already
// exist. Deprovision only touches prefixes marked for the tenant.
//
// # Deprovisioning
//
// In every mode the tenant loses access: its ACLs, client quotas and SCRAM
// credential are removed. on_deprovision then decides about the data:
//
//   - delete (default): every topic under the prefix is deleted, including
//     topics the tenant created itself, as are consumer groups under the
//     group prefix (best effort); the ownership marker goes last.
//   - keep: topics and the ownership marker stay, so a new tenant with the
//     same slug cannot take them over.
//   - retain: topics stay but ownership is released: the marker becomes
//     "User:tenarium-retained-<tenant id>". Provisioning a tenant whose prefix
//     collides with retained data fails until an operator removes it.
package kafkatopic

import (
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"text/template"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/kmsg"
	"github.com/twmb/franz-go/pkg/sasl/plain"
	"github.com/twmb/franz-go/pkg/sasl/scram"
)

// ID is the plugin ID.
const ID = "kafka-tenant"

func init() {
	sdk.Register(ID, func() sdk.Plugin { return &Plugin{} })
}

// Deprovision modes.
const (
	DeprovisionDelete = "delete"
	DeprovisionKeep   = "keep"
	DeprovisionRetain = "retain"
)

// DefaultNameTemplate names tenants when name_template is unset.
const DefaultNameTemplate = "tenant-{{.Slug}}"

// Marker principals recording prefix ownership in the ACL store.
const (
	OwnerPrincipalPrefix    = "User:tenarium-owner-"
	RetainedPrincipalPrefix = "User:tenarium-retained-"
)

// Kafka limits.
const (
	maxTopicLen   = 249
	maxUserLen    = 128
	minNameBudget = 16
)

type Config struct {
	Brokers  []string    `json:"brokers"`
	ClientID string      `json:"client_id"`
	SASL     *SASLConfig `json:"sasl"`
	TLS      *TLSConfig  `json:"tls"`

	// NameTemplate renders the tenant name (default "tenant-{{.Slug}}").
	NameTemplate string `json:"name_template"`
	// UserTemplate renders the principal's user name (default: the name).
	UserTemplate string `json:"user_template"`
	// TopicPrefix is a static prefix before the tenant name in topic names.
	TopicPrefix string `json:"topic_prefix"`
	// GroupPrefix is a static prefix before the tenant name in consumer
	// group and transactional IDs (default: topic_prefix).
	GroupPrefix *string `json:"group_prefix"`

	Topics []TopicConfig `json:"topics"`
	// PartitionsFromLimit names the entitlement limit that sets the
	// partition count of every topic.
	PartitionsFromLimit string `json:"partitions_from_limit"`
	// MaxPartitions caps limit-derived partition counts (0 = no cap).
	MaxPartitions int32 `json:"max_partitions"`

	ACL ACLConfig `json:"acl"`
	// SCRAM manages a SCRAM credential for the tenant's user.
	SCRAM *SCRAMConfig `json:"scram"`
	// ClientQuotas maps Kafka client quota keys to entitlement limits.
	ClientQuotas map[string]string `json:"client_quotas"`

	// OnDeprovision is "delete" (default), "keep" or "retain".
	OnDeprovision string `json:"on_deprovision"`
}

type TopicConfig struct {
	// Name is appended to the tenant's topic prefix.
	Name string `json:"name"`
	// Partitions; 0 or -1 uses the broker default.
	Partitions int32 `json:"partitions"`
	// ReplicationFactor; 0 or -1 uses the broker default.
	ReplicationFactor int16             `json:"replication_factor"`
	Configs           map[string]string `json:"configs"`
}

type ACLConfig struct {
	// Host the ACLs apply to (default "*").
	Host string `json:"host"`
	// TopicOperations on the topic prefix (default read, write, describe).
	TopicOperations []string `json:"topic_operations"`
	// GroupOperations on the group prefix (default read, describe).
	GroupOperations []string `json:"group_operations"`
	// TransactionalIDs grants write and describe on the transactional ID
	// prefix.
	TransactionalIDs bool `json:"transactional_ids"`
}

type SCRAMConfig struct {
	// Mechanism is SCRAM-SHA-256 or SCRAM-SHA-512 (default).
	Mechanism string `json:"mechanism"`
	// PasswordSecret derives tenant passwords (see TenantPassword).
	PasswordSecret string `json:"password_secret"`
	// Iterations of the SCRAM hash, 4096-16384 (default 8192).
	Iterations int32 `json:"iterations"`
}

type SASLConfig struct {
	// Mechanism is PLAIN, SCRAM-SHA-256 or SCRAM-SHA-512.
	Mechanism string `json:"mechanism"`
	Username  string `json:"username"`
	Password  string `json:"password"`
}

type TLSConfig struct {
	Enabled            bool `json:"enabled"`
	InsecureSkipVerify bool `json:"insecure_skip_verify"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "brokers": {"type": "array", "items": {"type": "string", "minLength": 1}, "minItems": 1},
    "client_id": {"type": "string"},
    "sasl": {
      "type": "object",
      "properties": {
        "mechanism": {"enum": ["PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512"]},
        "username": {"type": "string", "minLength": 1},
        "password": {"type": "string"}
      },
      "required": ["mechanism", "username"],
      "additionalProperties": false
    },
    "tls": {
      "type": "object",
      "properties": {
        "enabled": {"type": "boolean"},
        "insecure_skip_verify": {"type": "boolean"}
      },
      "additionalProperties": false
    },
    "name_template": {"type": "string", "minLength": 1},
    "user_template": {"type": "string", "minLength": 1},
    "topic_prefix": {"type": "string", "pattern": "^[a-zA-Z0-9._-]*$", "maxLength": 100},
    "group_prefix": {"type": "string", "maxLength": 100},
    "topics": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "name": {"type": "string", "pattern": "^[a-zA-Z0-9._-]+$", "maxLength": 100},
          "partitions": {"type": "integer", "minimum": -1},
          "replication_factor": {"type": "integer", "minimum": -1, "maximum": 32767},
          "configs": {"type": "object", "additionalProperties": {"type": "string"}}
        },
        "required": ["name"],
        "additionalProperties": false
      }
    },
    "partitions_from_limit": {"type": "string"},
    "max_partitions": {"type": "integer", "minimum": 0},
    "acl": {
      "type": "object",
      "properties": {
        "host": {"type": "string", "minLength": 1},
        "topic_operations": {"type": "array", "items": {"enum": ["read", "write", "create", "delete", "alter", "describe", "describe_configs", "alter_configs"]}},
        "group_operations": {"type": "array", "items": {"enum": ["read", "describe", "delete"]}},
        "transactional_ids": {"type": "boolean"}
      },
      "additionalProperties": false
    },
    "scram": {
      "type": "object",
      "properties": {
        "mechanism": {"enum": ["SCRAM-SHA-256", "SCRAM-SHA-512"]},
        "password_secret": {"type": "string", "minLength": 16},
        "iterations": {"type": "integer", "minimum": 4096, "maximum": 16384}
      },
      "required": ["password_secret"],
      "additionalProperties": false
    },
    "client_quotas": {
      "type": "object",
      "propertyNames": {"enum": ["producer_byte_rate", "consumer_byte_rate", "request_percentage", "controller_mutation_rate"]},
      "additionalProperties": {"type": "string", "minLength": 1}
    },
    "on_deprovision": {"enum": ["delete", "keep", "retain"]}
  },
  "required": ["brokers"],
  "additionalProperties": false
}`)

var (
	topicNameRE  = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	topicPrefixR = regexp.MustCompile(`^[a-zA-Z0-9._-]*$`)
)

var topicOps = map[string]kmsg.ACLOperation{
	"read": kmsg.ACLOperationRead, "write": kmsg.ACLOperationWrite, "create": kmsg.ACLOperationCreate,
	"delete": kmsg.ACLOperationDelete, "alter": kmsg.ACLOperationAlter, "describe": kmsg.ACLOperationDescribe,
	"describe_configs": kmsg.ACLOperationDescribeConfigs, "alter_configs": kmsg.ACLOperationAlterConfigs,
}

var groupOps = map[string]kmsg.ACLOperation{
	"read": kmsg.ACLOperationRead, "describe": kmsg.ACLOperationDescribe, "delete": kmsg.ACLOperationDelete,
}

var quotaKeys = []string{"producer_byte_rate", "consumer_byte_rate", "request_percentage", "controller_mutation_rate"}

type Plugin struct {
	cfg      Config
	name     *template.Template
	user     *template.Template // nil: user = name
	topicOps []kmsg.ACLOperation
	groupOps []kmsg.ACLOperation
	scram    kadm.ScramMechanism
	// nameBudget is the maximum tenant name length.
	nameBudget int

	adm  admin
	host sdk.Host
	log  *slog.Logger
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           ID,
		Name:         "Kafka Tenant Topics",
		Version:      "0.1.0",
		Description:  "Provisions per-tenant Kafka topics under a prefix, prefixed ACLs, and optionally SCRAM users and client quotas.",
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
	opts, err := clientOpts(&p.cfg)
	if err != nil {
		return err
	}
	adm, err := newKafkaAdmin(opts...)
	if err != nil {
		return err
	}
	p.adm = adm
	p.host = r.Host()
	p.log = r.Logger()
	r.Provisioner(p)
	r.Route("GET /tenants/{tenant}", http.HandlerFunc(p.serveTenant))
	if p.cfg.SCRAM != nil {
		r.Route("GET /tenants/{tenant}/credentials", http.HandlerFunc(p.serveCredentials))
	}
	return nil
}

func clientOpts(c *Config) ([]kgo.Opt, error) {
	opts := []kgo.Opt{
		kgo.SeedBrokers(c.Brokers...),
		kgo.ClientID(cmp.Or(c.ClientID, "tenarium")),
	}
	if s := c.SASL; s != nil {
		mech, err := saslMechanism(s)
		if err != nil {
			return nil, err
		}
		opts = append(opts, mech)
	}
	if t := c.TLS; t != nil && t.Enabled {
		opts = append(opts, kgo.DialTLSConfig(&tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: t.InsecureSkipVerify, //nolint:gosec // explicit opt-in
		}))
	}
	return opts, nil
}

func saslMechanism(s *SASLConfig) (kgo.Opt, error) {
	switch strings.ToUpper(s.Mechanism) {
	case "PLAIN":
		return kgo.SASL(plain.Auth{User: s.Username, Pass: s.Password}.AsMechanism()), nil
	case "SCRAM-SHA-256":
		return kgo.SASL(scram.Auth{User: s.Username, Pass: s.Password}.AsSha256Mechanism()), nil
	case "SCRAM-SHA-512":
		return kgo.SASL(scram.Auth{User: s.Username, Pass: s.Password}.AsSha512Mechanism()), nil
	default:
		return nil, fmt.Errorf("sasl.mechanism: unsupported %q (PLAIN, SCRAM-SHA-256, SCRAM-SHA-512)", s.Mechanism)
	}
}

// validate checks and defaults the configuration and compiles templates.
func (p *Plugin) validate() error {
	c := &p.cfg
	if len(c.Brokers) == 0 {
		return errors.New("brokers is required")
	}
	for _, b := range c.Brokers {
		if strings.TrimSpace(b) == "" || strings.Contains(b, "://") {
			return fmt.Errorf("brokers: %q must be host:port", b)
		}
	}
	if c.SASL != nil {
		if c.SASL.Username == "" {
			return errors.New("sasl.username is required")
		}
		if _, err := saslMechanism(c.SASL); err != nil {
			return err
		}
	}
	if !topicPrefixR.MatchString(c.TopicPrefix) || len(c.TopicPrefix) > 100 {
		return fmt.Errorf("topic_prefix %q may only contain letters, digits, '.', '_' and '-' (at most 100)", c.TopicPrefix)
	}
	if c.GroupPrefix == nil {
		gp := c.TopicPrefix
		c.GroupPrefix = &gp
	}
	if len(*c.GroupPrefix) > 100 || strings.ContainsFunc(*c.GroupPrefix, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return fmt.Errorf("group_prefix %q must be at most 100 printable characters", *c.GroupPrefix)
	}
	switch c.OnDeprovision {
	case "":
		c.OnDeprovision = DeprovisionDelete
	case DeprovisionDelete, DeprovisionKeep, DeprovisionRetain:
	default:
		return fmt.Errorf("on_deprovision must be delete, keep or retain, got %q", c.OnDeprovision)
	}

	longest := 0
	seen := map[string]bool{}
	for i := range c.Topics {
		tc := &c.Topics[i]
		if !topicNameRE.MatchString(tc.Name) || len(tc.Name) > 100 {
			return fmt.Errorf("topics[%d].name %q may only contain letters, digits, '.', '_' and '-' (at most 100)", i, tc.Name)
		}
		if seen[tc.Name] {
			return fmt.Errorf("topics[%d].name %q is duplicated", i, tc.Name)
		}
		seen[tc.Name] = true
		longest = max(longest, len(tc.Name))
		if tc.Partitions < -1 {
			return fmt.Errorf("topics[%d].partitions must be -1, 0 or positive", i)
		}
		if tc.Partitions == 0 {
			tc.Partitions = -1
		}
		if tc.ReplicationFactor < -1 {
			return fmt.Errorf("topics[%d].replication_factor must be -1, 0 or positive", i)
		}
		if tc.ReplicationFactor == 0 {
			tc.ReplicationFactor = -1
		}
		for k := range tc.Configs {
			if strings.TrimSpace(k) == "" {
				return fmt.Errorf("topics[%d].configs: empty key", i)
			}
		}
	}
	// <topic_prefix><name>.<topic>
	p.nameBudget = maxTopicLen - len(c.TopicPrefix) - 1 - longest
	if p.nameBudget < minNameBudget {
		return fmt.Errorf("topic_prefix and topic names leave only %d characters for tenant names (need %d)", p.nameBudget, minNameBudget)
	}
	if c.MaxPartitions < 0 {
		return errors.New("max_partitions must not be negative")
	}

	if c.ACL.Host == "" {
		c.ACL.Host = "*"
	}
	if c.ACL.TopicOperations == nil {
		c.ACL.TopicOperations = []string{"read", "write", "describe"}
	}
	if c.ACL.GroupOperations == nil {
		c.ACL.GroupOperations = []string{"read", "describe"}
	}
	var err error
	if p.topicOps, err = parseOps("acl.topic_operations", c.ACL.TopicOperations, topicOps); err != nil {
		return err
	}
	if p.groupOps, err = parseOps("acl.group_operations", c.ACL.GroupOperations, groupOps); err != nil {
		return err
	}

	if s := c.SCRAM; s != nil {
		switch s.Mechanism {
		case "", "SCRAM-SHA-512":
			s.Mechanism, p.scram = "SCRAM-SHA-512", kadm.ScramSha512
		case "SCRAM-SHA-256":
			p.scram = kadm.ScramSha256
		default:
			return fmt.Errorf("scram.mechanism must be SCRAM-SHA-256 or SCRAM-SHA-512, got %q", s.Mechanism)
		}
		if len(s.PasswordSecret) < 16 {
			return errors.New("scram.password_secret is required (at least 16 characters)")
		}
		if s.Iterations == 0 {
			s.Iterations = 8192
		}
		if s.Iterations < 4096 || s.Iterations > 16384 {
			return fmt.Errorf("scram.iterations must be between 4096 and 16384, got %d", s.Iterations)
		}
	}
	for k, limit := range c.ClientQuotas {
		if !slices.Contains(quotaKeys, k) {
			return fmt.Errorf("client_quotas: unknown quota %q (%s)", k, strings.Join(quotaKeys, ", "))
		}
		if limit == "" {
			return fmt.Errorf("client_quotas.%s: limit name is empty", k)
		}
	}

	if c.NameTemplate == "" {
		c.NameTemplate = DefaultNameTemplate
	}
	if p.name, err = parseTemplate("name_template", c.NameTemplate); err != nil {
		return err
	}
	if c.UserTemplate != "" {
		if p.user, err = parseTemplate("user_template", c.UserTemplate); err != nil {
			return err
		}
	}
	// Names and users must be tenant specific, or tenants would share topics
	// and credentials.
	t1, err := p.target(sample1)
	if err != nil {
		return err
	}
	t2, err := p.target(sample2)
	if err != nil {
		return err
	}
	if t1.Name == t2.Name {
		return errors.New("name_template must depend on the tenant (e.g. {{.Slug}} or {{.ID}})")
	}
	if t1.User == t2.User {
		return errors.New("user_template must depend on the tenant (e.g. {{.Slug}} or {{.ID}})")
	}
	return nil
}

func parseOps(field string, names []string, allowed map[string]kmsg.ACLOperation) ([]kmsg.ACLOperation, error) {
	var out []kmsg.ACLOperation
	for _, n := range names {
		op, ok := allowed[n]
		if !ok {
			return nil, fmt.Errorf("%s: unsupported operation %q", field, n)
		}
		if !slices.Contains(out, op) {
			out = append(out, op)
		}
	}
	return out, nil
}

func parseTemplate(field, s string) (*template.Template, error) {
	t, err := template.New(field).Option("missingkey=error").Parse(s)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	return t, nil
}

// Sample tenants used to validate templates at Init.
var (
	sample1 = sdk.Tenant{ID: "00000000-0000-0000-0000-000000000001", Slug: "example-one", Name: "Example One"}
	sample2 = sdk.Tenant{ID: "00000000-0000-0000-0000-000000000002", Slug: "example-two", Name: "Example Two"}
)

// SanitizeName lowercases s, replaces characters other than [a-z0-9_-]
// (including dots) by "-", collapses hyphen runs and trims hyphens.
func SanitizeName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else if !strings.HasSuffix(b.String(), "-") {
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// renderName renders tmpl for t, sanitizes it and shortens it to at most
// limit characters with a hash of the tenant ID.
func renderName(tmpl *template.Template, t sdk.Tenant, limit int) (string, error) {
	var b strings.Builder
	if err := tmpl.Execute(&b, t); err != nil {
		return "", fmt.Errorf("%s: %w", tmpl.Name(), err)
	}
	name := SanitizeName(b.String())
	if name == "" {
		return "", fmt.Errorf("%s renders an empty name for tenant %s", tmpl.Name(), t.ID)
	}
	if len(name) > limit {
		// Truncation alone could map two tenants to one name.
		sum := sha256.Sum256([]byte(t.ID))
		suffix := "-" + hex.EncodeToString(sum[:4])
		name = strings.TrimRight(name[:limit-len(suffix)], "-") + suffix
	}
	return name, nil
}

// target is what a tenant maps to in Kafka.
type target struct {
	Name        string
	User        string
	Principal   string
	TopicPrefix string
	GroupPrefix string
	// Topics are the full names of the configured topics, in config order.
	Topics []string
}

func (p *Plugin) target(t sdk.Tenant) (target, error) {
	name, err := renderName(p.name, t, p.nameBudget)
	if err != nil {
		return target{}, err
	}
	user := name
	if p.user != nil {
		if user, err = renderName(p.user, t, maxUserLen); err != nil {
			return target{}, err
		}
	}
	tg := target{
		Name:        name,
		User:        user,
		Principal:   "User:" + user,
		TopicPrefix: p.cfg.TopicPrefix + name + ".",
		GroupPrefix: *p.cfg.GroupPrefix + name + ".",
	}
	for _, tc := range p.cfg.Topics {
		tg.Topics = append(tg.Topics, tg.TopicPrefix+tc.Name)
	}
	return tg, nil
}

// TenantPassword derives the SCRAM password of a tenant:
// hex(HMAC-SHA256(secret, tenantID)). Applications that know the secret
// compute it the same way, so Tenarium stores no credentials.
func TenantPassword(secret, tenantID string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(tenantID))
	return hex.EncodeToString(m.Sum(nil))
}

func (p *Plugin) Name() string { return "kafka-topics" }

// desiredACLs are the ACLs the tenant's principal gets.
func (p *Plugin) desiredACLs(tg target) []aclBinding {
	var out []aclBinding
	add := func(typ kmsg.ACLResourceType, name string, ops []kmsg.ACLOperation) {
		for _, op := range ops {
			out = append(out, aclBinding{
				Type: typ, Name: name, Pattern: kmsg.ACLResourcePatternTypePrefixed,
				Principal: tg.Principal, Host: p.cfg.ACL.Host, Operation: op, Perm: kmsg.ACLPermissionTypeAllow,
			})
		}
	}
	add(kmsg.ACLResourceTypeTopic, tg.TopicPrefix, p.topicOps)
	add(kmsg.ACLResourceTypeGroup, tg.GroupPrefix, p.groupOps)
	if p.cfg.ACL.TransactionalIDs {
		add(kmsg.ACLResourceTypeTransactionalId, tg.GroupPrefix,
			[]kmsg.ACLOperation{kmsg.ACLOperationWrite, kmsg.ACLOperationDescribe})
	}
	return out
}

// managed reports whether b is an ACL of the tenant's principal on one of
// the tenant's prefixes, i.e. one the plugin maintains.
func managed(b aclBinding, tg target) bool {
	if b.Principal != tg.Principal || b.Pattern != kmsg.ACLResourcePatternTypePrefixed {
		return false
	}
	switch b.Type {
	case kmsg.ACLResourceTypeTopic:
		return b.Name == tg.TopicPrefix
	case kmsg.ACLResourceTypeGroup, kmsg.ACLResourceTypeTransactionalId:
		return b.Name == tg.GroupPrefix
	}
	return false
}

func markerACL(principal, prefix string) aclBinding {
	return aclBinding{
		Type: kmsg.ACLResourceTypeTopic, Name: prefix, Pattern: kmsg.ACLResourcePatternTypePrefixed,
		Principal: principal, Host: "*", Operation: kmsg.ACLOperationDescribe, Perm: kmsg.ACLPermissionTypeDeny,
	}
}

// markers lists the tenant IDs that own or retained the prefix.
type markers struct {
	owners, retained []string
}

func (p *Plugin) markers(ctx context.Context, prefix string) (markers, error) {
	acls, err := p.adm.DescribeACLs(ctx, aclFilter{
		Type: kmsg.ACLResourceTypeTopic, Name: &prefix,
		Pattern: kmsg.ACLResourcePatternTypePrefixed, Perm: kmsg.ACLPermissionTypeDeny,
	})
	if err != nil {
		return markers{}, fmt.Errorf("describe ownership ACLs: %w", err)
	}
	var m markers
	for _, a := range acls {
		if a.Name != prefix || a.Type != kmsg.ACLResourceTypeTopic || a.Pattern != kmsg.ACLResourcePatternTypePrefixed {
			continue
		}
		if id, ok := strings.CutPrefix(a.Principal, OwnerPrincipalPrefix); ok && !slices.Contains(m.owners, id) {
			m.owners = append(m.owners, id)
		} else if id, ok := strings.CutPrefix(a.Principal, RetainedPrincipalPrefix); ok && !slices.Contains(m.retained, id) {
			m.retained = append(m.retained, id)
		}
	}
	return m, nil
}

// Provision claims the tenant's prefix and converges its SCRAM credential,
// topics, ACLs and client quotas. Every step is idempotent.
func (p *Plugin) Provision(ctx context.Context, t sdk.Tenant) error {
	tg, err := p.target(t)
	if err != nil {
		return err
	}
	var ent *sdk.Entitlements
	if p.cfg.PartitionsFromLimit != "" || len(p.cfg.ClientQuotas) > 0 {
		e, err := p.host.Entitlements(ctx, t.ID)
		if err != nil {
			return fmt.Errorf("entitlements: %w", err)
		}
		ent = &e
	}
	if err := p.claim(ctx, tg, t); err != nil {
		return err
	}
	if s := p.cfg.SCRAM; s != nil {
		if err := p.adm.UpsertSCRAM(ctx, tg.User, p.scram, TenantPassword(s.PasswordSecret, t.ID), s.Iterations); err != nil {
			return fmt.Errorf("SCRAM credential for %s: %w", tg.User, err)
		}
	}
	if err := p.ensureTopics(ctx, tg, ent); err != nil {
		return err
	}
	if err := p.ensureACLs(ctx, tg); err != nil {
		return err
	}
	return p.ensureQuotas(ctx, tg, ent)
}

// claim makes sure the prefix is marked as owned by t, refusing prefixes
// that belong to someone else.
func (p *Plugin) claim(ctx context.Context, tg target, t sdk.Tenant) error {
	m, err := p.markers(ctx, tg.TopicPrefix)
	if err != nil {
		return err
	}
	for _, id := range m.owners {
		if id != t.ID {
			return fmt.Errorf("topic prefix %q belongs to tenant %s; not adopting it", tg.TopicPrefix, id)
		}
	}
	reclaim := false
	for _, id := range m.retained {
		if id != t.ID {
			return fmt.Errorf("topic prefix %q holds retained data of deleted tenant %s; remove its topics and the ACL marker %s%s first",
				tg.TopicPrefix, id, RetainedPrincipalPrefix, id)
		}
		reclaim = true
	}
	if slices.Contains(m.owners, t.ID) {
		return nil
	}
	if !reclaim {
		// A fresh claim: nothing may exist yet that the plugin would adopt.
		topics, err := p.adm.ListTopics(ctx)
		if err != nil {
			return fmt.Errorf("list topics: %w", err)
		}
		var found []string
		for name := range topics {
			if strings.HasPrefix(name, tg.TopicPrefix) {
				found = append(found, name)
			}
		}
		if len(found) > 0 {
			slices.Sort(found)
			return fmt.Errorf("topics with prefix %q exist without a tenarium ownership marker (%s); not adopting them",
				tg.TopicPrefix, strings.Join(found, ", "))
		}
		if p.cfg.SCRAM != nil {
			exists, err := p.adm.SCRAMUserExists(ctx, tg.User)
			if err != nil {
				return fmt.Errorf("describe SCRAM user %s: %w", tg.User, err)
			}
			if exists {
				return fmt.Errorf("SCRAM user %q already exists and is not managed for this tenant; not taking it over", tg.User)
			}
		}
	}
	if err := p.adm.CreateACLs(ctx, []aclBinding{markerACL(OwnerPrincipalPrefix+t.ID, tg.TopicPrefix)}); err != nil {
		return fmt.Errorf("create ownership marker: %w", err)
	}
	if reclaim {
		if err := p.adm.DeleteACLs(ctx, []aclBinding{markerACL(RetainedPrincipalPrefix+t.ID, tg.TopicPrefix)}); err != nil {
			return fmt.Errorf("remove retained marker: %w", err)
		}
	}
	return nil
}

// partitions returns the partition count for a configured topic.
func (p *Plugin) partitions(tc TopicConfig, ent *sdk.Entitlements) int32 {
	if ent != nil && p.cfg.PartitionsFromLimit != "" {
		if v, ok := ent.Limit(p.cfg.PartitionsFromLimit); ok && v > 0 {
			if p.cfg.MaxPartitions > 0 && v > int64(p.cfg.MaxPartitions) {
				v = int64(p.cfg.MaxPartitions)
			}
			return int32(min(v, math.MaxInt32)) //nolint:gosec // v is in [1, MaxInt32] here
		}
	}
	return tc.Partitions
}

func (p *Plugin) ensureTopics(ctx context.Context, tg target, ent *sdk.Entitlements) error {
	if len(p.cfg.Topics) == 0 {
		return nil
	}
	existing, err := p.adm.ListTopics(ctx)
	if err != nil {
		return fmt.Errorf("list topics: %w", err)
	}
	for i, tc := range p.cfg.Topics {
		name := tg.Topics[i]
		want := p.partitions(tc, ent)
		cur, ok := existing[name]
		if !ok {
			if err := p.adm.CreateTopic(ctx, name, want, tc.ReplicationFactor, tc.Configs); err != nil {
				return fmt.Errorf("create topic %s: %w", name, err)
			}
			continue
		}
		// Partitions is 0 while a new topic's metadata propagates.
		if want > 0 && cur.Partitions > 0 && cur.Partitions < want {
			if err := p.adm.SetPartitions(ctx, name, want); err != nil {
				return fmt.Errorf("increase partitions of %s to %d: %w", name, want, err)
			}
		} else if want > 0 && cur.Partitions > want {
			p.log.Info("topic has more partitions than configured; Kafka cannot reduce them",
				"topic", name, "partitions", cur.Partitions, "wanted", want)
		}
		if err := p.adm.SetTopicConfigs(ctx, name, tc.Configs); err != nil {
			return fmt.Errorf("set configs of %s: %w", name, err)
		}
	}
	return nil
}

func (p *Plugin) ensureACLs(ctx context.Context, tg target) error {
	desired := p.desiredACLs(tg)
	existing, err := p.adm.DescribeACLs(ctx, aclFilter{Principal: &tg.Principal})
	if err != nil {
		return fmt.Errorf("describe ACLs of %s: %w", tg.Principal, err)
	}
	var stale, missing []aclBinding
	for _, b := range existing {
		if managed(b, tg) && !slices.Contains(desired, b) {
			stale = append(stale, b)
		}
	}
	for _, b := range desired {
		if !slices.Contains(existing, b) {
			missing = append(missing, b)
		}
	}
	if err := p.adm.CreateACLs(ctx, missing); err != nil {
		return err
	}
	return p.adm.DeleteACLs(ctx, stale)
}

func (p *Plugin) ensureQuotas(ctx context.Context, tg target, ent *sdk.Entitlements) error {
	if len(p.cfg.ClientQuotas) == 0 {
		return nil
	}
	set := map[string]float64{}
	var remove []string
	for key, limit := range p.cfg.ClientQuotas {
		if v, ok := ent.Limit(limit); ok && v >= 0 {
			set[key] = float64(v)
		} else {
			remove = append(remove, key)
		}
	}
	if err := p.adm.AlterUserQuotas(ctx, tg.User, set, remove); err != nil {
		return fmt.Errorf("client quotas of %s: %w", tg.User, err)
	}
	return nil
}

// Deprovision revokes the tenant's access and applies on_deprovision. A
// prefix that is not marked for the tenant is left alone.
func (p *Plugin) Deprovision(ctx context.Context, t sdk.Tenant) error {
	tg, err := p.target(t)
	if err != nil {
		return err
	}
	m, err := p.markers(ctx, tg.TopicPrefix)
	if err != nil {
		return err
	}
	if !slices.Contains(m.owners, t.ID) {
		if len(m.owners) > 0 {
			p.log.Warn("topic prefix belongs to another tenant; leaving it untouched",
				"tenant", t.ID, "prefix", tg.TopicPrefix, "owners", m.owners)
		}
		return nil
	}
	if err := p.revoke(ctx, tg); err != nil {
		return err
	}
	owner := markerACL(OwnerPrincipalPrefix+t.ID, tg.TopicPrefix)
	switch p.cfg.OnDeprovision {
	case DeprovisionKeep:
		return nil
	case DeprovisionRetain:
		if err := p.adm.CreateACLs(ctx, []aclBinding{markerACL(RetainedPrincipalPrefix+t.ID, tg.TopicPrefix)}); err != nil {
			return fmt.Errorf("create retained marker: %w", err)
		}
		return p.adm.DeleteACLs(ctx, []aclBinding{owner})
	}
	topics, err := p.adm.ListTopics(ctx)
	if err != nil {
		return fmt.Errorf("list topics: %w", err)
	}
	var del []string
	for name := range topics {
		if strings.HasPrefix(name, tg.TopicPrefix) {
			del = append(del, name)
		}
	}
	slices.Sort(del)
	if err := p.adm.DeleteTopics(ctx, del); err != nil {
		return err
	}
	p.deleteGroups(ctx, tg)
	// The marker goes last so an interrupted run is retried.
	return p.adm.DeleteACLs(ctx, []aclBinding{owner})
}

// revoke removes the tenant's ACLs, client quotas and SCRAM credential.
func (p *Plugin) revoke(ctx context.Context, tg target) error {
	existing, err := p.adm.DescribeACLs(ctx, aclFilter{Principal: &tg.Principal})
	if err != nil {
		return fmt.Errorf("describe ACLs of %s: %w", tg.Principal, err)
	}
	var del []aclBinding
	for _, b := range existing {
		if managed(b, tg) {
			del = append(del, b)
		}
	}
	if err := p.adm.DeleteACLs(ctx, del); err != nil {
		return err
	}
	if len(p.cfg.ClientQuotas) > 0 {
		var keys []string
		for k := range p.cfg.ClientQuotas {
			keys = append(keys, k)
		}
		if err := p.adm.AlterUserQuotas(ctx, tg.User, nil, keys); err != nil {
			return fmt.Errorf("remove client quotas of %s: %w", tg.User, err)
		}
	}
	if p.cfg.SCRAM != nil {
		if err := p.adm.DeleteSCRAM(ctx, tg.User, p.scram); err != nil {
			return fmt.Errorf("delete SCRAM credential of %s: %w", tg.User, err)
		}
	}
	return nil
}

// deleteGroups deletes consumer groups under the tenant's group prefix. It
// is best effort: groups with active members cannot be deleted and expire
// on their own once empty.
func (p *Plugin) deleteGroups(ctx context.Context, tg target) {
	groups, err := p.adm.ListGroups(ctx)
	if err != nil {
		p.log.Warn("could not list consumer groups", "prefix", tg.GroupPrefix, "err", err)
		return
	}
	var del []string
	for _, g := range groups {
		if strings.HasPrefix(g, tg.GroupPrefix) {
			del = append(del, g)
		}
	}
	for g, err := range p.adm.DeleteGroups(ctx, del) {
		p.log.Warn("could not delete consumer group", "group", g, "err", err)
	}
}

// TenantInfo is the response of GET /tenants/{tenant}.
type TenantInfo struct {
	Brokers               []string `json:"brokers"`
	Principal             string   `json:"principal"`
	User                  string   `json:"user"`
	TopicPrefix           string   `json:"topic_prefix"`
	GroupPrefix           string   `json:"group_prefix"`
	TransactionalIDPrefix string   `json:"transactional_id_prefix,omitempty"`
	Topics                []string `json:"topics"`
	SASLMechanism         string   `json:"sasl_mechanism,omitempty"`
}

// Credentials is the response of GET /tenants/{tenant}/credentials.
type Credentials struct {
	User      string `json:"user"`
	Password  string `json:"password"`
	Mechanism string `json:"mechanism"`
}

// lookup resolves the {tenant} path value and checks read access. It
// answers "not found" for tenants the caller may not read, so callers
// cannot probe other tenants' slugs.
func (p *Plugin) lookup(w http.ResponseWriter, r *http.Request) (sdk.Tenant, bool) {
	t, err := p.host.GetTenant(r.Context(), r.PathValue("tenant"))
	if errors.Is(err, sdk.ErrNotFound) {
		http.Error(w, "tenant not found", http.StatusNotFound)
		return t, false
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return t, false
	}
	res := sdk.Resource{Type: "tenant", ID: t.ID, TenantID: t.ID}
	if err := p.host.Authorize(r.Context(), sdk.ActionTenantsRead, res); err != nil {
		http.Error(w, "tenant not found", http.StatusNotFound)
		return t, false
	}
	return t, true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (p *Plugin) serveTenant(w http.ResponseWriter, r *http.Request) {
	t, ok := p.lookup(w, r)
	if !ok {
		return
	}
	tg, err := p.target(t)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	info := TenantInfo{
		Brokers: p.cfg.Brokers, Principal: tg.Principal, User: tg.User,
		TopicPrefix: tg.TopicPrefix, GroupPrefix: tg.GroupPrefix, Topics: tg.Topics,
	}
	if info.Topics == nil {
		info.Topics = []string{}
	}
	if p.cfg.ACL.TransactionalIDs {
		info.TransactionalIDPrefix = tg.GroupPrefix
	}
	if p.cfg.SCRAM != nil {
		info.SASLMechanism = p.cfg.SCRAM.Mechanism
	}
	writeJSON(w, info)
}

// serveCredentials returns the tenant's SCRAM credential. It requires
// tenants:update on the tenant, so read-only callers cannot fetch it.
func (p *Plugin) serveCredentials(w http.ResponseWriter, r *http.Request) {
	t, ok := p.lookup(w, r)
	if !ok {
		return
	}
	res := sdk.Resource{Type: "tenant", ID: t.ID, TenantID: t.ID}
	if err := p.host.Authorize(r.Context(), sdk.ActionTenantsUpdate, res); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	tg, err := p.target(t)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, Credentials{
		User: tg.User, Password: TenantPassword(p.cfg.SCRAM.PasswordSecret, t.ID), Mechanism: p.cfg.SCRAM.Mechanism,
	})
}

// Health checks that a broker is reachable.
func (p *Plugin) Health(ctx context.Context) error { return p.adm.Ping(ctx) }

func (p *Plugin) Stop(context.Context) error {
	if p.adm != nil {
		p.adm.Close()
	}
	return nil
}
