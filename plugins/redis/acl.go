package redis

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"text/template"
	"unicode"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/redis/go-redis/v9"
)

// TenantPassword derives the ACL password of a tenant: the first 32 hex
// characters of HMAC-SHA256(secret, tenantID). Applications that know the
// secret compute it the same way to connect as the tenant.
func TenantPassword(secret, tenantID string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(tenantID))
	return hex.EncodeToString(m.Sum(nil))[:32]
}

// aclTemplates is the compiled acl configuration.
type aclTemplates struct {
	cfg      *ACLConfig
	user     *template.Template
	keys     *template.Template
	channels *template.Template // nil allows no channels
	commands []string
}

// aclTarget is what a tenant maps to in Redis.
type aclTarget struct {
	User     string
	Keys     []string
	Channels []string
}

func compileACL(c *ACLConfig) (*aclTemplates, error) {
	if c.PasswordSecret == "" {
		return nil, errors.New("acl.password_secret is required")
	}
	if c.KeyPattern == "" {
		c.KeyPattern = DefaultKeyPattern
	}
	if c.UsernameTemplate == "" {
		c.UsernameTemplate = DefaultUsernameTemplate
	}
	if c.Commands == "" {
		c.Commands = DefaultCommands
	}
	if c.Channels == nil {
		ch := DefaultChannels
		c.Channels = &ch
	}
	a := &aclTemplates{cfg: c, commands: strings.Fields(c.Commands)}
	for _, rule := range a.commands {
		if rule != "allcommands" && rule != "nocommands" && !strings.HasPrefix(rule, "+") && !strings.HasPrefix(rule, "-") {
			return nil, fmt.Errorf("acl.commands: %q is not a command rule (+cmd, -cmd, +@cat, -@cat)", rule)
		}
	}
	var err error
	if a.user, err = parseTemplate("acl.username_template", c.UsernameTemplate); err != nil {
		return nil, err
	}
	if a.keys, err = parseTemplate("acl.key_pattern", c.KeyPattern); err != nil {
		return nil, err
	}
	if *c.Channels != "" {
		if a.channels, err = parseTemplate("acl.channels", *c.Channels); err != nil {
			return nil, err
		}
	}
	// Render for two sample tenants: user names and key patterns must be
	// tenant specific, or tenants would share credentials and purges would
	// delete other tenants' keys.
	s1 := sdk.Tenant{ID: "00000000-0000-0000-0000-000000000001", Slug: "example-one", Name: "Example One"}
	s2 := sdk.Tenant{ID: "00000000-0000-0000-0000-000000000002", Slug: "example-two", Name: "Example Two"}
	t1, err := a.target(s1)
	if err != nil {
		return nil, err
	}
	t2, err := a.target(s2)
	if err != nil {
		return nil, err
	}
	if t1.User == t2.User {
		return nil, errors.New("acl.username_template must depend on the tenant (e.g. {{.Slug}} or {{.ID}})")
	}
	if strings.Join(t1.Keys, " ") == strings.Join(t2.Keys, " ") {
		return nil, errors.New("acl.key_pattern must depend on the tenant (e.g. {{.Slug}} or {{.ID}})")
	}
	return a, nil
}

func parseTemplate(field, s string) (*template.Template, error) {
	t, err := template.New(field).Option("missingkey=error").Parse(s)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	return t, nil
}

func render(t *template.Template, tenant sdk.Tenant) (string, error) {
	var b strings.Builder
	if err := t.Execute(&b, tenant); err != nil {
		return "", fmt.Errorf("%s: %w", t.Name(), err)
	}
	return b.String(), nil
}

func (a *aclTemplates) target(t sdk.Tenant) (aclTarget, error) {
	user, err := render(a.user, t)
	if err != nil {
		return aclTarget{}, err
	}
	if user == "" || strings.IndexFunc(user, func(r rune) bool { return unicode.IsSpace(r) || !unicode.IsPrint(r) }) >= 0 {
		return aclTarget{}, fmt.Errorf("acl.username_template renders invalid user name %q for tenant %s", user, t.ID)
	}
	if user == "default" {
		return aclTarget{}, fmt.Errorf("acl.username_template renders the reserved user name %q", user)
	}
	keys, err := render(a.keys, t)
	if err != nil {
		return aclTarget{}, err
	}
	tg := aclTarget{User: user, Keys: strings.Fields(keys)}
	if len(tg.Keys) == 0 {
		return aclTarget{}, fmt.Errorf("acl.key_pattern renders no pattern for tenant %s", t.ID)
	}
	if a.channels != nil {
		ch, err := render(a.channels, t)
		if err != nil {
			return aclTarget{}, err
		}
		tg.Channels = strings.Fields(ch)
	}
	return tg, nil
}

// aclProvisioner creates one ACL user per tenant.
//
// Each user carries a marker key "<prefix>acl-owner:<user>" holding its
// tenant ID. A user owned by another tenant (or one not created by the
// plugin) is never modified or deleted.
type aclProvisioner struct{ p *Plugin }

func (a *aclProvisioner) Name() string { return "acl" }

func (a *aclProvisioner) markerKey(user string) string { return a.p.key("acl-owner:", user) }

func (a *aclProvisioner) Provision(ctx context.Context, t sdk.Tenant) error {
	p := a.p
	tg, err := p.acl.target(t)
	if err != nil {
		return err
	}
	marker := a.markerKey(tg.User)
	owner, err := p.client.Get(ctx, marker).Result()
	switch {
	case errors.Is(err, redis.Nil):
		exists, err := a.userExists(ctx, tg.User)
		if err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("redis ACL user %q already exists and is not managed by tenarium", tg.User)
		}
		if _, err := p.client.SetNX(ctx, marker, t.ID, 0).Result(); err != nil {
			return err
		}
		if owner, err = p.client.Get(ctx, marker).Result(); err != nil {
			return err
		}
	case err != nil:
		return err
	}
	if owner != t.ID {
		return fmt.Errorf("redis ACL user %q belongs to tenant %s", tg.User, owner)
	}

	rules := []string{"reset", "resetchannels", "on", ">" + TenantPassword(p.acl.cfg.PasswordSecret, t.ID)}
	for _, k := range tg.Keys {
		rules = append(rules, "~"+k)
	}
	for _, c := range tg.Channels {
		rules = append(rules, "&"+c)
	}
	rules = append(rules, p.acl.commands...)
	if err := p.client.ACLSetUser(ctx, tg.User, rules...).Err(); err != nil {
		return fmt.Errorf("ACL SETUSER %s: %w", tg.User, err)
	}
	return a.save(ctx)
}

func (a *aclProvisioner) Deprovision(ctx context.Context, t sdk.Tenant) error {
	p := a.p
	tg, err := p.acl.target(t)
	if err != nil {
		return err
	}
	marker := a.markerKey(tg.User)
	owner, err := p.client.Get(ctx, marker).Result()
	if errors.Is(err, redis.Nil) {
		// Already deprovisioned, or never ours.
		return nil
	} else if err != nil {
		return err
	}
	if owner != t.ID {
		p.log.Warn("not removing redis ACL user owned by another tenant",
			"user", tg.User, "tenant", t.ID, "owner", owner)
		return nil
	}
	if err := p.client.ACLDelUser(ctx, tg.User).Err(); err != nil {
		return fmt.Errorf("ACL DELUSER %s: %w", tg.User, err)
	}
	if p.acl.cfg.PurgeKeysOnDelete {
		for _, pattern := range tg.Keys {
			if err := a.purge(ctx, pattern); err != nil {
				return err
			}
		}
	}
	// The marker goes last so a failed purge is retried.
	if err := p.client.Del(ctx, marker).Err(); err != nil {
		return err
	}
	return a.save(ctx)
}

func (a *aclProvisioner) userExists(ctx context.Context, user string) (bool, error) {
	err := a.p.client.Do(ctx, "ACL", "GETUSER", user).Err()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	return err == nil, err
}

// purge unlinks keys matching pattern in batches using SCAN.
func (a *aclProvisioner) purge(ctx context.Context, pattern string) error {
	var cursor uint64
	for {
		keys, next, err := a.p.client.Scan(ctx, cursor, pattern, 500).Result()
		if err != nil {
			return fmt.Errorf("scan %s: %w", pattern, err)
		}
		if len(keys) > 0 {
			if err := a.p.client.Unlink(ctx, keys...).Err(); err != nil {
				return err
			}
		}
		if next == 0 {
			return nil
		}
		cursor = next
	}
}

func (a *aclProvisioner) save(ctx context.Context) error {
	if !a.p.acl.cfg.Save {
		return nil
	}
	if err := a.p.client.Do(ctx, "ACL", "SAVE").Err(); err != nil {
		return fmt.Errorf("ACL SAVE: %w", err)
	}
	return nil
}
