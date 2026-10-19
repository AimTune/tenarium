package rabbitmqvhost

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func (p *Plugin) Name() string { return "rabbitmq-vhost" }

// owner returns the tenant ID a resource is marked for and, for a retained
// vhost, the ID of the deleted tenant whose data it holds.
func owner(tags []string) (ownerID, retainedID string) {
	for _, tag := range tags {
		if id, ok := strings.CutPrefix(tag, TagTenantID); ok {
			ownerID = id
		} else if id, ok := strings.CutPrefix(tag, TagRetainedTenantID); ok {
			retainedID = id
		}
	}
	return ownerID, retainedID
}

// checkOwner fails unless an existing resource is marked for tenantID.
func checkOwner(kind, name string, tags []string, tenantID string) error {
	ownerID, retainedID := owner(tags)
	switch {
	case ownerID == tenantID:
		return nil
	case ownerID != "":
		return fmt.Errorf("rabbitmq %s %q belongs to tenant %s", kind, name, ownerID)
	case retainedID != "":
		return fmt.Errorf("rabbitmq %s %q holds retained data of deleted tenant %s; an operator must remove or rename it first", kind, name, retainedID)
	default:
		return fmt.Errorf("rabbitmq %s %q already exists and is not managed by tenarium", kind, name)
	}
}

// foreignTags returns the tags not managed by the plugin, so operator tags
// survive updates.
func foreignTags(tags []string) []string {
	var out []string
	for _, t := range tags {
		if !strings.HasPrefix(t, tagReserved) {
			out = append(out, t)
		}
	}
	return out
}

// Provision creates or claims the tenant's vhost and user, sets the
// password, permissions and vhost limits. Every step is idempotent.
func (p *Plugin) Provision(ctx context.Context, t sdk.Tenant) error {
	tg, err := p.target(t)
	if err != nil {
		return err
	}
	limits, err := p.limits(ctx, t)
	if err != nil {
		return err
	}
	// Check both resources before changing anything.
	vh, err := p.api.getVhost(ctx, tg.Vhost)
	if err != nil {
		return err
	}
	var vhTags []string
	if vh != nil {
		vhTags = vh.tags()
		if err := checkOwner("vhost", tg.Vhost, vhTags, t.ID); err != nil {
			return err
		}
	}
	u, err := p.api.getUser(ctx, tg.User)
	if err != nil {
		return err
	}
	if u != nil {
		if err := checkOwner("user", tg.User, u.Tags, t.ID); err != nil {
			return err
		}
	}

	marker := TagTenantID + t.ID
	tags := append(foreignTags(vhTags), marker)
	if err := p.api.putVhost(ctx, tg.Vhost, vhostBody{
		Description:      fmt.Sprintf("Tenarium tenant %s (%s)", t.Slug, t.ID),
		Tags:             strings.Join(tags, ","),
		DefaultQueueType: p.cfg.DefaultQueueType,
	}); err != nil {
		return err
	}
	if err := p.verifyVhostTags(ctx, tg.Vhost, marker, ""); err != nil {
		return err
	}

	userTags := append(append([]string{}, p.cfg.UserTags...), marker)
	if err := p.api.putUser(ctx, tg.User, userBody{
		Password: TenantPassword(p.cfg.PasswordSecret, t.ID),
		Tags:     strings.Join(userTags, ","),
	}); err != nil {
		return err
	}
	if err := p.api.putPermissions(ctx, tg.Vhost, tg.User, p.perms); err != nil {
		return err
	}
	for _, name := range sortedKeys(p.cfg.Limits) {
		if v, ok := limits[name]; ok {
			if err := p.api.putVhostLimit(ctx, tg.Vhost, name, v); err != nil {
				return err
			}
		} else if err := p.api.deleteIgnoreMissing(ctx, "/api/vhost-limits/"+esc(tg.Vhost)+"/"+esc(name)); err != nil {
			return err
		}
	}
	return nil
}

// verifyVhostTags re-reads the vhost and checks that want is (or, with
// gone, that gone is no longer) among its tags. RabbitMQ releases without
// vhost metadata support silently drop tags, which would leave a vhost
// without ownership marker.
func (p *Plugin) verifyVhostTags(ctx context.Context, vhost, want, gone string) error {
	vh, err := p.api.getVhost(ctx, vhost)
	if err != nil {
		return err
	}
	if vh == nil {
		return fmt.Errorf("rabbitmq vhost %q disappeared while provisioning", vhost)
	}
	tags := vh.tags()
	hasWant := want == ""
	for _, t := range tags {
		if t == want {
			hasWant = true
		}
		if gone != "" && t == gone {
			return fmt.Errorf("rabbitmq vhost %q: the server did not update vhost tags (RabbitMQ 3.11 or later is required)", vhost)
		}
	}
	if !hasWant {
		return fmt.Errorf("rabbitmq vhost %q: the server did not store vhost tags (RabbitMQ 3.11 or later is required)", vhost)
	}
	return nil
}

// limits returns the configured vhost limits that are set for the tenant.
// Absent or negative entitlement limits are unlimited and not returned.
func (p *Plugin) limits(ctx context.Context, t sdk.Tenant) (map[string]int64, error) {
	if len(p.cfg.Limits) == 0 {
		return nil, nil
	}
	e, err := p.host.Entitlements(ctx, t.ID)
	if err != nil {
		return nil, fmt.Errorf("entitlements: %w", err)
	}
	out := map[string]int64{}
	for name, limit := range p.cfg.Limits {
		if v, ok := e.Limit(limit); ok && v >= 0 {
			out[name] = v
		}
	}
	return out, nil
}

// Deprovision applies on_deprovision. Missing resources count as already
// deprovisioned; resources of another tenant are left alone.
func (p *Plugin) Deprovision(ctx context.Context, t sdk.Tenant) error {
	if p.cfg.OnDeprovision == DeprovisionKeep {
		return nil
	}
	tg, err := p.target(t)
	if err != nil {
		return err
	}
	// The user goes first: deleting it closes the tenant's connections.
	u, err := p.api.getUser(ctx, tg.User)
	if err != nil {
		return err
	}
	if u != nil {
		if ownerID, _ := owner(u.Tags); ownerID == t.ID {
			if err := p.api.deleteIgnoreMissing(ctx, "/api/users/"+esc(tg.User)); err != nil {
				return err
			}
		} else {
			p.log.Warn("not removing rabbitmq user not owned by the tenant",
				"user", tg.User, "tenant", t.ID, "owner", ownerID)
		}
	}

	vh, err := p.api.getVhost(ctx, tg.Vhost)
	if err != nil || vh == nil {
		return err
	}
	tags := vh.tags()
	ownerID, _ := owner(tags)
	if ownerID != t.ID {
		p.log.Warn("not removing rabbitmq vhost not owned by the tenant",
			"vhost", tg.Vhost, "tenant", t.ID, "owner", ownerID)
		return nil
	}
	if p.cfg.OnDeprovision == DeprovisionDelete {
		return p.api.deleteIgnoreMissing(ctx, "/api/vhosts/"+esc(tg.Vhost))
	}
	// retain: release ownership but keep the data.
	retained := append(foreignTags(tags),
		TagRetainedTenantID+t.ID,
		TagDeletedAt+p.now().UTC().Format(time.RFC3339))
	body := vhostBody{
		Description: fmt.Sprintf("Retained data of deleted Tenarium tenant %s (%s)", t.Slug, t.ID),
		Tags:        strings.Join(retained, ","),
		// Keep the queue type; omitting it could reset it on some releases.
		DefaultQueueType: knownQueueType(vh.DefaultQueueType),
	}
	if err := p.api.putVhost(ctx, tg.Vhost, body); err != nil {
		return err
	}
	return p.verifyVhostTags(ctx, tg.Vhost, TagRetainedTenantID+t.ID, TagTenantID+t.ID)
}

// knownQueueType returns q if it is a queue type that can be sent back to
// the server; RabbitMQ reports an unset type as "undefined".
func knownQueueType(q string) string {
	switch q {
	case "classic", "quorum", "stream":
		return q
	}
	return ""
}
