package mongotenant

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func (p *Plugin) Name() string { return "mongodb" }

// markerSet indexes a database's marker documents.
type markerSet struct {
	owner, retained *marker
}

func (p *Plugin) markers(ctx context.Context, db string) (markerSet, error) {
	ms, err := p.db.Markers(ctx, db)
	if err != nil {
		return markerSet{}, err
	}
	var s markerSet
	for i := range ms {
		switch ms[i].ID {
		case markerOwner:
			s.owner = &ms[i]
		case markerRetained:
			s.retained = &ms[i]
		}
	}
	return s, nil
}

// hasData reports whether db holds any collection besides the marker
// collection.
func (p *Plugin) hasData(ctx context.Context, db string) (bool, error) {
	names, err := p.db.Collections(ctx, db)
	if err != nil {
		return false, err
	}
	for _, n := range names {
		if n != MarkerCollection {
			return true, nil
		}
	}
	return false, nil
}

// Provision creates or claims the tenant database, then creates or updates
// its user. Every step is idempotent.
func (p *Plugin) Provision(ctx context.Context, t sdk.Tenant) error {
	tg, err := p.target(t)
	if err != nil {
		return err
	}
	quota, err := p.quota(ctx, t)
	if err != nil {
		return err
	}
	if err := p.claimDatabase(ctx, tg.Database, t, quota); err != nil {
		return err
	}
	return p.ensureUser(ctx, tg, t)
}

// claimDatabase makes sure db carries t's owner marker. Databases owned by
// another tenant or retained from a deleted one are refused; unmarked
// databases are adopted only when they have no collections.
func (p *Plugin) claimDatabase(ctx context.Context, db string, t sdk.Tenant, quota *int64) error {
	for attempt := 0; ; attempt++ {
		ms, err := p.markers(ctx, db)
		if err != nil {
			return err
		}
		switch {
		case ms.owner != nil && ms.owner.TenantID == t.ID:
			return p.updateOwner(ctx, db, *ms.owner, quota)
		case ms.owner != nil:
			return fmt.Errorf("database %s already exists and belongs to another tenant (%s)", db, ms.owner.TenantID)
		case ms.retained != nil:
			return fmt.Errorf("database %s holds data retained from deleted tenant %s (deleted at %s); drop or rename it before provisioning a tenant with this name",
				db, ms.retained.DeletedTenantID, ms.retained.DeletedAt.Format(time.RFC3339))
		}
		data, err := p.hasData(ctx, db)
		if err != nil {
			return err
		}
		if data {
			return fmt.Errorf("database %s already exists, is not empty and is not managed by tenarium", db)
		}
		m := marker{ID: markerOwner, TenantID: t.ID, TenantSlug: t.Slug, CreatedAt: p.now().UTC()}
		if quota != nil {
			m.QuotaMetric, m.QuotaLimit = p.cfg.QuotaFromLimit, quota
		}
		err = p.db.InsertMarker(ctx, db, m)
		if !errors.Is(err, errDuplicate) || attempt > 0 {
			return err
		}
		// Claimed concurrently: re-read to see by whom.
	}
}

// updateOwner refreshes the quota recorded in the owner marker.
func (p *Plugin) updateOwner(ctx context.Context, db string, cur marker, quota *int64) error {
	want := cur
	want.QuotaMetric, want.QuotaLimit = "", nil
	if quota != nil {
		want.QuotaMetric, want.QuotaLimit = p.cfg.QuotaFromLimit, quota
	}
	if want.QuotaMetric == cur.QuotaMetric && equalLimit(want.QuotaLimit, cur.QuotaLimit) {
		return nil
	}
	return p.db.PutMarker(ctx, db, want)
}

func equalLimit(a, b *int64) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// ensureUser creates the tenant user or resets its password, roles and
// customData. Users marked for another tenant, or not marked at all, are
// refused.
func (p *Plugin) ensureUser(ctx context.Context, tg target, t sdk.Tenant) error {
	pwd := TenantPassword(p.cfg.PasswordSecret, t.ID)
	roles := p.roles(tg.Database)
	custom := map[string]any{CustomDataTenantID: t.ID}
	u, err := p.db.User(ctx, tg.AuthDatabase, tg.User)
	if err != nil {
		return err
	}
	if u == nil {
		err := p.db.CreateUser(ctx, tg.AuthDatabase, tg.User, pwd, roles, custom)
		if !errors.Is(err, errDuplicate) {
			return err
		}
		// Created concurrently: check whose it is before updating it.
		if u, err = p.db.User(ctx, tg.AuthDatabase, tg.User); err != nil {
			return err
		}
		if u == nil {
			return fmt.Errorf("user %s@%s vanished while being created", tg.User, tg.AuthDatabase)
		}
	}
	switch owner := u.tenantID(); owner {
	case t.ID:
	case "":
		return fmt.Errorf("user %s@%s already exists and is not managed by tenarium", tg.User, tg.AuthDatabase)
	default:
		return fmt.Errorf("user %s@%s already exists and belongs to another tenant (%s)", tg.User, tg.AuthDatabase, owner)
	}
	return p.db.UpdateUser(ctx, tg.AuthDatabase, tg.User, pwd, roles, custom)
}

// Deprovision applies on_deprovision. Missing resources count as already
// deprovisioned.
func (p *Plugin) Deprovision(ctx context.Context, t sdk.Tenant) error {
	if p.cfg.OnDeprovision == DeprovisionKeep {
		return nil
	}
	tg, err := p.target(t)
	if err != nil {
		return err
	}
	// The user goes first so access ends before the data does. It is
	// handled on its own ownership marker, independently of the database.
	if err := p.dropUser(ctx, tg, t); err != nil {
		return err
	}
	ms, err := p.markers(ctx, tg.Database)
	if err != nil {
		return err
	}
	switch {
	case ms.owner != nil && ms.owner.TenantID == t.ID:
	case ms.owner != nil:
		p.log.Warn("not deprovisioning a database owned by another tenant",
			"database", tg.Database, "tenant_id", t.ID, "owner", ms.owner.TenantID)
		return nil
	case ms.retained != nil:
		if ms.retained.DeletedTenantID != t.ID {
			p.log.Warn("not deprovisioning a database retained from another tenant",
				"database", tg.Database, "tenant_id", t.ID, "owner", ms.retained.DeletedTenantID)
		}
		return nil // already retained
	default:
		// Unmarked: an empty database does not exist in MongoDB, and data
		// without a marker is not ours.
		data, err := p.hasData(ctx, tg.Database)
		if err != nil {
			return err
		}
		if data {
			p.log.Warn("not deprovisioning an unmanaged database", "database", tg.Database, "tenant_id", t.ID)
		}
		return nil
	}

	if p.cfg.OnDeprovision == DeprovisionRetain {
		// Write the retained marker before removing the owner marker, so an
		// interrupted run still finds the database owned and retries.
		r := marker{ID: markerRetained, DeletedAt: p.now().UTC(), DeletedTenantID: t.ID, TenantSlug: t.Slug}
		if err := p.db.PutMarker(ctx, tg.Database, r); err != nil {
			return err
		}
		return p.db.DeleteMarker(ctx, tg.Database, markerOwner)
	}
	return p.db.DropDatabase(ctx, tg.Database)
}

func (p *Plugin) dropUser(ctx context.Context, tg target, t sdk.Tenant) error {
	u, err := p.db.User(ctx, tg.AuthDatabase, tg.User)
	if err != nil || u == nil {
		return err
	}
	if owner := u.tenantID(); owner != t.ID {
		p.log.Warn("not dropping a user that does not belong to the tenant",
			"user", tg.User, "auth_database", tg.AuthDatabase, "tenant_id", t.ID, "owner", owner)
		return nil
	}
	return p.db.DropUser(ctx, tg.AuthDatabase, tg.User)
}

// quota returns the tenant's quota_from_limit value, or nil when not
// configured or unlimited.
func (p *Plugin) quota(ctx context.Context, t sdk.Tenant) (*int64, error) {
	if p.cfg.QuotaFromLimit == "" {
		return nil, nil
	}
	e, err := p.host.Entitlements(ctx, t.ID)
	if err != nil {
		return nil, fmt.Errorf("entitlements: %w", err)
	}
	if v, ok := e.Limit(p.cfg.QuotaFromLimit); ok {
		return &v, nil
	}
	return nil, nil
}
