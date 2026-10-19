package tenant

import (
	"context"
	"errors"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
)

// GDPR event types.
const (
	EventUserErased   = "user.erased"
	EventTenantPurged = "tenant.purged"
)

// exportEventLimit bounds the audit events included in an export.
const exportEventLimit = 10000

// TenantExport is everything Tenarium stores about a tenant (secrets
// excluded), for data portability requests.
type TenantExport struct {
	ExportedAt   time.Time               `json:"exported_at"`
	Tenant       sdk.Tenant              `json:"tenant"`
	Entitlements sdk.Entitlements        `json:"entitlements"`
	Members      []sdk.Member            `json:"members"`
	Usage        []store.Usage           `json:"usage"`
	Domains      []store.Domain          `json:"domains"`
	APIKeys      []store.APIKey          `json:"api_keys"`
	Webhooks     []store.Webhook         `json:"webhooks"`
	SSO          *store.SSOConnection    `json:"sso,omitempty"`
	Roles        []store.TenantRole      `json:"roles"`
	Groups       []store.Group           `json:"groups"`
	Schedule     []store.ScheduledAction `json:"schedule"`
	Events       []sdk.Event             `json:"events"`
	Truncated    bool                    `json:"events_truncated,omitempty"`
}

func collect[T any](items []T, err error, dst *[]T, errs *[]error) {
	if err != nil {
		*errs = append(*errs, err)
		return
	}
	*dst = items
}

// ExportTenant gathers a tenant's data.
func (s *Service) ExportTenant(ctx context.Context, tenantRef string) (TenantExport, error) {
	t, err := s.Get(ctx, tenantRef)
	if err != nil {
		return TenantExport{}, err
	}
	x := TenantExport{ExportedAt: s.now(), Tenant: t}
	var errs []error
	if x.Entitlements, err = s.entitlementsOf(ctx, t); err != nil {
		errs = append(errs, err)
	}
	ms, err := s.store.ListMembers(ctx, t.ID)
	collect(ms, err, &x.Members, &errs)
	us, err := s.store.ListUsage(ctx, store.UsageQuery{TenantID: t.ID})
	collect(us, err, &x.Usage, &errs)
	ds, err := s.store.ListDomains(ctx, t.ID)
	collect(ds, err, &x.Domains, &errs)
	ks, err := s.store.ListAPIKeys(ctx, t.ID)
	collect(ks, err, &x.APIKeys, &errs)
	ws, err := s.store.ListWebhooks(ctx, t.ID)
	collect(ws, err, &x.Webhooks, &errs)
	rs, err := s.store.ListTenantRoles(ctx, t.ID)
	collect(rs, err, &x.Roles, &errs)
	gs, err := s.store.ListGroups(ctx, t.ID)
	collect(gs, err, &x.Groups, &errs)
	sc, err := s.store.ListScheduledActions(ctx, t.ID)
	collect(sc, err, &x.Schedule, &errs)
	evs, err := s.store.QueryEvents(ctx, store.EventQuery{TenantIDs: []string{t.ID}, Limit: exportEventLimit + 1})
	collect(evs, err, &x.Events, &errs)
	if len(x.Events) > exportEventLimit {
		x.Events, x.Truncated = x.Events[:exportEventLimit], true
	}
	if c, err := s.store.GetSSOConnection(ctx, t.ID); err == nil {
		x.SSO = &c
	} else if !errors.Is(err, store.ErrNotFound) {
		errs = append(errs, err)
	}
	return x, errors.Join(errs...)
}

// UserExport is everything Tenarium stores about a user (secrets excluded).
type UserExport struct {
	ExportedAt  time.Time                  `json:"exported_at"`
	User        sdk.User                   `json:"user"`
	Memberships []sdk.Member               `json:"memberships"`
	MFA         MFAStatus                  `json:"mfa"`
	Passkeys    []store.WebAuthnCredential `json:"passkeys"`
	// Events the user caused (as signed-in user).
	Events    []sdk.Event `json:"events"`
	Truncated bool        `json:"events_truncated,omitempty"`
}

// ExportUser gathers a user's data.
func (s *Service) ExportUser(ctx context.Context, idOrEmail string) (UserExport, error) {
	u, err := s.GetUser(ctx, idOrEmail)
	if err != nil {
		return UserExport{}, err
	}
	x := UserExport{ExportedAt: s.now(), User: u}
	var errs []error
	ms, err := s.store.ListMembershipsOfUser(ctx, u.ID)
	collect(ms, err, &x.Memberships, &errs)
	if x.MFA, err = s.MFAStatus(ctx, u.ID); err != nil {
		errs = append(errs, err)
	}
	pk, err := s.store.ListWebAuthnCredentials(ctx, u.ID)
	collect(pk, err, &x.Passkeys, &errs)
	evs, err := s.store.QueryEvents(ctx, store.EventQuery{Actor: "core/token:" + u.ID, Limit: exportEventLimit + 1})
	collect(evs, err, &x.Events, &errs)
	if len(x.Events) > exportEventLimit {
		x.Events, x.Truncated = x.Events[:exportEventLimit], true
	}
	return x, errors.Join(errs...)
}

// EraseUser deletes a user everywhere (memberships, credentials, passkeys,
// sessions, the directory entry) and, with redact, replaces their email
// and name in the audit trail. Event actors keep the user ID, which is
// pseudonymous once the user record is gone. It returns how many events
// were redacted.
func (s *Service) EraseUser(ctx context.Context, idOrEmail string, redact bool) (int64, error) {
	u, err := s.GetUser(ctx, idOrEmail)
	if err != nil {
		return 0, err
	}
	if err := s.DeleteUser(ctx, u.ID); err != nil {
		return 0, err
	}
	var n int64
	if redact {
		for _, needle := range []string{u.Email, u.Name} {
			if len(needle) < 3 { // too short to replace safely
				continue
			}
			c, err := s.store.RedactEvents(ctx, needle, "[erased]")
			if err != nil {
				return n, err
			}
			n += c
		}
	}
	return n, s.RecordEvent(ctx, EventUserErased, "", "users/"+u.ID,
		map[string]any{"user_id": u.ID, "redacted_events": n})
}

// PurgeDeletedTenants removes the data of tenants deleted before olderThan
// ago (members, usage, keys, domains, webhooks, SSO, roles, groups,
// schedules) and blanks their settings and labels. The tenant record stays
// as a tombstone, with status reason "purged".
func (s *Service) PurgeDeletedTenants(ctx context.Context, olderThan time.Duration) (int, error) {
	cutoff := s.now().Add(-olderThan)
	n, after := 0, ""
	for {
		page, err := s.store.ListTenants(ctx, store.ListTenantsQuery{Status: sdk.StatusDeleted, IncludeDeleted: true, After: after, Limit: 200})
		if err != nil {
			return n, err
		}
		for _, t := range page {
			if t.StatusReason == "purged" || t.DeletedAt == nil || t.DeletedAt.After(cutoff) {
				continue
			}
			if err := s.purgeTenant(ctx, t); err != nil {
				return n, err
			}
			n++
		}
		if len(page) < 200 {
			break
		}
		after = page[len(page)-1].ID
	}
	if n > 0 {
		s.notify()
	}
	return n, nil
}

func (s *Service) purgeTenant(ctx context.Context, t sdk.Tenant) error {
	return s.store.InTx(ctx, func(tx store.Tx) error {
		cur, err := tx.GetTenant(ctx, t.ID)
		if err != nil {
			return err
		}
		prev := cur.Clone()
		if err := tx.PurgeTenantData(ctx, t.ID); err != nil {
			return err
		}
		cur.StatusReason, cur.Settings, cur.Labels, cur.Features, cur.Limits = "purged", nil, nil, nil, nil
		cur.Version, cur.UpdatedAt = prev.Version+1, s.now()
		if err := tx.UpdateTenant(ctx, cur, prev.Version); err != nil {
			return err
		}
		return s.appendEvent(ctx, tx, EventTenantPurged, t.ID, "tenants/"+t.ID, map[string]string{"tenant_id": t.ID})
	})
}
