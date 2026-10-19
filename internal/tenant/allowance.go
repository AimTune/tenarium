package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/google/uuid"
)

// UsageGrant is a share of a tenant's limit reserved for a regional cell
// (or any client far from the control plane), which then enforces it
// locally without a round trip per use and gives back what it did not
// use. The reserved amount counts as usage immediately, so limits stay
// exact across regions; a cell that disappears without releasing simply
// keeps its share as used.
type UsageGrant struct {
	ID        string     `json:"id"`
	TenantID  string     `json:"tenant_id"`
	Metric    string     `json:"metric"`
	Amount    int64      `json:"amount"`
	Period    string     `json:"period,omitempty"`
	PeriodEnd *time.Time `json:"period_end,omitempty"`
	ExpiresAt time.Time  `json:"expires_at"`
	// Holder names who holds the grant, e.g. a region or replica.
	Holder string `json:"holder,omitempty"`
}

const grantPrefix = "usage-grant/"

// grantReleased marks a grant claimed by a release, until it is deleted.
var grantReleased = []byte("released")

// GrantInput reserves part of a limit.
type GrantInput struct {
	Amount int64         `json:"amount"`
	TTL    time.Duration `json:"-"`
	Holder string        `json:"holder,omitempty"`
}

// ReserveUsage records amount as used now (enforcing the limit like
// RecordUsage, so a refused reservation means the limit is reached) and
// returns a grant to release later.
func (s *Service) ReserveUsage(ctx context.Context, tenantIDOrSlug, metric string, in GrantInput) (UsageGrant, error) {
	if in.Amount <= 0 {
		return UsageGrant{}, invalid("amount", "must be positive")
	}
	if in.TTL <= 0 || in.TTL > 24*time.Hour {
		return UsageGrant{}, invalid("ttl", "must be between 1s and 24h")
	}
	if len(in.Holder) > 128 {
		return UsageGrant{}, invalid("holder", "too long")
	}
	item, err := s.RecordUsage(ctx, tenantIDOrSlug, metric, in.Amount)
	if err != nil {
		return UsageGrant{}, err
	}
	t, err := s.Get(ctx, tenantIDOrSlug)
	if err != nil {
		return UsageGrant{}, err
	}
	g := UsageGrant{ID: uuid.Must(uuid.NewV7()).String(), TenantID: t.ID, Metric: metric, Amount: in.Amount,
		Period: item.Period, PeriodEnd: item.PeriodEnd, ExpiresAt: s.now().Add(in.TTL), Holder: in.Holder}
	b, err := json.Marshal(g)
	if err != nil {
		return UsageGrant{}, err
	}
	if err := s.store.KVPut(ctx, grantPrefix+g.ID, b); err != nil {
		// Give the reservation back rather than leak it.
		_, _ = s.store.IncrementUsage(ctx, g.usageKey(), -g.Amount, nil)
		return UsageGrant{}, err
	}
	return g, nil
}

func (g UsageGrant) usageKey() store.UsageKey {
	return store.UsageKey{TenantID: g.TenantID, Metric: g.Metric, Period: g.Period, PeriodEnd: g.PeriodEnd}
}

// ErrGrantGone means the grant was already released or has expired; its
// whole amount stays counted as used.
var ErrGrantGone = errors.New("usage grant already released or expired")

// ReleaseUsage closes a grant, giving back the part that was not used.
// Nothing is given back once the grant has expired or its period has
// ended (the counter of that period is final by then).
func (s *Service) ReleaseUsage(ctx context.Context, tenantIDOrSlug, grantID string, used int64) (UsageGrant, error) {
	t, err := s.Get(ctx, tenantIDOrSlug)
	if err != nil {
		return UsageGrant{}, err
	}
	raw, err := s.store.KVGet(ctx, grantPrefix+grantID)
	if errors.Is(err, store.ErrNotFound) {
		return UsageGrant{}, ErrGrantGone
	} else if err != nil {
		return UsageGrant{}, err
	}
	var g UsageGrant
	if err := json.Unmarshal(raw, &g); err != nil {
		return UsageGrant{}, err
	}
	if g.TenantID != t.ID {
		return UsageGrant{}, store.ErrNotFound
	}
	if used < 0 || used > g.Amount {
		return UsageGrant{}, invalid("used", "must be between 0 and the granted %d", g.Amount)
	}
	// Claim the grant first, so two releases cannot both refund.
	if ok, err := s.store.KVCompareAndSwap(ctx, grantPrefix+grantID, raw, grantReleased); err != nil {
		return UsageGrant{}, err
	} else if !ok {
		return UsageGrant{}, ErrGrantGone
	}
	_ = s.store.KVDelete(ctx, grantPrefix+grantID)
	now := s.now()
	if now.After(g.ExpiresAt) || (g.PeriodEnd != nil && !now.Before(*g.PeriodEnd)) {
		return g, ErrGrantGone
	}
	if unused := g.Amount - used; unused > 0 {
		if _, err := s.store.IncrementUsage(ctx, g.usageKey(), -unused, nil); err != nil {
			return g, err
		}
	}
	return g, nil
}

// PurgeExpiredGrants deletes grants past their expiry (their amount stays
// counted). It runs with the scheduler.
func (s *Service) PurgeExpiredGrants(ctx context.Context) (int, error) {
	keys, err := s.store.KVKeys(ctx, grantPrefix)
	if err != nil {
		return 0, err
	}
	n, now := 0, s.now()
	for _, k := range keys {
		raw, err := s.store.KVGet(ctx, k)
		if err != nil {
			continue
		}
		var g UsageGrant
		if string(raw) == string(grantReleased) || (json.Unmarshal(raw, &g) == nil && now.After(g.ExpiresAt)) {
			if err := s.store.KVDelete(ctx, k); err == nil {
				n++
			}
		}
	}
	return n, nil
}
