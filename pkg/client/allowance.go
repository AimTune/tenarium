package client

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// UsageGrant is a share of a tenant's limit reserved for local use (see
// UsageService.Reserve).
type UsageGrant struct {
	ID        string     `json:"id"`
	TenantID  string     `json:"tenant_id"`
	Metric    string     `json:"metric"`
	Amount    int64      `json:"amount"`
	Period    string     `json:"period,omitempty"`
	PeriodEnd *time.Time `json:"period_end,omitempty"`
	ExpiresAt time.Time  `json:"expires_at"`
	Holder    string     `json:"holder,omitempty"`
}

// Reserve records amount as used now and returns a grant to spend locally
// and release later. It fails with IsQuotaExceeded when the limit leaves
// no room for amount.
func (s *UsageService) Reserve(ctx context.Context, tenant, metric string, amount int64, ttl time.Duration, holder string, opts ...CallOption) (UsageGrant, error) {
	var g UsageGrant
	if err := checkIDs(tenant, metric); err != nil {
		return g, err
	}
	body := struct {
		Amount     int64  `json:"amount"`
		TTLSeconds int64  `json:"ttl_seconds"`
		Holder     string `json:"holder,omitempty"`
	}{amount, int64(ttl / time.Second), holder}
	err := s.c.do(ctx, http.MethodPost, "/v1/tenants/"+esc(tenant)+"/usage/"+esc(metric)+"/grants", nil, body, &g,
		append([]CallOption{autoIdempotency()}, opts...)...)
	return g, err
}

// Release closes a grant, giving back what was not used. Releasing a grant
// that expired or was already released fails with IsGrantGone.
func (s *UsageService) Release(ctx context.Context, g UsageGrant, used int64, opts ...CallOption) (UsageGrant, error) {
	var out UsageGrant
	if err := checkIDs(g.TenantID, g.Metric, g.ID); err != nil {
		return out, err
	}
	body := struct {
		Used int64 `json:"used"`
	}{used}
	err := s.c.do(ctx, http.MethodPost, "/v1/tenants/"+esc(g.TenantID)+"/usage/"+esc(g.Metric)+"/grants/"+esc(g.ID)+"/release",
		nil, body, &out, opts...)
	return out, err
}

// IsGrantGone reports releasing a grant that expired or was released.
func IsGrantGone(err error) bool { return hasCode(err, "grant_gone") }

// Allowance enforces a tenant's limit locally, for services far from the
// control plane: it reserves chunks of the limit and counts uses against
// them in memory, so only one call in chunk reaches Tenarium. Unused
// parts are given back on Close and when a chunk is replaced. It is safe
// for concurrent use.
type Allowance struct {
	usage          *UsageService
	tenant, metric string
	holder         string
	chunk          int64
	ttl            time.Duration
	now            func() time.Time

	mu    sync.Mutex
	grant *UsageGrant
	used  int64
}

// NewAllowance returns an Allowance reserving chunk units at a time, each
// grant living for ttl (renewed before it expires); holder names the
// caller (e.g. its region).
func (s *UsageService) NewAllowance(tenant, metric string, chunk int64, ttl time.Duration, holder string) *Allowance {
	return &Allowance{usage: s, tenant: tenant, metric: metric, holder: holder, chunk: max(chunk, 1), ttl: ttl, now: time.Now}
}

// Use counts n uses, reserving a new chunk when the current one is spent
// or about to expire. It fails with IsQuotaExceeded when the limit is
// reached.
func (a *Allowance) Use(ctx context.Context, n int64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.grant != nil && a.used+n <= a.grant.Amount && a.now().Before(a.grant.ExpiresAt.Add(-a.ttl/10)) {
		a.used += n
		return nil
	}
	if err := a.releaseLocked(ctx); err != nil && !IsGrantGone(err) {
		return err
	}
	g, err := a.usage.Reserve(ctx, a.tenant, a.metric, max(a.chunk, n), a.ttl, a.holder)
	if IsQuotaExceeded(err) && n < a.chunk {
		// Near the limit a whole chunk may not fit, but n might.
		g, err = a.usage.Reserve(ctx, a.tenant, a.metric, n, a.ttl, a.holder)
	}
	if err != nil {
		return err
	}
	a.grant, a.used = &g, n
	return nil
}

// Close gives back the unused part of the current chunk.
func (a *Allowance) Close(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.releaseLocked(ctx); err != nil && !IsGrantGone(err) {
		return err
	}
	return nil
}

func (a *Allowance) releaseLocked(ctx context.Context) error {
	if a.grant == nil {
		return nil
	}
	g, used := *a.grant, a.used
	a.grant, a.used = nil, 0
	_, err := a.usage.Release(ctx, g, used)
	return err
}
