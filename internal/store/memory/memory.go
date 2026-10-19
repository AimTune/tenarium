// Package memory is an in-process Store for development and tests. Data is
// lost on restart.
package memory

import (
	"context"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
)

type lease struct {
	owner     string
	expires   time.Time
	preferred bool
}

type Store struct {
	mu           sync.RWMutex
	tenants      map[string]sdk.Tenant
	plans        map[string]sdk.Plan
	members      map[string]sdk.Member // by member ID
	usage        map[string]store.Usage
	events       []sdk.Event
	cursors      map[string]int64
	leases       map[string]lease
	deadLetters  []store.DeadLetter
	idem         map[string]store.IdempotencyRecord
	users        map[string]sdk.User
	creds        map[string]store.Credentials
	actions      map[string]actionToken
	refresh      map[string]refreshToken
	keys         []store.SigningKey
	apiKeys      map[string]store.APIKey
	domains      map[string]store.Domain
	schedule     map[string]store.ScheduledAction
	mfa          map[string]store.MFA
	webhooks     map[string]store.Webhook
	deliveries   map[string]store.WebhookDelivery
	sso          map[string]store.SSOConnection
	roles        map[string]store.TenantRole
	groups       map[string]store.Group
	passkeys     map[string]store.WebAuthnCredential
	oauthClients map[string]store.OAuthClient
	consents     map[string]store.OAuthConsent
	kv           map[string][]byte
	planRevs     map[string]store.PlanRevision
	rollouts     map[string]store.Rollout
	templates    map[string][]byte
	rates        map[rateKey]int
	// pruned is the number of events deleted from the front of events, so
	// events[i].Seq == pruned+i+1.
	pruned int64
	now    func() time.Time
}

var _ store.Store = (*Store)(nil)

func New() *Store {
	return &Store{
		tenants:      map[string]sdk.Tenant{},
		plans:        map[string]sdk.Plan{},
		members:      map[string]sdk.Member{},
		usage:        map[string]store.Usage{},
		cursors:      map[string]int64{},
		leases:       map[string]lease{},
		idem:         map[string]store.IdempotencyRecord{},
		users:        map[string]sdk.User{},
		creds:        map[string]store.Credentials{},
		actions:      map[string]actionToken{},
		refresh:      map[string]refreshToken{},
		apiKeys:      map[string]store.APIKey{},
		domains:      map[string]store.Domain{},
		schedule:     map[string]store.ScheduledAction{},
		mfa:          map[string]store.MFA{},
		webhooks:     map[string]store.Webhook{},
		deliveries:   map[string]store.WebhookDelivery{},
		sso:          map[string]store.SSOConnection{},
		roles:        map[string]store.TenantRole{},
		groups:       map[string]store.Group{},
		passkeys:     map[string]store.WebAuthnCredential{},
		oauthClients: map[string]store.OAuthClient{},
		consents:     map[string]store.OAuthConsent{},
		kv:           map[string][]byte{},
		planRevs:     map[string]store.PlanRevision{},
		rollouts:     map[string]store.Rollout{},
		templates:    map[string][]byte{},
		now:          time.Now,
	}
}

// InTx serialises transactions with a single write lock and stages writes
// until fn succeeds.
func (s *Store) InTx(ctx context.Context, fn func(tx store.Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx := &tx{
		s:        s,
		tenants:  maps.Clone(s.tenants),
		plans:    maps.Clone(s.plans),
		members:  maps.Clone(s.members),
		users:    maps.Clone(s.users),
		creds:    maps.Clone(s.creds),
		apiKeys:  maps.Clone(s.apiKeys),
		domains:  maps.Clone(s.domains),
		schedule: maps.Clone(s.schedule),
		webhooks: maps.Clone(s.webhooks),
		roles:    maps.Clone(s.roles),
		groups:   maps.Clone(s.groups),
		planRevs: maps.Clone(s.planRevs),
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.tenants, s.plans, s.members = tx.tenants, tx.plans, tx.members
	s.users, s.creds, s.apiKeys = tx.users, tx.creds, tx.apiKeys
	s.domains, s.schedule = tx.domains, tx.schedule
	s.webhooks = tx.webhooks
	s.roles, s.groups = tx.roles, tx.groups
	s.planRevs = tx.planRevs
	if tx.webhookDeleted {
		s.dropOrphanDeliveries()
	}
	s.forgetUsers(tx.deletedUsers)
	s.applyUsageClosures(tx)
	s.events = append(s.events, tx.events...)
	return nil
}

func (s *Store) GetTenant(_ context.Context, id string) (sdk.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tenants[id]
	if !ok {
		return sdk.Tenant{}, store.ErrNotFound
	}
	return t.Clone(), nil
}

func (s *Store) GetTenantBySlug(_ context.Context, slug string) (sdk.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.tenants {
		if t.Slug == slug && t.Status != sdk.StatusDeleted {
			return t.Clone(), nil
		}
	}
	return sdk.Tenant{}, store.ErrNotFound
}

func (s *Store) ListTenants(_ context.Context, q store.ListTenantsQuery) ([]sdk.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []sdk.Tenant
	for _, id := range slices.Sorted(maps.Keys(s.tenants)) {
		if q.After != "" && id <= q.After {
			continue
		}
		t := s.tenants[id]
		switch {
		case !q.IncludeDeleted && t.Status == sdk.StatusDeleted,
			q.Status != "" && t.Status != q.Status,
			q.Plan != "" && t.Plan != q.Plan,
			q.ParentID != "" && t.ParentID != q.ParentID,
			q.IDs != nil && !slices.Contains(q.IDs, t.ID),
			!labelsMatch(t.Labels, q.Labels):
			continue
		}
		out = append(out, t.Clone())
		if q.Limit > 0 && len(out) == q.Limit {
			break
		}
	}
	return out, nil
}

func labelsMatch(have, want map[string]string) bool {
	for k, v := range want {
		if hv, ok := have[k]; !ok || hv != v {
			return false
		}
	}
	return true
}

func (s *Store) GetPlan(_ context.Context, id string) (sdk.Plan, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.plans[id]
	if !ok {
		return sdk.Plan{}, store.ErrNotFound
	}
	return p.Clone(), nil
}

func (s *Store) ListPlans(context.Context) ([]sdk.Plan, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]sdk.Plan, 0, len(s.plans))
	for _, id := range slices.Sorted(maps.Keys(s.plans)) {
		out = append(out, s.plans[id].Clone())
	}
	return out, nil
}

func (s *Store) GetMember(_ context.Context, tenantID, memberID string) (sdk.Member, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.members[memberID]
	if !ok || m.TenantID != tenantID {
		return sdk.Member{}, store.ErrNotFound
	}
	return m, nil
}

func (s *Store) ListMembers(_ context.Context, tenantID string) ([]sdk.Member, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []sdk.Member
	for _, id := range slices.Sorted(maps.Keys(s.members)) {
		if m := s.members[id]; m.TenantID == tenantID {
			out = append(out, m)
		}
	}
	return out, nil
}

func (s *Store) ReadEvents(_ context.Context, after int64, limit int) ([]sdk.Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Seq is 1-based and dense, so it doubles as an index (offset by pruned).
	start := int(max(after-s.pruned, 0))
	if start >= len(s.events) {
		return nil, nil
	}
	end := len(s.events)
	if limit > 0 {
		end = min(end, start+limit)
	}
	return slices.Clone(s.events[start:end]), nil
}

func (s *Store) LastEventSeq(context.Context) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pruned + int64(len(s.events)), nil
}

func (s *Store) GetCursor(_ context.Context, sub string) (int64, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seq, ok := s.cursors[sub]
	return seq, ok, nil
}

func (s *Store) SetCursor(_ context.Context, sub string, seq int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cursors[sub] = max(s.cursors[sub], seq)
	return nil
}

func (s *Store) AcquireLease(_ context.Context, name, owner string, ttl time.Duration, preferred bool) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if l, ok := s.leases[name]; ok && l.owner != owner && now.Before(l.expires) && (l.preferred || !preferred) {
		return false, nil
	}
	s.leases[name] = lease{owner: owner, expires: now.Add(ttl), preferred: preferred}
	return true, nil
}

func (s *Store) ReleaseLease(_ context.Context, name, owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l, ok := s.leases[name]; ok && l.owner == owner {
		delete(s.leases, name)
	}
	return nil
}

func (s *Store) AddDeadLetter(_ context.Context, dl store.DeadLetter) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deadLetters = append(s.deadLetters, dl)
	return nil
}

func (s *Store) GetDeadLetter(_ context.Context, id string) (store.DeadLetter, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, dl := range s.deadLetters {
		if dl.ID == id {
			return dl, nil
		}
	}
	return store.DeadLetter{}, store.ErrNotFound
}

func (s *Store) ListDeadLetters(_ context.Context, sub string, limit int) ([]store.DeadLetter, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []store.DeadLetter
	for _, dl := range s.deadLetters {
		if sub != "" && dl.Subscription != sub {
			continue
		}
		out = append(out, dl)
		if limit > 0 && len(out) == limit {
			break
		}
	}
	return out, nil
}

func (s *Store) DeleteDeadLetter(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := slices.IndexFunc(s.deadLetters, func(dl store.DeadLetter) bool { return dl.ID == id })
	if i < 0 {
		return store.ErrNotFound
	}
	s.deadLetters = slices.Delete(s.deadLetters, i, i+1)
	return nil
}

func (s *Store) GetIdempotency(_ context.Context, key string) (store.IdempotencyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.idem[key]
	if !ok {
		return store.IdempotencyRecord{}, store.ErrNotFound
	}
	return rec, nil
}

func (s *Store) PutIdempotency(_ context.Context, rec store.IdempotencyRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.idem[rec.Key]; ok {
		return store.ErrAlreadyExists
	}
	s.idem[rec.Key] = rec
	return nil
}

func (s *Store) Close() error { return nil }

// tx works on copies of the parent's maps; the parent's write lock is held
// for its lifetime and the copies replace the originals on commit.
type tx struct {
	s              *Store
	tenants        map[string]sdk.Tenant
	plans          map[string]sdk.Plan
	members        map[string]sdk.Member
	users          map[string]sdk.User
	creds          map[string]store.Credentials
	deletedUsers   []string
	apiKeys        map[string]store.APIKey
	domains        map[string]store.Domain
	schedule       map[string]store.ScheduledAction
	webhooks       map[string]store.Webhook
	roles          map[string]store.TenantRole
	groups         map[string]store.Group
	planRevs       map[string]store.PlanRevision
	webhookDeleted bool
	closedUsage    []string
	closedAt       time.Time
	events         []sdk.Event
}

func (t *tx) GetTenant(_ context.Context, id string) (sdk.Tenant, error) {
	v, ok := t.tenants[id]
	if !ok {
		return sdk.Tenant{}, store.ErrNotFound
	}
	return v.Clone(), nil
}

func (t *tx) CreateTenant(_ context.Context, nt sdk.Tenant) error {
	if _, ok := t.tenants[nt.ID]; ok {
		return store.ErrAlreadyExists
	}
	for _, existing := range t.tenants {
		if existing.Slug == nt.Slug && existing.Status != sdk.StatusDeleted {
			return store.ErrAlreadyExists
		}
	}
	t.tenants[nt.ID] = nt.Clone()
	return nil
}

func (t *tx) UpdateTenant(_ context.Context, nt sdk.Tenant, expectedVersion int64) error {
	cur, ok := t.tenants[nt.ID]
	if !ok {
		return store.ErrNotFound
	}
	if cur.Version != expectedVersion {
		return store.ErrConflict
	}
	t.tenants[nt.ID] = nt.Clone()
	return nil
}

func (t *tx) CountLiveChildren(_ context.Context, id string) (int, error) {
	n := 0
	for _, c := range t.tenants {
		if c.ParentID == id && c.Status != sdk.StatusDeleted {
			n++
		}
	}
	return n, nil
}

func (t *tx) CreatePlan(_ context.Context, p sdk.Plan) error {
	if _, ok := t.plans[p.ID]; ok {
		return store.ErrAlreadyExists
	}
	t.plans[p.ID] = p.Clone()
	return nil
}

func (t *tx) UpdatePlan(_ context.Context, p sdk.Plan, expectedVersion int64) error {
	cur, ok := t.plans[p.ID]
	if !ok {
		return store.ErrNotFound
	}
	if cur.Version != expectedVersion {
		return store.ErrConflict
	}
	t.plans[p.ID] = p.Clone()
	return nil
}

func (t *tx) DeletePlan(_ context.Context, id string) error {
	if _, ok := t.plans[id]; !ok {
		return store.ErrNotFound
	}
	delete(t.plans, id)
	return nil
}

func (t *tx) CountTenantsOnPlan(_ context.Context, planID string) (int, error) {
	n := 0
	for _, tn := range t.tenants {
		if tn.Plan == planID && tn.Status != sdk.StatusDeleted {
			n++
		}
	}
	return n, nil
}

func (t *tx) CreateMember(_ context.Context, m sdk.Member) error {
	for _, e := range t.members {
		if e.ID == m.ID || (e.TenantID == m.TenantID && strings.EqualFold(e.Email, m.Email)) {
			return store.ErrAlreadyExists
		}
	}
	t.members[m.ID] = m
	return nil
}

func (t *tx) UpdateMember(_ context.Context, m sdk.Member, expectedVersion int64) error {
	cur, ok := t.members[m.ID]
	if !ok || cur.TenantID != m.TenantID {
		return store.ErrNotFound
	}
	if cur.Version != expectedVersion {
		return store.ErrConflict
	}
	t.members[m.ID] = m
	return nil
}

func (t *tx) DeleteMember(_ context.Context, tenantID, memberID string) error {
	cur, ok := t.members[memberID]
	if !ok || cur.TenantID != tenantID {
		return store.ErrNotFound
	}
	delete(t.members, memberID)
	return nil
}

func (t *tx) CountMembers(_ context.Context, tenantID string) (int, error) {
	n := 0
	for _, m := range t.members {
		if m.TenantID == tenantID {
			n++
		}
	}
	return n, nil
}

func (t *tx) AppendEvents(_ context.Context, events ...sdk.Event) ([]sdk.Event, error) {
	next := t.s.pruned + int64(len(t.s.events)+len(t.events))
	out := make([]sdk.Event, len(events))
	for i, e := range events {
		next++
		e.Seq = next
		out[i] = e
	}
	t.events = append(t.events, out...)
	return out, nil
}
