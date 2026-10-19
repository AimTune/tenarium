package client_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/client"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/server"
)

func TestTenants(t *testing.T) {
	ctx := context.Background()
	c := newClient(t, startServer(t, baseConfig()), client.WithAPIKey(apiKey))

	for _, s := range []string{"t1", "t2", "t3", "t4", "t5"} {
		tn := must(c.Tenants.Create(ctx, client.CreateTenantRequest{Slug: s, Name: strings.ToUpper(s), Labels: map[string]string{"env": "test"}}))
		if tn.Status != sdk.StatusActive || tn.Version != 1 {
			t.Fatalf("created tenant: %+v", tn)
		}
	}

	// Pagination with a small page size.
	p := must(c.Tenants.List(ctx, client.TenantListOptions{Limit: 2}))
	if len(p.Items) != 2 || p.Next == "" {
		t.Fatalf("first page: %+v", p)
	}
	p2 := must(c.Tenants.List(ctx, client.TenantListOptions{Limit: 2, After: p.Next}))
	if len(p2.Items) != 2 || p2.Items[0].ID == p.Items[0].ID {
		t.Fatalf("second page: %+v", p2)
	}
	var slugs []string
	for tn, err := range c.Tenants.All(ctx, client.TenantListOptions{Limit: 2, Labels: map[string]string{"env": "test"}}) {
		if err != nil {
			t.Fatal(err)
		}
		slugs = append(slugs, tn.Slug)
	}
	if len(slugs) != 5 {
		t.Fatalf("iterator: %v", slugs)
	}
	// Breaking out of the iterator early is fine.
	n := 0
	for range c.Tenants.All(ctx, client.TenantListOptions{Limit: 2}) {
		if n++; n == 3 {
			break
		}
	}

	// Get by slug, optimistic locking.
	t1 := must(c.Tenants.Get(ctx, "t1"))
	upd := must(c.Tenants.Update(ctx, "t1", client.UpdateTenantRequest{Name: client.Ptr("Tenant One"), Settings: map[string]any{"theme": "dark"}}, client.IfMatch(t1.Version)))
	if upd.Name != "Tenant One" || upd.Version != t1.Version+1 || upd.Settings["theme"] != "dark" {
		t.Fatalf("update: %+v", upd)
	}
	_, err := c.Tenants.Update(ctx, "t1", client.UpdateTenantRequest{Name: client.Ptr("stale")}, client.IfMatch(t1.Version))
	if !client.IsVersionConflict(err) {
		t.Fatalf("stale update: %v", err)
	}
	apiErr, ok := client.AsError(err)
	if !ok || apiErr.Status != 412 || apiErr.Code != "version_conflict" || apiErr.RequestID == "" {
		t.Fatalf("error mapping: %#v", apiErr)
	}

	// Lifecycle transitions.
	if s := must(c.Tenants.Suspend(ctx, "t1", "unpaid")); s.Status != sdk.StatusSuspended || s.StatusReason != "unpaid" {
		t.Fatalf("suspend: %+v", s)
	}
	if _, err := c.Tenants.Suspend(ctx, "t1", ""); !client.IsConflict(err) {
		t.Fatalf("double suspend: %v", err)
	}
	if r := must(c.Tenants.Resume(ctx, "t1")); r.Status != sdk.StatusActive {
		t.Fatalf("resume: %+v", r)
	}

	// Children.
	for _, s := range []string{"c1", "c2", "c3"} {
		must(c.Tenants.Create(ctx, client.CreateTenantRequest{Slug: s, Name: s, ParentID: "t2"}))
	}
	cp := must(c.Tenants.Children(ctx, "t2", client.ListOptions{Limit: 2}))
	if len(cp.Items) != 2 || cp.Next == "" {
		t.Fatalf("children page: %+v", cp)
	}
	kids := must(client.Collect(c.Tenants.AllChildren(ctx, "t2", client.ListOptions{Limit: 2})))
	if len(kids) != 3 || kids[0].ParentID == "" {
		t.Fatalf("all children: %+v", kids)
	}
	if l := must(c.Tenants.List(ctx, client.TenantListOptions{ParentID: "t2"})); len(l.Items) != 3 {
		t.Fatalf("list by parent: %d", len(l.Items))
	}

	ent := must(c.Tenants.Entitlements(ctx, "t1"))
	if ent.TenantID != t1.ID {
		t.Fatalf("entitlements: %+v", ent)
	}

	// Errors.
	if _, err := c.Tenants.Create(ctx, client.CreateTenantRequest{Slug: "t1", Name: "dup"}); !client.IsConflict(err) {
		t.Fatalf("duplicate slug: %v", err)
	}
	_, err = c.Tenants.Create(ctx, client.CreateTenantRequest{Slug: "Bad Slug!", Name: "x"})
	if e, ok := client.AsError(err); !client.IsValidation(err) || !ok || e.Field != "slug" {
		t.Fatalf("validation: %v", err)
	}
	if _, err := c.Tenants.Get(ctx, "nope"); !client.IsNotFound(err) {
		t.Fatalf("not found: %v", err)
	}
	if _, err := c.Tenants.Get(ctx, ""); err == nil {
		t.Fatal("empty id accepted")
	}

	if d := must(c.Tenants.Delete(ctx, "t5")); d.IsLive() {
		t.Fatalf("delete: %+v", d)
	}
	if l := must(c.Tenants.List(ctx, client.TenantListOptions{IncludeDeleted: true, Status: sdk.StatusDeleted})); len(l.Items) != 1 {
		t.Fatalf("deleted list: %+v", l.Items)
	}

	// Credentials.
	anon := newClient(t, c.BaseURL())
	if _, err := anon.Tenants.List(ctx, client.TenantListOptions{}); !client.IsUnauthorized(err) {
		t.Fatalf("anonymous: %v", err)
	}
	me := must(c.Me(ctx))
	if me.Kind != "service" {
		t.Fatalf("me: %+v", me)
	}
}

func TestPlansMembersUsage(t *testing.T) {
	ctx := context.Background()
	cfg := baseConfig()
	cfg.Tenants.RequireKnownPlans = true
	cfg.Bootstrap.Plans = []server.BootstrapPlan{
		{ID: "free", Features: map[string]bool{"sso": false}, Limits: map[string]int64{"members": 2, "api_calls": 2}},
	}
	c := newClient(t, startServer(t, cfg), client.WithAPIKey(apiKey))

	// Plans.
	pro := must(c.Plans.Create(ctx, client.CreatePlanRequest{ID: "pro", Name: "Pro", Features: map[string]bool{"sso": true}, Limits: map[string]int64{"members": 10}}))
	if plans := must(c.Plans.List(ctx)); len(plans) != 2 {
		t.Fatalf("plans: %+v", plans)
	}
	upd := must(c.Plans.Update(ctx, "pro", client.UpdatePlanRequest{Description: client.Ptr("For teams")}, client.IfMatch(pro.Version)))
	if upd.Description != "For teams" || upd.Version != pro.Version+1 {
		t.Fatalf("plan update: %+v", upd)
	}
	if _, err := c.Plans.Update(ctx, "pro", client.UpdatePlanRequest{Name: client.Ptr("x")}, client.IfMatch(pro.Version)); !client.IsVersionConflict(err) {
		t.Fatalf("stale plan update: %v", err)
	}
	if g := must(c.Plans.Get(ctx, "pro")); g.Description != "For teams" {
		t.Fatalf("plan get: %+v", g)
	}
	must(c.Plans.Create(ctx, client.CreatePlanRequest{ID: "temp", Name: "Temp"}))
	if err := c.Plans.Delete(ctx, "temp"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Plans.Get(ctx, "temp"); !client.IsNotFound(err) {
		t.Fatalf("deleted plan: %v", err)
	}
	if _, err := c.Tenants.Create(ctx, client.CreateTenantRequest{Slug: "x", Name: "X", Plan: "gold"}); !client.IsValidation(err) {
		t.Fatalf("unknown plan: %v", err)
	}

	must(c.Tenants.Create(ctx, client.CreateTenantRequest{Slug: "acme", Name: "Acme", Plan: "free"}))
	if e := must(c.Tenants.Entitlements(ctx, "acme")); e.Limits["api_calls"] != 2 || e.HasFeature("sso") {
		t.Fatalf("entitlements: %+v", e)
	}

	// Members: inviting an unknown email creates an invited user.
	m := must(c.Members.Add(ctx, "acme", client.AddMemberRequest{Email: "ada@example.com", Name: "Ada", Role: "viewer"}))
	if m.Status != sdk.MemberInvited || m.Role != "viewer" {
		t.Fatalf("invite: %+v", m)
	}
	ml := must(c.Members.List(ctx, "acme"))
	if len(ml.Items) != 1 || len(ml.Roles) == 0 {
		t.Fatalf("members: %+v", ml)
	}
	if g := must(c.Members.Get(ctx, "acme", m.ID)); g.Email != "ada@example.com" {
		t.Fatalf("member get: %+v", g)
	}
	if u := must(c.Members.Update(ctx, "acme", m.ID, client.UpdateMemberRequest{Role: client.Ptr("admin")})); u.Role != "admin" {
		t.Fatalf("member update: %+v", u)
	}
	must(c.Members.Add(ctx, "acme", client.AddMemberRequest{Email: "bob@example.com", Role: "viewer"}))
	_, err := c.Members.Add(ctx, "acme", client.AddMemberRequest{Email: "eve@example.com", Role: "viewer"})
	if !client.IsQuotaExceeded(err) {
		t.Fatalf("member quota: %v", err)
	}

	// Users created by invitations.
	ada := must(c.Users.Get(ctx, "ada@example.com"))
	if ada.Status != sdk.UserInvited || ada.Name != "Ada" {
		t.Fatalf("invited user: %+v", ada)
	}
	if err := c.Users.ResendInvitation(ctx, ada.ID); err != nil {
		t.Fatal(err)
	}
	if ms := must(c.Users.Memberships(ctx, ada.ID)); len(ms) != 1 || ms[0].ID != m.ID {
		t.Fatalf("user memberships: %+v", ms)
	}
	if err := c.Members.Remove(ctx, "acme", m.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Members.Get(ctx, "acme", m.ID); !client.IsNotFound(err) {
		t.Fatalf("removed member: %v", err)
	}

	// Usage and quotas.
	for i := range 2 {
		it := must(c.Usage.Record(ctx, "acme", "api_calls", 1))
		if it.Value != int64(i+1) || it.Limit == nil || *it.Limit != 2 {
			t.Fatalf("record %d: %+v", i, it)
		}
	}
	_, err = c.Usage.Record(ctx, "acme", "api_calls", 1)
	if !client.IsQuotaExceeded(err) {
		t.Fatalf("quota: %v", err)
	}
	if e, _ := client.AsError(err); e.Status != 429 || e.Field != "api_calls" {
		t.Fatalf("quota error: %#v", e)
	}
	usage := must(c.Usage.Get(ctx, "acme"))
	found := false
	for _, u := range usage {
		found = found || (u.Metric == "api_calls" && u.Value == 2)
	}
	if !found {
		t.Fatalf("usage: %+v", usage)
	}
}

func TestAuthUsersAndTokenSource(t *testing.T) {
	ctx := context.Background()
	testMailbox.mu.Lock()
	testMailbox.sent = nil
	testMailbox.mu.Unlock()
	cfg := baseConfig()
	cfg.Auth.Tokens.AccessTTL = 2 * time.Second
	base := startServer(t, cfg)
	pub := newClient(t, base)

	if _, err := pub.Auth.Login(ctx, client.LoginRequest{Email: rootEmail, Password: "wrong"}); !client.IsUnauthorized(err) {
		t.Fatalf("bad password: %v", err)
	}
	pair := must(pub.Auth.Login(ctx, client.LoginRequest{Email: rootEmail, Password: rootPassword}))
	if pair.AccessToken == "" || pair.RefreshToken == "" || pair.Expiry.IsZero() {
		t.Fatalf("login: %+v", pair)
	}

	var refreshes atomic.Int32
	ts := client.NewTokenSource(pub.Auth, pair, client.OnRefresh(func(client.TokenPair) { refreshes.Add(1) }))
	root := pub.With(client.WithTokenSource(ts))
	me := must(root.Me(ctx))
	if me.Authenticator != "core/token" || refreshes.Load() != 0 {
		t.Fatalf("me: %+v (refreshes %d)", me, refreshes.Load())
	}

	// The 2s token is refreshed before it expires (skew = half its lifetime).
	time.Sleep(time.Until(pair.Expiry.Add(-time.Duration(pair.ExpiresIn) * time.Second / 2)))
	must(root.Me(ctx))
	if refreshes.Load() != 1 || ts.Pair().RefreshToken == pair.RefreshToken {
		t.Fatalf("expected one proactive refresh, got %d", refreshes.Load())
	}

	// A rejected access token triggers exactly one refresh and a retry.
	bad := ts.Pair()
	bad.AccessToken = "garbage"
	bad.Expiry = time.Now().Add(time.Hour)
	var reauths atomic.Int32
	ts2 := client.NewTokenSource(pub.Auth, bad, client.OnRefresh(func(client.TokenPair) { reauths.Add(1) }))
	if me := must(pub.With(client.WithTokenSource(ts2)).Me(ctx)); me.Authenticator != "core/token" || reauths.Load() != 1 {
		t.Fatalf("reauth: %+v (refreshes %d)", me, reauths.Load())
	}
	// The source's old refresh token was rotated by ts2: reusing it fails
	// (and the server revokes that session).
	if _, err := pub.Auth.Refresh(ctx, bad.RefreshToken); err == nil {
		t.Fatal("rotated refresh token accepted")
	}
	// No refresh token: a 401 is returned as is.
	if _, err := pub.With(client.WithToken("garbage")).Me(ctx); !client.IsUnauthorized(err) {
		t.Fatalf("static bad token: %v", err)
	}

	// Fresh admin session for user management.
	pair = must(pub.Auth.Login(ctx, client.LoginRequest{Email: rootEmail, Password: rootPassword}))
	admin := pub.With(client.WithTokenSource(client.NewTokenSource(pub.Auth, pair)))

	must(admin.Tenants.Create(ctx, client.CreateTenantRequest{Slug: "acme", Name: "Acme"}))
	must(admin.Members.Add(ctx, "acme", client.AddMemberRequest{Email: "ada@example.com", Role: "viewer"}))
	invite := testMailbox.token(t, "ada@example.com", "invitation")
	if r := must(pub.Auth.AcceptInvitation(ctx, client.AcceptInvitationRequest{Token: invite, Password: "ada's long passphrase", Name: "Ada"})); r.Status != "active" {
		t.Fatalf("accept: %+v", r)
	}
	_, err := pub.Auth.Login(ctx, client.LoginRequest{Email: "ada@example.com", Password: "ada's long passphrase"})
	if e, _ := client.AsError(err); e == nil || e.Code != "tenant_required" {
		t.Fatalf("platform login of tenant user: %v", err)
	}
	adaPair := must(pub.Auth.Login(ctx, client.LoginRequest{Email: "ada@example.com", Password: "ada's long passphrase", Tenant: "acme"}))
	ada := pub.With(client.WithToken(adaPair.AccessToken))
	if adaPair.TenantID == "" {
		t.Fatalf("tenant login: %+v", adaPair)
	}
	must(ada.Tenants.Get(ctx, "acme"))
	if _, err := ada.Tenants.Delete(ctx, "acme"); !client.IsForbidden(err) {
		t.Fatalf("viewer delete: %v", err)
	}
	if ms := must(ada.MyMemberships(ctx)); len(ms) != 1 {
		t.Fatalf("my memberships: %+v", ms)
	}
	if err := ada.ChangeMyPassword(ctx, "ada's long passphrase", "ada's newer passphrase"); err != nil {
		t.Fatal(err)
	}

	// Logout revokes the refresh token.
	if err := pub.Auth.Logout(ctx, adaPair.RefreshToken); err != nil {
		t.Fatal(err)
	}
	if _, err := pub.Auth.Refresh(ctx, adaPair.RefreshToken); err == nil {
		t.Fatal("refresh after logout")
	}

	// Password reset.
	if err := pub.Auth.RequestPasswordReset(ctx, "nobody@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := pub.Auth.RequestPasswordReset(ctx, "ada@example.com"); err != nil {
		t.Fatal(err)
	}
	reset := testMailbox.token(t, "ada@example.com", "password_reset")
	if err := pub.Auth.ConfirmPasswordReset(ctx, reset, "ada's reset passphrase"); err != nil {
		t.Fatal(err)
	}
	must(pub.Auth.Login(ctx, client.LoginRequest{Email: "ada@example.com", Password: "ada's reset passphrase", Tenant: "acme"}))

	// User administration.
	u := must(admin.Users.Create(ctx, client.CreateUserRequest{Email: "bob@example.com", Name: "Bob", Password: "bob's long passphrase"}))
	if u.Status != sdk.UserActive {
		t.Fatalf("create user: %+v", u)
	}
	if _, err := admin.Users.Create(ctx, client.CreateUserRequest{Email: "bob@example.com"}); !client.IsConflict(err) {
		t.Fatalf("duplicate user: %v", err)
	}
	u2 := must(admin.Users.Update(ctx, u.ID, client.UpdateUserRequest{Name: client.Ptr("Robert")}, client.IfMatch(u.Version)))
	if u2.Name != "Robert" {
		t.Fatalf("update user: %+v", u2)
	}
	if _, err := admin.Users.Update(ctx, u.ID, client.UpdateUserRequest{Name: client.Ptr("x")}, client.IfMatch(u.Version)); !client.IsVersionConflict(err) {
		t.Fatalf("stale user update: %v", err)
	}
	if d := must(admin.Users.Disable(ctx, "bob@example.com")); d.Status != sdk.UserDisabled {
		t.Fatalf("disable: %+v", d)
	}
	if e := must(admin.Users.Enable(ctx, u.ID)); e.Status != sdk.UserActive {
		t.Fatalf("enable: %+v", e)
	}
	if err := admin.Users.SetPassword(ctx, u.ID, "bob's newer passphrase"); err != nil {
		t.Fatal(err)
	}
	if err := admin.Users.RevokeSessions(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	users := must(client.Collect(admin.Users.All(ctx, client.UserListOptions{Limit: 1})))
	if len(users) != 3 {
		t.Fatalf("users: %d", len(users))
	}
	if p := must(admin.Users.List(ctx, client.UserListOptions{Query: "bob"})); len(p.Items) != 1 {
		t.Fatalf("user search: %+v", p.Items)
	}
	if err := admin.Users.Delete(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Users.Get(ctx, u.ID); !client.IsNotFound(err) {
		t.Fatalf("deleted user: %v", err)
	}
}

func TestEventsDeadLettersPlugins(t *testing.T) {
	flakyFail.Store(true)
	defer flakyFail.Store(false)
	cfg := baseConfig()
	cfg.Plugins = append(cfg.Plugins, server.PluginSpec{Plugin: "clienttest-flaky"})
	c := newClient(t, startServer(t, cfg), client.WithAPIKey(apiKey))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Tail in the background from the start of the log.
	tailCtx, stopTail := context.WithCancel(ctx)
	var (
		mu     sync.Mutex
		tailed []string
	)
	tailDone := make(chan error, 1)
	go func() {
		tailDone <- c.Events.Tail(tailCtx, 0, func(e sdk.Event) error {
			mu.Lock()
			defer mu.Unlock()
			tailed = append(tailed, e.Type+":"+e.Subject)
			return nil
		}, client.TailType("tenant.created"), client.TailInterval(20*time.Millisecond))
	}()

	acme := must(c.Tenants.Create(ctx, client.CreateTenantRequest{Slug: "acme", Name: "Acme"}))
	must(c.Tenants.Suspend(ctx, "acme", ""))
	must(c.Tenants.Create(ctx, client.CreateTenantRequest{Slug: "globex", Name: "Globex"}))

	waitFor(t, "tailed events", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(tailed) == 2
	})
	stopTail()
	if err := <-tailDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("tail: %v", err)
	}

	evs := must(client.Collect(c.Events.All(ctx, client.EventListOptions{Limit: 1, TenantID: acme.ID})))
	if len(evs) < 2 || evs[0].Type != sdk.EventTenantCreated {
		t.Fatalf("events: %+v", evs)
	}
	p := must(c.Events.List(ctx, client.EventListOptions{Type: "tenant.suspended"}))
	if len(p.Items) != 1 || p.Items[0].TenantID != acme.ID {
		t.Fatalf("filtered events: %+v", p.Items)
	}
	if last := must(c.Events.LastSeq(ctx)); last < evs[len(evs)-1].Seq {
		t.Fatalf("last seq %d", last)
	}

	// Dead letters from the failing subscriber.
	const sub = "clienttest-flaky/sink"
	var dls client.DeadLetterList
	waitFor(t, "dead letters", func() bool {
		dls = must(c.DeadLetters.List(ctx, sub))
		return len(dls.Items) == 2
	})
	if !contains(dls.Subscriptions, sub) {
		t.Fatalf("subscriptions: %v", dls.Subscriptions)
	}
	dl := must(c.DeadLetters.Get(ctx, dls.Items[0].ID))
	if dl.Event.Type != sdk.EventTenantCreated || dl.Error == "" || dl.Attempts != 1 {
		t.Fatalf("dead letter: %+v", dl)
	}
	err := c.DeadLetters.Replay(ctx, dl.ID)
	if e, ok := client.AsError(err); !ok || e.Status != http.StatusBadGateway || e.Code != "replay_failed" {
		t.Fatalf("failing replay: %v", err)
	}
	flakyFail.Store(false)
	if err := c.DeadLetters.Replay(ctx, dl.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DeadLetters.Get(ctx, dl.ID); !client.IsNotFound(err) {
		t.Fatalf("replayed dead letter: %v", err)
	}
	if err := c.DeadLetters.Discard(ctx, dls.Items[1].ID); err != nil {
		t.Fatal(err)
	}
	if l := must(c.DeadLetters.List(ctx, "")); len(l.Items) != 0 {
		t.Fatalf("dead letters left: %+v", l.Items)
	}

	pl := must(c.Plugins.List(ctx))
	names := []string{}
	for _, it := range pl.Items {
		names = append(names, it.Name)
	}
	if !contains(names, "clienttest-flaky") || !contains(pl.Available, "clienttest-mailbox") {
		t.Fatalf("plugins: %v available %v", names, pl.Available)
	}
}

// faultyProxy forwards to the real server but answers the first fail
// requests matching match with status (after forwarding them when forward
// is set, simulating a response lost on the way back).
type faultyProxy struct {
	proxy      *httputil.ReverseProxy
	mu         sync.Mutex
	fail       int
	status     int
	retryAfter string
	forward    bool
	match      func(*http.Request) bool
	seen       []string // Idempotency-Key per matching request
}

func (p *faultyProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	hit := p.match != nil && p.match(r)
	failNow := hit && p.fail > 0
	if hit {
		p.seen = append(p.seen, r.Header.Get("Idempotency-Key"))
	}
	if failNow {
		p.fail--
	}
	p.mu.Unlock()
	if !failNow {
		p.proxy.ServeHTTP(w, r)
		return
	}
	if p.forward {
		p.proxy.ServeHTTP(httptest.NewRecorder(), r)
	}
	if p.retryAfter != "" {
		w.Header().Set("Retry-After", p.retryAfter)
	}
	w.WriteHeader(p.status)
}

func (p *faultyProxy) arm(fail, status int, forward bool, match func(*http.Request) bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fail, p.status, p.forward, p.match, p.seen, p.retryAfter = fail, status, forward, match, nil, ""
}

func (p *faultyProxy) keys() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.seen...)
}

func TestRetry(t *testing.T) {
	ctx := context.Background()
	target, _ := url.Parse(startServer(t, baseConfig()))
	fp := &faultyProxy{proxy: httputil.NewSingleHostReverseProxy(target)}
	front := httptest.NewServer(fp)
	t.Cleanup(front.Close)

	c := newClient(t, front.URL, client.WithAPIKey(apiKey), client.WithRetry(3, 5*time.Millisecond))
	noRetry := newClient(t, front.URL, client.WithAPIKey(apiKey))
	isPost := func(path string) func(*http.Request) bool {
		return func(r *http.Request) bool { return r.Method == http.MethodPost && r.URL.Path == path }
	}

	// A create whose first response is lost is retried with the same
	// automatic Idempotency-Key, so the server replays the 201 instead of 409.
	fp.arm(1, http.StatusServiceUnavailable, true, isPost("/v1/tenants"))
	tn := must(c.Tenants.Create(ctx, client.CreateTenantRequest{Slug: "acme", Name: "Acme"}))
	keys := fp.keys()
	if tn.Slug != "acme" || len(keys) != 2 || keys[0] == "" || keys[0] != keys[1] {
		t.Fatalf("create retry: %+v keys %v", tn, keys)
	}

	// GETs are retried on 502/503/504.
	fp.arm(2, http.StatusBadGateway, false, func(r *http.Request) bool { return r.Method == http.MethodGet })
	must(c.Tenants.Get(ctx, "acme"))
	if n := len(fp.keys()); n != 3 {
		t.Fatalf("get attempts: %d", n)
	}

	// Retries are bounded.
	fp.arm(10, http.StatusServiceUnavailable, false, func(r *http.Request) bool { return r.Method == http.MethodGet })
	_, err := c.Tenants.Get(ctx, "acme")
	if e, ok := client.AsError(err); !ok || e.Status != 503 || len(fp.keys()) != 4 {
		t.Fatalf("exhausted retries: %v attempts %d", err, len(fp.keys()))
	}

	// POSTs without an Idempotency-Key are not retried.
	fp.arm(1, http.StatusServiceUnavailable, false, isPost("/v1/tenants/acme/suspend"))
	if _, err := c.Tenants.Suspend(ctx, "acme", ""); err == nil || len(fp.keys()) != 1 {
		t.Fatalf("suspend retried: %v attempts %d", err, len(fp.keys()))
	}

	// Without WithRetry nothing is retried.
	fp.arm(1, http.StatusServiceUnavailable, false, func(r *http.Request) bool { return r.Method == http.MethodGet })
	if _, err := noRetry.Tenants.Get(ctx, "acme"); err == nil {
		t.Fatal("expected 503 without retries")
	}

	// 429 is retried only with Retry-After, which is honored.
	fp.arm(1, http.StatusTooManyRequests, false, func(r *http.Request) bool { return r.Method == http.MethodGet })
	fp.retryAfter = "1"
	start := time.Now()
	must(c.Tenants.Get(ctx, "acme"))
	if time.Since(start) < 900*time.Millisecond {
		t.Fatalf("Retry-After not honored: %v", time.Since(start))
	}

	// An explicit Idempotency-Key makes any POST retryable.
	fp.arm(1, http.StatusServiceUnavailable, true, isPost("/v1/tenants/acme/usage/api_calls"))
	it := must(c.Usage.Record(ctx, "acme", "api_calls", 5, client.WithIdempotencyKey("record-1")))
	if it.Value != 5 {
		t.Fatalf("usage recorded twice: %+v", it)
	}

	// Context cancellation stops retrying.
	fp.arm(100, http.StatusServiceUnavailable, false, func(r *http.Request) bool { return r.Method == http.MethodGet })
	slow := newClient(t, front.URL, client.WithAPIKey(apiKey), client.WithRetry(100, time.Second))
	cctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	if _, err := slow.Tenants.Get(cctx, "acme"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled retry: %v", err)
	}
}

func TestNewValidatesURL(t *testing.T) {
	for _, u := range []string{"", "localhost:8080", "ftp://x", "http://"} {
		if _, err := client.New(u); err == nil {
			t.Errorf("New(%q) accepted", u)
		}
	}
	c := newClient(t, "http://localhost:8080/")
	if c.BaseURL() != "http://localhost:8080" {
		t.Fatalf("base: %s", c.BaseURL())
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
