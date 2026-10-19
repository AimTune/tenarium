package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
)

// --- fake Keycloak ---

type fakeRealm struct {
	enabled     bool
	displayName string
	clients     []map[string]any
	users       map[string]map[string]any // by id
	passwords   map[string]string         // by user id
	profile     map[string]any            // user profile config
}

type fakeKeycloak struct {
	t *testing.T
	*httptest.Server

	mu            sync.Mutex
	realms        map[string]*fakeRealm
	tokens        map[string]bool
	tokenRequests int
	nextID        int
	actionEmails  []actionEmail
}

func newFakeKeycloak(t *testing.T) *fakeKeycloak {
	f := &fakeKeycloak{t: t, realms: map[string]*fakeRealm{}, tokens: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /realms/{realm}/protocol/openid-connect/token", f.token)
	admin := http.NewServeMux()
	admin.HandleFunc("POST /admin/realms", f.createRealm)
	admin.HandleFunc("PUT /admin/realms/{realm}", f.updateRealm)
	admin.HandleFunc("DELETE /admin/realms/{realm}", f.deleteRealm)
	admin.HandleFunc("GET /admin/realms/{realm}/clients", f.listClients)
	admin.HandleFunc("POST /admin/realms/{realm}/clients", f.createClient)
	admin.HandleFunc("GET /admin/realms/{realm}/users", f.searchUsers)
	admin.HandleFunc("POST /admin/realms/{realm}/users", f.createUser)
	admin.HandleFunc("PUT /admin/realms/{realm}/users/{id}", f.updateUser)
	admin.HandleFunc("DELETE /admin/realms/{realm}/users/{id}", f.deleteUser)
	admin.HandleFunc("PUT /admin/realms/{realm}/users/{id}/reset-password", f.resetPassword)
	admin.HandleFunc("PUT /admin/realms/{realm}/users/{id}/execute-actions-email", f.executeActionsEmail)
	admin.HandleFunc("GET /admin/realms/{realm}/users/profile", f.getProfile)
	admin.HandleFunc("PUT /admin/realms/{realm}/users/profile", f.putProfile)
	mux.Handle("/admin/", f.auth(admin))
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

// expireTokens invalidates every issued token, as after a Keycloak restart.
func (f *fakeKeycloak) expireTokens() {
	f.mu.Lock()
	defer f.mu.Unlock()
	clear(f.tokens)
}

func (f *fakeKeycloak) tokenCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokenRequests
}

func (f *fakeKeycloak) realm(name string) *fakeRealm {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.realms[name]
}

func (f *fakeKeycloak) token(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokenRequests++
	if r.PathValue("realm") != "master" {
		f.userToken(w, r)
		return
	}
	ok := r.FormValue("client_id") == "admin-cli" &&
		r.FormValue("grant_type") == "password" &&
		r.FormValue("username") == "admin" && r.FormValue("password") == "secret"
	if !ok {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusUnauthorized)
		return
	}
	tok := fmt.Sprintf("tok-%d", f.tokenRequests)
	f.tokens[tok] = true
	writeJSON(w, http.StatusOK, map[string]any{"access_token": tok, "expires_in": 300, "token_type": "Bearer"})
}

func (f *fakeKeycloak) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		f.mu.Lock()
		ok := f.tokens[tok]
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

// The handlers below run with f.mu held.

func decode(r *http.Request) map[string]any {
	var m map[string]any
	_ = json.NewDecoder(r.Body).Decode(&m)
	return m
}

func (f *fakeKeycloak) lookup(w http.ResponseWriter, r *http.Request) *fakeRealm {
	rl := f.realms[r.PathValue("realm")]
	if rl == nil {
		http.Error(w, `{"error":"Realm not found."}`, http.StatusNotFound)
	}
	return rl
}

func (f *fakeKeycloak) createRealm(w http.ResponseWriter, r *http.Request) {
	in := decode(r)
	name, _ := in["realm"].(string)
	if _, dup := f.realms[name]; dup {
		http.Error(w, `{"errorMessage":"Conflict detected."}`, http.StatusConflict)
		return
	}
	enabled, _ := in["enabled"].(bool)
	display, _ := in["displayName"].(string)
	f.realms[name] = &fakeRealm{enabled: enabled, displayName: display, users: map[string]map[string]any{},
		passwords: map[string]string{}, profile: map[string]any{"attributes": []any{}}}
	w.WriteHeader(http.StatusCreated)
}

func (f *fakeKeycloak) updateRealm(w http.ResponseWriter, r *http.Request) {
	rl := f.lookup(w, r)
	if rl == nil {
		return
	}
	in := decode(r)
	if v, ok := in["enabled"].(bool); ok {
		rl.enabled = v
	}
	if v, ok := in["displayName"].(string); ok {
		rl.displayName = v
	}
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeKeycloak) deleteRealm(w http.ResponseWriter, r *http.Request) {
	if f.lookup(w, r) == nil {
		return
	}
	delete(f.realms, r.PathValue("realm"))
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeKeycloak) listClients(w http.ResponseWriter, r *http.Request) {
	rl := f.lookup(w, r)
	if rl == nil {
		return
	}
	out := []map[string]any{}
	for _, c := range rl.clients {
		if c["clientId"] == r.URL.Query().Get("clientId") {
			out = append(out, c)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (f *fakeKeycloak) createClient(w http.ResponseWriter, r *http.Request) {
	rl := f.lookup(w, r)
	if rl == nil {
		return
	}
	in := decode(r)
	for _, c := range rl.clients {
		if c["clientId"] == in["clientId"] {
			w.WriteHeader(http.StatusConflict)
			return
		}
	}
	rl.clients = append(rl.clients, in)
	w.WriteHeader(http.StatusCreated)
}

func (f *fakeKeycloak) searchUsers(w http.ResponseWriter, r *http.Request) {
	rl := f.lookup(w, r)
	if rl == nil {
		return
	}
	q := r.URL.Query()
	out := []map[string]any{}
	for _, u := range rl.users {
		if q.Has("email") && sameEmail(u["email"], q.Get("email")) ||
			q.Has("username") && u["username"] == strings.ToLower(q.Get("username")) {
			out = append(out, u)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func sameEmail(v any, email string) bool {
	s, _ := v.(string)
	return s != "" && strings.EqualFold(s, email)
}

func (f *fakeKeycloak) createUser(w http.ResponseWriter, r *http.Request) {
	rl := f.lookup(w, r)
	if rl == nil {
		return
	}
	in := decode(r)
	in["username"] = strings.ToLower(in["username"].(string))
	email, _ := in["email"].(string)
	for _, u := range rl.users {
		if u["username"] == in["username"] || sameEmail(u["email"], email) {
			http.Error(w, `{"errorMessage":"User exists with same username"}`, http.StatusConflict)
			return
		}
	}
	f.nextID++
	id := fmt.Sprintf("user-%d", f.nextID)
	in["id"] = id
	rl.users[id] = in
	w.Header().Set("Location", "http://"+r.Host+r.URL.Path+"/"+id)
	w.WriteHeader(http.StatusCreated)
}

func (f *fakeKeycloak) resetPassword(w http.ResponseWriter, r *http.Request) {
	rl := f.lookup(w, r)
	if rl == nil {
		return
	}
	id := r.PathValue("id")
	if rl.users[id] == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	in := decode(r)
	pw, _ := in["value"].(string)
	if in["type"] != "password" || in["temporary"] != false {
		http.Error(w, `{"error":"bad credential"}`, http.StatusBadRequest)
		return
	}
	if len(pw) < 8 { // fake password policy: length(8)
		http.Error(w, `{"error":"invalidPasswordMinLengthMessage","error_description":"Invalid password: minimum length 8."}`,
			http.StatusBadRequest)
		return
	}
	rl.passwords[id] = pw
	w.WriteHeader(http.StatusNoContent)
}

type actionEmail struct {
	realm, id string
	query     url.Values
	actions   []string
}

func (f *fakeKeycloak) executeActionsEmail(w http.ResponseWriter, r *http.Request) {
	rl := f.lookup(w, r)
	if rl == nil {
		return
	}
	id := r.PathValue("id")
	if rl.users[id] == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	var actions []string
	if err := json.NewDecoder(r.Body).Decode(&actions); err != nil {
		http.Error(w, `{"error":"bad body"}`, http.StatusBadRequest)
		return
	}
	f.actionEmails = append(f.actionEmails, actionEmail{r.PathValue("realm"), id, r.URL.Query(), actions})
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeKeycloak) getProfile(w http.ResponseWriter, r *http.Request) {
	if rl := f.lookup(w, r); rl != nil {
		writeJSON(w, http.StatusOK, rl.profile)
	}
}

func (f *fakeKeycloak) putProfile(w http.ResponseWriter, r *http.Request) {
	if rl := f.lookup(w, r); rl != nil {
		rl.profile = decode(r)
		writeJSON(w, http.StatusOK, rl.profile)
	}
}

// Fake users realm client for the password grant.
const fakeClientID, fakeClientSecret = "tenarium", "client-secret"

// userToken serves the password grant of a non-master realm. It runs with
// f.mu held.
func (f *fakeKeycloak) userToken(w http.ResponseWriter, r *http.Request) {
	rl := f.realms[r.PathValue("realm")]
	switch {
	case rl == nil:
		http.Error(w, `{"error":"Realm does not exist"}`, http.StatusNotFound)
		return
	case r.FormValue("client_id") != fakeClientID || r.FormValue("client_secret") != fakeClientSecret:
		http.Error(w, `{"error":"unauthorized_client","error_description":"Invalid client credentials"}`, http.StatusUnauthorized)
		return
	case r.FormValue("grant_type") != "password" || r.FormValue("scope") != "openid":
		http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
		return
	}
	for id, u := range rl.users {
		if u["username"] != r.FormValue("username") {
			continue
		}
		if pw, ok := rl.passwords[id]; !ok || pw != r.FormValue("password") {
			break
		}
		if u["enabled"] != true {
			http.Error(w, `{"error":"invalid_grant","error_description":"Account disabled"}`, http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"access_token": "user-" + id, "expires_in": 300})
		return
	}
	http.Error(w, `{"error":"invalid_grant","error_description":"Invalid user credentials"}`, http.StatusUnauthorized)
}

func (f *fakeKeycloak) updateUser(w http.ResponseWriter, r *http.Request) {
	rl := f.lookup(w, r)
	if rl == nil {
		return
	}
	id := r.PathValue("id")
	if rl.users[id] == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	in := decode(r)
	in["id"] = id
	rl.users[id] = in
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeKeycloak) deleteUser(w http.ResponseWriter, r *http.Request) {
	rl := f.lookup(w, r)
	if rl == nil {
		return
	}
	if rl.users[r.PathValue("id")] == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	delete(rl.users, r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}

// --- fake sdk.Registrar and sdk.Host ---

type fakeHost struct {
	tenants []sdk.Tenant
}

func (h *fakeHost) GetTenant(_ context.Context, idOrSlug string) (sdk.Tenant, error) {
	for _, t := range h.tenants {
		if t.ID == idOrSlug || t.Slug == idOrSlug {
			return t, nil
		}
	}
	return sdk.Tenant{}, sdk.ErrNotFound
}

func (h *fakeHost) ListTenants(context.Context, string, int) ([]sdk.Tenant, error) {
	return h.tenants, nil
}

func (h *fakeHost) GetPlan(context.Context, string) (sdk.Plan, error) {
	return sdk.Plan{}, sdk.ErrNotFound
}

func (h *fakeHost) Entitlements(context.Context, string) (sdk.Entitlements, error) {
	return sdk.Entitlements{}, nil
}

type fakeRegistrar struct {
	cfg          map[string]any
	host         *fakeHost
	provisioners []sdk.Provisioner
	directories  []sdk.UserDirectory
	subs         map[string]sdk.EventHandler
	filters      map[string]sdk.EventFilter
	mux          *http.ServeMux
}

func newRegistrar(cfg map[string]any, host *fakeHost) *fakeRegistrar {
	return &fakeRegistrar{cfg: cfg, host: host, subs: map[string]sdk.EventHandler{},
		filters: map[string]sdk.EventFilter{}, mux: http.NewServeMux()}
}

func (r *fakeRegistrar) Config(v any) error {
	b, err := json.Marshal(r.cfg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
func (r *fakeRegistrar) Logger() *slog.Logger { return slog.New(slog.DiscardHandler) }
func (r *fakeRegistrar) Host() sdk.Host       { return r.host }
func (r *fakeRegistrar) InstanceName() string { return "keycloak" }
func (r *fakeRegistrar) Subscribe(name string, f sdk.EventFilter, h sdk.EventHandler, _ ...sdk.SubscribeOption) {
	r.subs[name], r.filters[name] = h, f
}
func (r *fakeRegistrar) Hook(sdk.HookPoint, sdk.HookHandler, ...sdk.HookOption) {}
func (r *fakeRegistrar) Provisioner(p sdk.Provisioner)                          { r.provisioners = append(r.provisioners, p) }
func (r *fakeRegistrar) Route(pattern string, h http.Handler)                   { r.mux.Handle(pattern, h) }
func (r *fakeRegistrar) Authenticator(sdk.Authenticator)                        {}
func (r *fakeRegistrar) Authorizer(sdk.Authorizer)                              {}

// --- helpers ---

var acme = sdk.Tenant{ID: "t-1", Slug: "acme", Name: "Acme Inc", Status: sdk.StatusActive}

type env struct {
	kc   *fakeKeycloak
	p    *Plugin
	reg  *fakeRegistrar
	prov sdk.Provisioner
	ctx  context.Context
}

func setup(t *testing.T, extra map[string]any) *env {
	t.Helper()
	kc := newFakeKeycloak(t)
	cfg := map[string]any{"url": kc.URL, "username": "admin", "password": "secret"}
	for k, v := range extra {
		cfg[k] = v
	}
	reg := newRegistrar(cfg, &fakeHost{tenants: []sdk.Tenant{acme}})
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if len(reg.provisioners) != 1 || reg.provisioners[0].Name() != "realm" {
		t.Fatalf("provisioners = %v", reg.provisioners)
	}
	return &env{kc: kc, p: p, reg: reg, prov: reg.provisioners[0], ctx: context.Background()}
}

func event(t *testing.T, typ, tenantID string, data any) sdk.Event {
	t.Helper()
	b, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	return sdk.Event{ID: "evt-" + typ, Type: typ, TenantID: tenantID, Time: time.Now(), Data: b}
}

// --- tests ---

func TestProvisionCreatesRealmAndClient(t *testing.T) {
	e := setup(t, map[string]any{"client": map[string]any{
		"client_id": "app", "redirect_uris": []string{"https://app/*"}, "public": true,
	}})
	for range 2 { // second run must be a no-op
		if err := e.prov.Provision(e.ctx, acme); err != nil {
			t.Fatalf("Provision: %v", err)
		}
	}
	rl := e.kc.realm("tenant-acme")
	if rl == nil || !rl.enabled || rl.displayName != "Acme Inc" {
		t.Fatalf("realm = %+v", rl)
	}
	if len(rl.clients) != 1 || rl.clients[0]["clientId"] != "app" || rl.clients[0]["publicClient"] != true {
		t.Fatalf("clients = %v", rl.clients)
	}
}

func TestProvisionConvergesExistingRealm(t *testing.T) {
	e := setup(t, nil)
	if err := e.prov.Provision(e.ctx, acme); err != nil {
		t.Fatal(err)
	}
	rl := e.kc.realm("tenant-acme")
	e.kc.mu.Lock()
	rl.enabled, rl.displayName = false, "stale"
	e.kc.mu.Unlock()
	if err := e.prov.Provision(e.ctx, acme); err != nil {
		t.Fatal(err)
	}
	if !rl.enabled || rl.displayName != "Acme Inc" {
		t.Fatalf("realm not converged: %+v", rl)
	}
}

func TestDeprovisionDeletes(t *testing.T) {
	e := setup(t, nil)
	if err := e.prov.Provision(e.ctx, acme); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := e.prov.Deprovision(e.ctx, acme); err != nil {
			t.Fatalf("Deprovision: %v", err)
		}
	}
	if e.kc.realm("tenant-acme") != nil {
		t.Fatal("realm still exists")
	}
}

func TestDeprovisionDisableMode(t *testing.T) {
	e := setup(t, map[string]any{"delete_realm_on_deprovision": false})
	if err := e.prov.Provision(e.ctx, acme); err != nil {
		t.Fatal(err)
	}
	if err := e.prov.Deprovision(e.ctx, acme); err != nil {
		t.Fatal(err)
	}
	if rl := e.kc.realm("tenant-acme"); rl == nil || rl.enabled {
		t.Fatalf("realm = %+v, want disabled", rl)
	}
	// Disabling a realm that is gone is fine too.
	other := sdk.Tenant{ID: "t-2", Slug: "gone"}
	if err := e.prov.Deprovision(e.ctx, other); err != nil {
		t.Fatal(err)
	}
}

func TestMemberSync(t *testing.T) {
	e := setup(t, nil)
	if err := e.prov.Provision(e.ctx, acme); err != nil {
		t.Fatal(err)
	}
	h := e.reg.subs["members"]
	if h == nil {
		t.Fatal("members subscription not registered")
	}
	m := sdk.Member{ID: "m-1", TenantID: acme.ID, Email: "Bob@Example.com", Role: "admin"}
	added := event(t, sdk.EventMemberAdded, acme.ID, sdk.MemberEventData{Member: m})
	for range 2 {
		if err := h(e.ctx, added); err != nil {
			t.Fatalf("member_added: %v", err)
		}
	}
	rl := e.kc.realm("tenant-acme")
	if len(rl.users) != 1 {
		t.Fatalf("users = %v", rl.users)
	}
	u := onlyUser(t, rl)
	if u["username"] != "bob@example.com" || u["email"] != "Bob@Example.com" || u["enabled"] != true {
		t.Fatalf("user = %v", u)
	}
	if ra, _ := u["requiredActions"].([]any); len(ra) != 2 {
		t.Fatalf("requiredActions = %v", u["requiredActions"])
	}

	// Role change updates the attribute.
	prev := m
	m.Role = "viewer"
	if err := h(e.ctx, event(t, sdk.EventMemberUpdated, acme.ID, sdk.MemberEventData{Member: m, Previous: &prev})); err != nil {
		t.Fatalf("member_updated: %v", err)
	}
	u = onlyUser(t, rl)
	attrs, _ := u["attributes"].(map[string]any)
	if role, _ := attrs[RoleAttribute].([]any); len(role) != 1 || role[0] != "viewer" {
		t.Fatalf("attributes = %v", u["attributes"])
	}

	removed := event(t, sdk.EventMemberRemoved, acme.ID, sdk.MemberEventData{Member: m})
	for range 2 {
		if err := h(e.ctx, removed); err != nil {
			t.Fatalf("member_removed: %v", err)
		}
	}
	if len(rl.users) != 0 {
		t.Fatalf("users = %v", rl.users)
	}
}

func TestMemberSyncSkipsMissingRealmAndTenant(t *testing.T) {
	e := setup(t, nil)
	h := e.reg.subs["members"]
	m := sdk.Member{TenantID: acme.ID, Email: "a@b.c", Role: "admin"}
	if err := h(e.ctx, event(t, sdk.EventMemberAdded, acme.ID, sdk.MemberEventData{Member: m})); err != nil {
		t.Fatalf("missing realm should be ignored: %v", err)
	}
	m.TenantID = "unknown"
	if err := h(e.ctx, event(t, sdk.EventMemberAdded, "unknown", sdk.MemberEventData{Member: m})); err != nil {
		t.Fatalf("unknown tenant should be ignored: %v", err)
	}
	// While the tenant is still provisioning, a missing realm is retried.
	e.reg.host.tenants[0].Status = sdk.StatusProvisioning
	t.Cleanup(func() { e.reg.host.tenants[0].Status = sdk.StatusActive })
	m.TenantID = acme.ID
	if err := h(e.ctx, event(t, sdk.EventMemberAdded, acme.ID, sdk.MemberEventData{Member: m})); err == nil {
		t.Fatal("want retryable error while provisioning")
	}
}

func TestSyncDisabled(t *testing.T) {
	e := setup(t, map[string]any{"sync_members": false, "sync_status": false})
	if len(e.reg.subs) != 0 {
		t.Fatalf("subs = %v", e.reg.subs)
	}
}

func TestSuspendResume(t *testing.T) {
	e := setup(t, nil)
	if err := e.prov.Provision(e.ctx, acme); err != nil {
		t.Fatal(err)
	}
	h := e.reg.subs["status"]
	rl := e.kc.realm("tenant-acme")
	if err := h(e.ctx, event(t, sdk.EventTenantSuspended, acme.ID, sdk.TenantEventData{Tenant: acme})); err != nil {
		t.Fatal(err)
	}
	if rl.enabled {
		t.Fatal("realm still enabled after suspend")
	}
	if err := h(e.ctx, event(t, sdk.EventTenantResumed, acme.ID, sdk.TenantEventData{Tenant: acme})); err != nil {
		t.Fatal(err)
	}
	if !rl.enabled {
		t.Fatal("realm disabled after resume")
	}
	ghost := sdk.Tenant{ID: "t-9", Slug: "ghost"}
	if err := h(e.ctx, event(t, sdk.EventTenantSuspended, ghost.ID, sdk.TenantEventData{Tenant: ghost})); err != nil {
		t.Fatalf("missing realm should be ignored: %v", err)
	}
}

func TestTokenCachingAndRefresh(t *testing.T) {
	e := setup(t, nil)
	for _, tn := range []string{"a", "b", "c"} {
		if err := e.prov.Provision(e.ctx, sdk.Tenant{ID: tn, Slug: tn, Name: tn}); err != nil {
			t.Fatal(err)
		}
	}
	if n := e.kc.tokenCount(); n != 1 {
		t.Fatalf("token requests = %d, want 1 (cached)", n)
	}
	e.kc.expireTokens()
	if err := e.prov.Deprovision(e.ctx, sdk.Tenant{ID: "a", Slug: "a"}); err != nil {
		t.Fatalf("Deprovision after expiry: %v", err)
	}
	if n := e.kc.tokenCount(); n != 2 {
		t.Fatalf("token requests = %d, want 2 (one refresh)", n)
	}
	// Local expiry also triggers a refresh.
	e.p.now = func() time.Time { return time.Now().Add(time.Hour) }
	if err := e.prov.Deprovision(e.ctx, sdk.Tenant{ID: "b", Slug: "b"}); err != nil {
		t.Fatal(err)
	}
	if n := e.kc.tokenCount(); n != 3 {
		t.Fatalf("token requests = %d, want 3", n)
	}
}

func TestHealth(t *testing.T) {
	e := setup(t, nil)
	if err := e.p.Health(e.ctx); err != nil {
		t.Fatalf("Health: %v", err)
	}
	e.p.cfg.Password = "wrong"
	if err := e.p.Health(e.ctx); err == nil {
		t.Fatal("Health with bad credentials should fail")
	}
}

func TestInitValidation(t *testing.T) {
	cases := map[string]map[string]any{
		"bad url":           {"url": "keycloak:8080", "username": "a", "password": "b"},
		"no credentials":    {"url": "http://kc"},
		"template syntax":   {"url": "http://kc", "username": "a", "password": "b", "realm_template": "{{.Slug"},
		"template field":    {"url": "http://kc", "username": "a", "password": "b", "realm_template": "{{.Nope}}"},
		"display field":     {"url": "http://kc", "username": "a", "password": "b", "display_name_template": "{{.Missing}}"},
		"empty realm name":  {"url": "http://kc", "username": "a", "password": "b", "realm_template": "{{.ParentID}}"},
		"bad timeout":       {"url": "http://kc", "username": "a", "password": "b", "timeout": "soon"},
		"client without id": {"url": "http://kc", "username": "a", "password": "b", "client": map[string]any{}},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if err := (&Plugin{}).Init(context.Background(), newRegistrar(cfg, &fakeHost{})); err == nil {
				t.Fatal("want error")
			}
		})
	}
	ok := map[string]any{"url": "http://kc", "client_id": "svc", "client_secret": "s",
		"realm_template": "{{.Labels.region}}-{{.Slug}}"}
	if err := (&Plugin{}).Init(context.Background(), newRegistrar(ok, &fakeHost{})); err != nil {
		t.Fatalf("valid config: %v", err)
	}
}

func TestRealmRoute(t *testing.T) {
	e := setup(t, nil)
	for _, key := range []string{"acme", "t-1"} {
		rec := httptest.NewRecorder()
		e.reg.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/realms/"+key, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body)
		}
		var out map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if out["realm"] != "tenant-acme" || out["issuer"] != e.kc.URL+"/realms/tenant-acme" {
			t.Fatalf("body = %v", out)
		}
	}
	rec := httptest.NewRecorder()
	e.reg.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/realms/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
	// A principal scoped to another tenant cannot look up acme.
	req := httptest.NewRequest(http.MethodGet, "/realms/acme", nil)
	req = req.WithContext(sdk.WithPrincipal(req.Context(), &sdk.Principal{Subject: "x", TenantID: "t-2"}))
	rec = httptest.NewRecorder()
	e.reg.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("scoped status = %d", rec.Code)
	}
}

func TestConfigSchema(t *testing.T) {
	sch, err := schema.Compile((&Plugin{}).Manifest().ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	good := map[string]any{"url": "http://kc:8080", "username": "a", "password": "b",
		"client": map[string]any{"client_id": "app", "public": true}, "sync_members": false}
	if err := sch.Validate(good); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if err := sch.Validate(map[string]any{"url": "http://kc", "realm": "x"}); err == nil {
		t.Fatal("unknown field accepted")
	}
}

// TestRealKeycloak runs the provisioning flow against a real server when
// TENARIUM_TEST_KEYCLOAK_URL is set, e.g.:
//
//	docker run -p 8180:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak start-dev
//	TENARIUM_TEST_KEYCLOAK_URL=http://localhost:8180 go test ./plugins/keycloak/ -run RealKeycloak
//
// Credentials default to admin/admin and can be overridden with
// TENARIUM_TEST_KEYCLOAK_USER and TENARIUM_TEST_KEYCLOAK_PASSWORD.
func TestRealKeycloak(t *testing.T) {
	base := os.Getenv("TENARIUM_TEST_KEYCLOAK_URL")
	if base == "" {
		t.Skip("TENARIUM_TEST_KEYCLOAK_URL not set")
	}
	user, pass := os.Getenv("TENARIUM_TEST_KEYCLOAK_USER"), os.Getenv("TENARIUM_TEST_KEYCLOAK_PASSWORD")
	if user == "" {
		user, pass = "admin", "admin"
	}
	tenant := sdk.Tenant{ID: "it-1", Slug: fmt.Sprintf("it%d", time.Now().UnixNano()), Name: "Integration"}
	reg := newRegistrar(map[string]any{
		"url": base, "username": user, "password": pass,
		"client": map[string]any{"client_id": "app", "redirect_uris": []string{"http://localhost/*"}},
	}, &fakeHost{tenants: []sdk.Tenant{tenant}})
	p := &Plugin{}
	ctx := context.Background()
	if err := p.Init(ctx, reg); err != nil {
		t.Fatal(err)
	}
	if err := p.Health(ctx); err != nil {
		t.Fatal(err)
	}
	prov := reg.provisioners[0]
	t.Cleanup(func() { _ = prov.Deprovision(ctx, tenant) })
	for range 2 {
		if err := prov.Provision(ctx, tenant); err != nil {
			t.Fatalf("Provision: %v", err)
		}
	}
	m := sdk.Member{TenantID: tenant.ID, Email: "it@example.com", Role: "admin"}
	if err := reg.subs["members"](ctx, event(t, sdk.EventMemberAdded, tenant.ID, sdk.MemberEventData{Member: m})); err != nil {
		t.Fatalf("member_added: %v", err)
	}
	if err := reg.subs["members"](ctx, event(t, sdk.EventMemberRemoved, tenant.ID, sdk.MemberEventData{Member: m})); err != nil {
		t.Fatalf("member_removed: %v", err)
	}
	resp, err := http.Get(p.Issuer("tenant-"+tenant.Slug) + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status = %d", resp.StatusCode)
	}
	for range 2 {
		if err := prov.Deprovision(ctx, tenant); err != nil {
			t.Fatalf("Deprovision: %v", err)
		}
	}
}

func onlyUser(t *testing.T, rl *fakeRealm) map[string]any {
	t.Helper()
	if len(rl.users) != 1 {
		t.Fatalf("users = %v, want exactly one", rl.users)
	}
	for _, u := range rl.users {
		return u
	}
	return nil
}

func (h *fakeHost) Authorize(context.Context, sdk.Action, sdk.Resource) error { return nil }

func (h *fakeHost) GetUser(context.Context, string) (sdk.User, error) {
	return sdk.User{}, sdk.ErrNotFound
}

func (r *fakeRegistrar) UserDirectory(d sdk.UserDirectory) { r.directories = append(r.directories, d) }
func (r *fakeRegistrar) Mailer(sdk.Mailer)                 {}

func (h *fakeHost) SuspendTenant(context.Context, string, string) (sdk.Tenant, error) {
	return sdk.Tenant{}, sdk.ErrUnsupported
}
func (h *fakeHost) ResumeTenant(context.Context, string) (sdk.Tenant, error) {
	return sdk.Tenant{}, sdk.ErrUnsupported
}
func (h *fakeHost) SetTenantPlan(context.Context, string, string) (sdk.Tenant, error) {
	return sdk.Tenant{}, sdk.ErrUnsupported
}
func (h *fakeHost) RecordUsage(context.Context, string, string, int64) (int64, error) {
	return 0, sdk.ErrUnsupported
}

func (r *fakeRegistrar) PublicRoute(string, http.Handler) {}
