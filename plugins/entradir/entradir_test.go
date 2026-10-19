package entradir

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

const tenantID, clientID, clientSecret = "contoso-tenant", "app-id", "app-secret"

// fakeGraph reproduces the Entra token endpoint and the Graph user,
// invitation and deleted-items endpoints the directory uses, including
// replication lag for new users and throttling.
type fakeGraph struct {
	*httptest.Server
	mu      sync.Mutex
	seq     int
	users   map[string]map[string]any
	deleted map[string]map[string]any
	// lag hides a new user from requests by ID this many times.
	lag      int
	hidden   map[string]int
	throttle int // answer the next n Graph requests with 429
	invites  []map[string]any
}

func newFakeGraph(t *testing.T) *fakeGraph {
	f := &fakeGraph{users: map[string]map[string]any{}, deleted: map[string]map[string]any{}, hidden: map[string]int{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /"+tenantID+"/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("grant_type") != "client_credentials" ||
			r.PostForm.Get("client_id") != clientID || r.PostForm.Get("client_secret") != clientSecret ||
			r.PostForm.Get("scope") != f.URL+"/.default" {
			writeJSON(w, 401, map[string]any{"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret."})
			return
		}
		writeJSON(w, 200, map[string]any{"access_token": "graph-token", "token_type": "Bearer", "expires_in": 3599})
	})
	api := http.NewServeMux()
	api.HandleFunc("GET /v1.0/users", f.list)
	api.HandleFunc("POST /v1.0/users", f.create)
	api.HandleFunc("GET /v1.0/users/{id}", f.get)
	api.HandleFunc("PATCH /v1.0/users/{id}", f.patch)
	api.HandleFunc("DELETE /v1.0/users/{id}", f.del)
	api.HandleFunc("POST /v1.0/invitations", f.invite)
	api.HandleFunc("DELETE /v1.0/directory/deletedItems/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.deleted[r.PathValue("id")] == nil {
			graphErr(w, 404, "Request_ResourceNotFound", "Resource does not exist.")
			return
		}
		delete(f.deleted, r.PathValue("id"))
		w.WriteHeader(204)
	})
	mux.Handle("/v1.0/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer graph-token" {
			graphErr(w, 401, "InvalidAuthenticationToken", "Access token is empty.")
			return
		}
		f.mu.Lock()
		throttled := f.throttle > 0
		if throttled {
			f.throttle--
		}
		f.mu.Unlock()
		if throttled {
			w.Header().Set("Retry-After", "0")
			graphErr(w, 429, "TooManyRequests", "Too many requests")
			return
		}
		api.ServeHTTP(w, r)
	}))
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func graphErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": msg}})
}

var eqClause = regexp.MustCompile(`(\w+) eq '((?:[^']|'')*)'`)

// list supports "$filter=a eq 'x' or b eq 'y'".
func (f *fakeGraph) list(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	clauses := eqClause.FindAllStringSubmatch(r.URL.Query().Get("$filter"), -1)
	out := []map[string]any{}
	for _, u := range f.users {
		for _, c := range clauses {
			if strings.EqualFold(fmt.Sprint(u[c[1]]), strings.ReplaceAll(c[2], "''", "'")) {
				out = append(out, u)
				break
			}
		}
	}
	writeJSON(w, 200, map[string]any{"value": out})
}

func (f *fakeGraph) add(u map[string]any) string {
	f.seq++
	id := fmt.Sprintf("00000000-0000-0000-0000-%012d", f.seq)
	u["id"] = id
	f.users[id] = u
	f.hidden[id] = f.lag
	return id
}

func (f *fakeGraph) create(w http.ResponseWriter, r *http.Request) {
	var in map[string]any
	_ = json.NewDecoder(r.Body).Decode(&in)
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, req := range []string{"accountEnabled", "displayName", "mailNickname", "userPrincipalName", "passwordProfile"} {
		if in[req] == nil {
			graphErr(w, 400, "Request_BadRequest", "Property "+req+" is required.")
			return
		}
	}
	if pp := in["passwordProfile"].(map[string]any); len(fmt.Sprint(pp["password"])) < 8 {
		graphErr(w, 400, "Request_BadRequest", "The specified password does not comply with password complexity requirements.")
		return
	}
	for _, u := range f.users {
		if strings.EqualFold(fmt.Sprint(u["userPrincipalName"]), fmt.Sprint(in["userPrincipalName"])) {
			graphErr(w, 400, "Request_BadRequest", "Another object with the same value for property userPrincipalName already exists.")
			return
		}
	}
	in["userType"] = "Member"
	f.add(in)
	writeJSON(w, 201, in)
}

// visible reports whether id can be read; it counts down replication lag.
func (f *fakeGraph) visible(id string) map[string]any {
	if f.hidden[id] > 0 {
		f.hidden[id]--
		return nil
	}
	return f.users[id]
}

func (f *fakeGraph) get(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.visible(r.PathValue("id"))
	if u == nil {
		graphErr(w, 404, "Request_ResourceNotFound", "Resource '"+r.PathValue("id")+"' does not exist.")
		return
	}
	writeJSON(w, 200, u)
}

func (f *fakeGraph) patch(w http.ResponseWriter, r *http.Request) {
	var in map[string]any
	_ = json.NewDecoder(r.Body).Decode(&in)
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.visible(r.PathValue("id"))
	if u == nil {
		graphErr(w, 404, "Request_ResourceNotFound", "Resource does not exist.")
		return
	}
	if pp, ok := in["passwordProfile"].(map[string]any); ok {
		if u["userType"] == "Guest" {
			graphErr(w, 400, "Request_BadRequest", "Guests have no password.")
			return
		}
		if len(fmt.Sprint(pp["password"])) < 8 {
			graphErr(w, 400, "Request_BadRequest", "The specified password does not comply with password complexity requirements.")
			return
		}
	}
	for k, v := range in {
		if v == nil {
			delete(u, k)
		} else {
			u[k] = v
		}
	}
	w.WriteHeader(204)
}

func (f *fakeGraph) del(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.visible(r.PathValue("id"))
	if u == nil {
		graphErr(w, 404, "Request_ResourceNotFound", "Resource does not exist.")
		return
	}
	delete(f.users, r.PathValue("id"))
	f.deleted[r.PathValue("id")] = u
	w.WriteHeader(204)
}

func (f *fakeGraph) invite(w http.ResponseWriter, r *http.Request) {
	var in map[string]any
	_ = json.NewDecoder(r.Body).Decode(&in)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.invites = append(f.invites, in)
	email := fmt.Sprint(in["invitedUserEmailAddress"])
	var id string
	for uid, u := range f.users {
		if strings.EqualFold(fmt.Sprint(u["mail"]), email) {
			id = uid
		}
	}
	if id == "" {
		id = f.add(map[string]any{
			"mail": email, "displayName": in["invitedUserDisplayName"], "userType": "Guest", "accountEnabled": true,
			"userPrincipalName": strings.Replace(email, "@", "_", 1) + "#EXT#@contoso.onmicrosoft.com",
		})
	}
	writeJSON(w, 201, map[string]any{"id": "inv-1", "status": "PendingAcceptance", "invitedUser": map[string]any{"id": id},
		"inviteRedeemUrl": "https://login.microsoftonline.com/redeem?x"})
}

func (f *fakeGraph) user(id string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.users[id]
}

func setup(t *testing.T, extra map[string]any) (*fakeGraph, sdk.UserDirectory, *Plugin) {
	t.Helper()
	f := newFakeGraph(t)
	cfg := map[string]any{
		"tenant_id": tenantID, "client_id": clientID, "client_secret": clientSecret,
		"authority_url": f.URL, "graph_url": f.URL + "/v1.0",
	}
	for k, v := range extra {
		cfg[k] = v
	}
	reg := sdktest.NewRegistrar(cfg)
	p := &Plugin{retryDelays: []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if reg.Directory == nil {
		t.Fatal("no directory registered")
	}
	return f, reg.Directory, p
}

var ada = sdk.User{ID: "u-1", Email: "Ada@Example.com", Name: "Ada Lovelace",
	Status: sdk.UserInvited, Attributes: map[string]string{"dept": "math"}}

var memberCfg = map[string]any{
	"upn_domain": "contoso.onmicrosoft.com", "user_id_attribute": "employeeId",
	"attribute_map": map[string]any{"dept": "department"},
}

func TestRegistration(t *testing.T) {
	_, dir, p := setup(t, nil)
	if dir.Name() != "entra" {
		t.Fatalf("Name = %q", dir.Name())
	}
	if _, ok := dir.(sdk.PasswordVerifier); ok {
		t.Fatal("Entra cannot verify passwords")
	}
	if err := p.Health(context.Background()); err != nil {
		t.Fatalf("Health: %v", err)
	}
}

func TestMemberLifecycle(t *testing.T) {
	f, dir, _ := setup(t, memberCfg)
	f.lag = 2 // new users are invisible by ID for two requests
	ctx := context.Background()
	u := ada
	id, err := dir.CreateUser(ctx, u)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	got := f.user(id)
	pp := got["passwordProfile"].(map[string]any)
	if got["userPrincipalName"] != "Ada_Example.com@contoso.onmicrosoft.com" || got["mail"] != "Ada@Example.com" ||
		got["mailNickname"] != "Ada" || got["displayName"] != "Ada Lovelace" || got["accountEnabled"] != true ||
		got["employeeId"] != "u-1" || got["department"] != "math" ||
		pp["forceChangePasswordNextSignIn"] != true || len(fmt.Sprint(pp["password"])) < 20 {
		t.Fatalf("user = %v", got)
	}
	if again, err := dir.CreateUser(ctx, u); err != nil || again != id {
		t.Fatalf("re-create = %q, %v", again, err)
	}
	other := u
	other.ID = "u-2"
	if _, err := dir.CreateUser(ctx, other); err == nil || !strings.Contains(err.Error(), "another Tenarium user") {
		t.Fatalf("conflict err = %v", err)
	}

	// SetPassword right after creation waits for replication.
	u.ExternalID = id
	if err := dir.SetPassword(ctx, u, "short"); err == nil || !strings.Contains(err.Error(), "complexity") || strings.Contains(err.Error(), "short") {
		t.Fatalf("policy err = %v", err)
	}
	if err := dir.SetPassword(ctx, u, "correct horse 1"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	pp = f.user(id)["passwordProfile"].(map[string]any)
	if pp["password"] != "correct horse 1" || pp["forceChangePasswordNextSignIn"] != false {
		t.Fatalf("passwordProfile = %v", pp)
	}

	// Update: name, disable, email (UPN follows), attributes cleared.
	u.Name, u.Status, u.Email, u.Attributes = "", sdk.UserDisabled, "ada@lovelace.org", nil
	if err := dir.UpdateUser(ctx, u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	got = f.user(id)
	if got["displayName"] != "ada@lovelace.org" || got["accountEnabled"] != false || got["mail"] != "ada@lovelace.org" ||
		got["userPrincipalName"] != "ada_lovelace.org@contoso.onmicrosoft.com" || got["department"] != nil {
		t.Fatalf("user = %v", got)
	}
	u.Status = sdk.UserActive
	if err := dir.UpdateUser(ctx, u); err != nil || f.user(id)["accountEnabled"] != true {
		t.Fatalf("enable: %v, %v", err, f.user(id))
	}

	if err := dir.(sdk.InvitationSender).SendInvitation(ctx, u); !errors.Is(err, sdk.ErrUnsupported) {
		t.Fatalf("SendInvitation err = %v", err)
	}

	for range 2 {
		if err := dir.DeleteUser(ctx, u); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}
	}
	if f.user(id) != nil || f.deleted[id] == nil {
		t.Fatal("user not soft-deleted")
	}
	u.ExternalID = ""
	if err := dir.DeleteUser(ctx, u); err != nil {
		t.Fatalf("DeleteUser by email: %v", err)
	}
}

func TestAdoptKeepsUPN(t *testing.T) {
	f, dir, _ := setup(t, nil)
	ctx := context.Background()
	f.mu.Lock()
	id := f.add(map[string]any{"mail": "grace@example.com", "userPrincipalName": "ghopper@contoso.com", "displayName": "G"})
	f.mu.Unlock()
	u := sdk.User{ID: "u-9", Email: "GRACE@example.com", Name: "Grace Hopper", Status: sdk.UserActive}
	got, err := dir.CreateUser(ctx, u)
	if err != nil || got != id {
		t.Fatalf("adopt = %q, %v", got, err)
	}
	u.ExternalID = id
	u.Email = "grace@navy.mil"
	if err := dir.UpdateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if g := f.user(id); g["userPrincipalName"] != "ghopper@contoso.com" || g["mail"] != "grace@navy.mil" || g["displayName"] != "Grace Hopper" {
		t.Fatalf("user = %v", g)
	}
	// Without upn_domain the email is the UPN.
	u2 := sdk.User{ID: "u-10", Email: "alan@example.com"}
	id2, err := dir.CreateUser(ctx, u2)
	if err != nil || f.user(id2)["userPrincipalName"] != "alan@example.com" {
		t.Fatalf("create = %v, %v", err, f.user(id2))
	}
}

func TestHardDeleteAndThrottling(t *testing.T) {
	f, dir, _ := setup(t, map[string]any{"hard_delete": true})
	ctx := context.Background()
	u := ada
	var err error
	f.throttle = 2
	if u.ExternalID, err = dir.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser after throttling: %v", err)
	}
	if err := dir.DeleteUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if len(f.deleted) != 0 || len(f.users) != 0 {
		t.Fatalf("deleted = %v, users = %v", f.deleted, f.users)
	}
	f.throttle = 10
	if _, err := dir.CreateUser(ctx, ada); err == nil || !strings.Contains(err.Error(), "TooManyRequests") {
		t.Fatalf("persistent throttling err = %v", err)
	}
}

func TestGuestMode(t *testing.T) {
	f, dir, _ := setup(t, map[string]any{"mode": "guest", "user_id_attribute": "employeeId",
		"invite_redirect_url": "https://console.example.com/"})
	ctx := context.Background()
	u := ada
	id, err := dir.CreateUser(ctx, u)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if len(f.invites) != 1 || f.invites[0]["sendInvitationMessage"] != false ||
		f.invites[0]["inviteRedirectUrl"] != "https://console.example.com/" {
		t.Fatalf("invites = %v", f.invites)
	}
	if g := f.user(id); g["userType"] != "Guest" || g["employeeId"] != "u-1" {
		t.Fatalf("guest = %v", g)
	}
	if again, err := dir.CreateUser(ctx, u); err != nil || again != id || len(f.invites) != 1 {
		t.Fatalf("re-create = %q, %v, invites %d", again, err, len(f.invites))
	}
	u.ExternalID = id
	if err := dir.(sdk.InvitationSender).SendInvitation(ctx, u); err != nil {
		t.Fatalf("SendInvitation: %v", err)
	}
	if len(f.invites) != 2 || f.invites[1]["sendInvitationMessage"] != true {
		t.Fatalf("invites = %v", f.invites)
	}
	if err := dir.SetPassword(ctx, u, "whatever123"); !errors.Is(err, sdk.ErrUnsupported) {
		t.Fatalf("SetPassword err = %v", err)
	}
	u.Status = sdk.UserDisabled
	if err := dir.UpdateUser(ctx, u); err != nil || f.user(id)["accountEnabled"] != false {
		t.Fatalf("disable: %v %v", err, f.user(id))
	}
	if err := dir.DeleteUser(ctx, u); err != nil || f.user(id) != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestBadCredentials(t *testing.T) {
	f := newFakeGraph(t)
	reg := sdktest.NewRegistrar(map[string]any{"tenant_id": tenantID, "client_id": clientID, "client_secret": "nope",
		"authority_url": f.URL, "graph_url": f.URL + "/v1.0"})
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if err := p.Health(context.Background()); err == nil || !strings.Contains(err.Error(), "AADSTS7000215") {
		t.Fatalf("Health err = %v", err)
	}
}

func TestHelpers(t *testing.T) {
	if got := odataString("o'brien@x.com"); got != "'o''brien@x.com'" {
		t.Fatal(got)
	}
	d := &directory{p: &Plugin{cfg: Config{UPNDomain: "t.onmicrosoft.com"}}}
	long := strings.Repeat("a", 70) + "@example.com"
	if got := d.upn(long); len(strings.Split(got, "@")[0]) > 64 || got != d.upn(long) {
		t.Fatalf("upn = %q", got)
	}
	if got := d.upn("o'brien+x@ex.com"); got != "o_brien_x_ex.com@t.onmicrosoft.com" {
		t.Fatalf("upn = %q", got)
	}
	if got := mailNickname("@x"); got != "user" {
		t.Fatalf("nickname = %q", got)
	}
}

func TestConfigValidation(t *testing.T) {
	base := func(extra map[string]any) map[string]any {
		c := map[string]any{"tenant_id": "t", "client_id": "c", "client_secret": "s"}
		for k, v := range extra {
			c[k] = v
		}
		return c
	}
	bad := map[string]map[string]any{
		"no secret":            {"client_secret": ""},
		"bad mode":             {"mode": "admin"},
		"bad graph url":        {"graph_url": "graph.microsoft.com"},
		"bad upn domain":       {"upn_domain": "contoso"},
		"redirect in member":   {"invite_redirect_url": "https://x/"},
		"upn domain in guest":  {"mode": "guest", "upn_domain": "a.b"},
		"bad redirect":         {"mode": "guest", "invite_redirect_url": "/relative"},
		"reserved owner prop":  {"user_id_attribute": "mail"},
		"reserved mapped prop": {"attribute_map": map[string]any{"x": "accountEnabled"}},
		"duplicate prop":       {"user_id_attribute": "employeeId", "attribute_map": map[string]any{"x": "employeeId"}},
		"bad timeout":          {"timeout": "-1s"},
		"unknown key":          {"nope": 1},
	}
	for name, extra := range bad {
		t.Run(name, func(t *testing.T) {
			if err := (&Plugin{}).Init(context.Background(), sdktest.NewRegistrar(base(extra))); err == nil {
				t.Fatal("want error")
			}
		})
	}
	p := &Plugin{}
	if err := p.Init(context.Background(), sdktest.NewRegistrar(base(nil))); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	if p.graph != "https://graph.microsoft.com/v1.0" || scopeFor(p.graph) != "https://graph.microsoft.com/.default" {
		t.Fatalf("graph = %q", p.graph)
	}
	sch, err := schema.Compile(p.Manifest().ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(base(map[string]any{"mode": "guest", "attribute_map": map[string]any{"dept": "department"}})); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for _, c := range []map[string]any{base(map[string]any{"nope": 1}), base(map[string]any{"mode": "x"}), {"tenant_id": "t"}} {
		if err := sch.Validate(c); err == nil {
			t.Fatalf("config %v accepted", c)
		}
	}
}
