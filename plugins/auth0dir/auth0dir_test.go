package auth0dir

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

const (
	mgmtClient, mgmtSecret   = "m2m", "m2m-secret"
	loginClient, loginSecret = "spa", "spa-secret"
	conn                     = "Username-Password-Authentication"
)

// fakeAuth0 reproduces the Management API endpoints the directory uses,
// the token endpoint and /dbconnections/change_password.
type fakeAuth0 struct {
	*httptest.Server
	t   *testing.T
	mu  sync.Mutex
	seq int
	// users by user_id; each is the stored JSON object plus "password".
	users        map[string]map[string]any
	tokens       int
	resetEmails  []map[string]any
	verifyEmails []map[string]any
}

func newFakeAuth0(t *testing.T) *fakeAuth0 {
	f := &fakeAuth0{t: t, users: map[string]map[string]any{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth/token", f.token)
	mux.HandleFunc("POST /dbconnections/change_password", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in["client_id"] != loginClient && in["client_id"] != mgmtClient {
			writeJSON(w, 400, map[string]any{"error": "bad client"})
			return
		}
		f.mu.Lock()
		f.resetEmails = append(f.resetEmails, in)
		f.mu.Unlock()
		_, _ = w.Write([]byte(`"We've just sent you an email to reset your password."`))
	})
	api := http.NewServeMux()
	api.HandleFunc("GET /api/v2/users-by-email", f.byEmail)
	api.HandleFunc("POST /api/v2/users", f.create)
	api.HandleFunc("GET /api/v2/users/{id}", f.get)
	api.HandleFunc("PATCH /api/v2/users/{id}", f.patch)
	api.HandleFunc("DELETE /api/v2/users/{id}", f.del)
	api.HandleFunc("POST /api/v2/jobs/verification-email", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.users[fmt.Sprint(in["user_id"])] == nil {
			writeJSON(w, 404, map[string]any{"message": "user not found"})
			return
		}
		f.verifyEmails = append(f.verifyEmails, in)
		writeJSON(w, 201, map[string]any{"type": "verification_email", "status": "pending", "id": "job_1"})
	})
	mux.Handle("/api/v2/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer mgmt-token" {
			writeJSON(w, 401, map[string]any{"statusCode": 401, "error": "Unauthorized", "message": "Invalid token"})
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

func (f *fakeAuth0) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	switch r.PostForm.Get("grant_type") {
	case "client_credentials":
		if r.PostForm.Get("client_id") != mgmtClient || r.PostForm.Get("client_secret") != mgmtSecret ||
			r.PostForm.Get("audience") != f.URL+"/api/v2/" {
			writeJSON(w, 401, map[string]any{"error": "access_denied", "error_description": "Unauthorized"})
			return
		}
		f.mu.Lock()
		f.tokens++
		f.mu.Unlock()
		writeJSON(w, 200, map[string]any{"access_token": "mgmt-token", "token_type": "Bearer", "expires_in": 86400})
	case "http://auth0.com/oauth/grant-type/password-realm":
		if r.PostForm.Get("client_id") != loginClient || r.PostForm.Get("client_secret") != loginSecret {
			writeJSON(w, 401, map[string]any{"error": "access_denied", "error_description": "Unauthorized"})
			return
		}
		if r.PostForm.Get("realm") != conn {
			writeJSON(w, 400, map[string]any{"error": "invalid_request", "error_description": "unknown realm"})
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, u := range f.users {
			if strings.EqualFold(fmt.Sprint(u["email"]), r.PostForm.Get("username")) && u["password"] == r.PostForm.Get("password") {
				if u["blocked"] == true {
					writeJSON(w, 401, map[string]any{"error": "unauthorized", "error_description": "user is blocked"})
					return
				}
				writeJSON(w, 200, map[string]any{"access_token": "user-token", "id_token": "x", "expires_in": 60})
				return
			}
		}
		writeJSON(w, 403, map[string]any{"error": "invalid_grant", "error_description": "Wrong email or password."})
	default:
		writeJSON(w, 400, map[string]any{"error": "unsupported_grant_type"})
	}
}

// public returns the user without the password.
func public(u map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range u {
		if k != "password" {
			out[k] = v
		}
	}
	return out
}

func (f *fakeAuth0) byEmail(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []map[string]any{}
	for _, u := range f.users {
		if strings.EqualFold(fmt.Sprint(u["email"]), r.URL.Query().Get("email")) {
			out = append(out, public(u))
		}
	}
	writeJSON(w, 200, out)
}

func (f *fakeAuth0) create(w http.ResponseWriter, r *http.Request) {
	var in map[string]any
	_ = json.NewDecoder(r.Body).Decode(&in)
	f.mu.Lock()
	defer f.mu.Unlock()
	if in["connection"] != conn {
		writeJSON(w, 400, map[string]any{"message": "connection does not exist"})
		return
	}
	if pw, _ := in["password"].(string); len(pw) < 8 {
		writeJSON(w, 400, map[string]any{"message": "PasswordStrengthError: Password is too weak"})
		return
	}
	for _, u := range f.users {
		if strings.EqualFold(fmt.Sprint(u["email"]), fmt.Sprint(in["email"])) {
			writeJSON(w, 409, map[string]any{"statusCode": 409, "message": "The user already exists.", "errorCode": "auth0_idp_error"})
			return
		}
	}
	f.seq++
	id := fmt.Sprintf("auth0|%04d", f.seq)
	u := map[string]any{"user_id": id, "identities": []any{map[string]any{"connection": conn, "provider": "auth0"}}}
	for k, v := range in {
		if k != "connection" && k != "verify_email" {
			u[k] = v
		}
	}
	u["email"] = strings.ToLower(fmt.Sprint(in["email"])) // Auth0 lower-cases emails
	if in["verify_email"] == true {
		f.verifyEmails = append(f.verifyEmails, map[string]any{"user_id": id, "on_create": true})
	}
	f.users[id] = u
	writeJSON(w, 201, public(u))
}

func (f *fakeAuth0) get(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.users[r.PathValue("id")]
	if u == nil {
		writeJSON(w, 404, map[string]any{"statusCode": 404, "message": "The user does not exist."})
		return
	}
	writeJSON(w, 200, public(u))
}

func (f *fakeAuth0) patch(w http.ResponseWriter, r *http.Request) {
	var in map[string]any
	_ = json.NewDecoder(r.Body).Decode(&in)
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.users[r.PathValue("id")]
	if u == nil {
		writeJSON(w, 404, map[string]any{"statusCode": 404, "message": "The user does not exist."})
		return
	}
	if _, ok := in["email"]; ok && in["connection"] != conn {
		writeJSON(w, 400, map[string]any{"message": "connection is required when updating email"})
		return
	}
	if pw, ok := in["password"].(string); ok {
		if in["connection"] != conn {
			writeJSON(w, 400, map[string]any{"message": "connection is required when updating password"})
			return
		}
		if len(pw) < 8 {
			writeJSON(w, 400, map[string]any{"message": "PasswordStrengthError: Password is too weak"})
			return
		}
	}
	for k, v := range in {
		switch k {
		case "connection":
		case "app_metadata": // merged at the first level, like Auth0
			md, _ := u["app_metadata"].(map[string]any)
			if md == nil {
				md = map[string]any{}
			}
			for mk, mv := range v.(map[string]any) {
				md[mk] = mv
			}
			u["app_metadata"] = md
		default:
			u[k] = v
		}
	}
	writeJSON(w, 200, public(u))
}

func (f *fakeAuth0) del(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.users, r.PathValue("id")) // Auth0 answers 204 for unknown users too
	w.WriteHeader(204)
}

func (f *fakeAuth0) user(id string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.users[id]
}

func setup(t *testing.T, extra map[string]any) (*fakeAuth0, sdk.UserDirectory, *Plugin) {
	t.Helper()
	f := newFakeAuth0(t)
	cfg := map[string]any{"domain": f.URL, "client_id": mgmtClient, "client_secret": mgmtSecret, "connection": conn}
	for k, v := range extra {
		cfg[k] = v
	}
	reg := sdktest.NewRegistrar(cfg)
	p := &Plugin{}
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

func TestRegistration(t *testing.T) {
	_, dir, p := setup(t, nil)
	if dir.Name() != "auth0" {
		t.Fatalf("Name = %q", dir.Name())
	}
	if _, ok := dir.(sdk.PasswordVerifier); ok {
		t.Fatal("PasswordVerifier offered without password_login")
	}
	if _, ok := dir.(sdk.InvitationSender); !ok {
		t.Fatal("not an InvitationSender")
	}
	if err := p.Health(context.Background()); err != nil {
		t.Fatalf("Health: %v", err)
	}
	_, dir, _ = setup(t, map[string]any{"password_login": map[string]any{"client_id": loginClient, "client_secret": loginSecret}})
	if _, ok := dir.(sdk.PasswordVerifier); !ok {
		t.Fatal("PasswordVerifier not offered with password_login")
	}
}

func TestCreateUser(t *testing.T) {
	f, dir, _ := setup(t, map[string]any{"verify_email": true})
	ctx := context.Background()
	id, err := dir.CreateUser(ctx, ada)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	u := f.user(id)
	if u["email"] != "ada@example.com" || u["name"] != "Ada Lovelace" || u["blocked"] != false || u["email_verified"] != false {
		t.Fatalf("user = %v", u)
	}
	if pw, _ := u["password"].(string); len(pw) < 20 {
		t.Fatalf("random password = %q", pw)
	}
	md := u["app_metadata"].(map[string]any)["tenarium"].(map[string]any)
	if md["user_id"] != "u-1" || fmt.Sprint(md["attributes"]) != "map[dept:math]" {
		t.Fatalf("app_metadata = %v", md)
	}
	if len(f.verifyEmails) != 1 {
		t.Fatalf("verify emails = %v", f.verifyEmails)
	}

	// A retry finds the same user.
	if again, err := dir.CreateUser(ctx, ada); err != nil || again != id {
		t.Fatalf("re-create = %q, %v; want %q", again, err, id)
	}
	// Another Tenarium user with the same email does not get it.
	other := ada
	other.ID = "u-2"
	if _, err := dir.CreateUser(ctx, other); err == nil || !strings.Contains(err.Error(), "another Tenarium user") {
		t.Fatalf("conflict err = %v", err)
	}
	// A user created outside Tenarium is adopted; one in another connection is not.
	f.mu.Lock()
	f.users["auth0|ext"] = map[string]any{"user_id": "auth0|ext", "email": "ext@example.com",
		"identities": []any{map[string]any{"connection": conn}}}
	f.users["google-oauth2|1"] = map[string]any{"user_id": "google-oauth2|1", "email": "g@example.com",
		"identities": []any{map[string]any{"connection": "google-oauth2"}}}
	f.mu.Unlock()
	if got, err := dir.CreateUser(ctx, sdk.User{ID: "u-3", Email: "EXT@example.com"}); err != nil || got != "auth0|ext" {
		t.Fatalf("adopt = %q, %v", got, err)
	}
	if got, err := dir.CreateUser(ctx, sdk.User{ID: "u-4", Email: "g@example.com", Status: sdk.UserDisabled}); err == nil {
		// The fake rejects duplicate emails across connections; a real Auth0
		// would create a second user. Either way the social user is not adopted.
		t.Fatalf("social user adopted: %q", got)
	}
	if _, err := dir.CreateUser(ctx, sdk.User{ID: "u-5"}); err == nil {
		t.Fatal("want error without email")
	}
}

func TestUpdateAndDelete(t *testing.T) {
	f, dir, _ := setup(t, nil)
	ctx := context.Background()
	u := ada
	var err error
	if u.ExternalID, err = dir.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	u.Name = ""
	u.Email = "ada@lovelace.org"
	u.Status = sdk.UserDisabled
	u.EmailVerified = true
	u.Attributes = map[string]string{"team": "engines"}
	if err := dir.UpdateUser(ctx, u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	got := f.user(u.ExternalID)
	md := got["app_metadata"].(map[string]any)["tenarium"].(map[string]any)
	if got["email"] != "ada@lovelace.org" || got["name"] != "ada@lovelace.org" || got["blocked"] != true ||
		got["email_verified"] != true || fmt.Sprint(md["attributes"]) != "map[team:engines]" || md["user_id"] != "u-1" {
		t.Fatalf("user = %v", got)
	}
	u.Status = sdk.UserActive
	if err := dir.UpdateUser(ctx, u); err != nil || f.user(u.ExternalID)["blocked"] != false {
		t.Fatalf("unblock: %v %v", err, f.user(u.ExternalID))
	}
	missing := u
	missing.ExternalID = "auth0|nope"
	if err := dir.UpdateUser(ctx, missing); err == nil {
		t.Fatal("want error for missing user")
	}

	for range 2 {
		if err := dir.DeleteUser(ctx, u); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}
	}
	if f.user(u.ExternalID) != nil {
		t.Fatal("user still exists")
	}
	u.ExternalID = ""
	if err := dir.DeleteUser(ctx, u); err != nil {
		t.Fatalf("DeleteUser without external ID: %v", err)
	}
	if f.tokens != 1 {
		t.Fatalf("token requests = %d, want 1 (cached)", f.tokens)
	}
}

func TestPasswords(t *testing.T) {
	f, dir, _ := setup(t, map[string]any{"password_login": map[string]any{"client_id": loginClient, "client_secret": loginSecret}})
	ctx := context.Background()
	u := ada
	u.Status = sdk.UserActive
	var err error
	if u.ExternalID, err = dir.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	err = dir.SetPassword(ctx, u, "short")
	if err == nil || !strings.Contains(err.Error(), "PasswordStrengthError") || strings.Contains(err.Error(), "short") {
		t.Fatalf("policy err = %v", err)
	}
	if err := dir.SetPassword(ctx, u, "correct horse"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if f.user(u.ExternalID)["password"] != "correct horse" {
		t.Fatal("password not stored")
	}
	v := dir.(sdk.PasswordVerifier)
	if err := v.VerifyPassword(ctx, u, "correct horse"); err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if err := v.VerifyPassword(ctx, u, "wrong password"); !errors.Is(err, ErrInvalidCredentials) || strings.Contains(err.Error(), "wrong password") {
		t.Fatalf("wrong password err = %v", err)
	}
	if err := v.VerifyPassword(ctx, u, ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("empty password err = %v", err)
	}
	u.Status = sdk.UserDisabled
	if err := dir.UpdateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := v.VerifyPassword(ctx, u, "correct horse"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("blocked err = %v", err)
	}
	// A misconfigured client is not a credentials problem.
	v.(verifyingDirectory).p.cfg.PasswordLogin.ClientSecret = "bad"
	if err := v.VerifyPassword(ctx, u, "correct horse"); err == nil || errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("bad client err = %v", err)
	}
}

func TestInvitations(t *testing.T) {
	ctx := context.Background()
	f, dir, _ := setup(t, nil)
	u := ada
	var err error
	if u.ExternalID, err = dir.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := dir.(sdk.InvitationSender).SendInvitation(ctx, u); !errors.Is(err, sdk.ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
	if len(f.resetEmails) != 0 || len(f.verifyEmails) != 0 {
		t.Fatalf("emails sent without an invitation mode: reset %v, verify %v", f.resetEmails, f.verifyEmails)
	}

	f, dir, _ = setup(t, map[string]any{"invitation": "change_password_email",
		"password_login": map[string]any{"client_id": loginClient, "client_secret": loginSecret}})
	if u.ExternalID, err = dir.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := dir.(sdk.InvitationSender).SendInvitation(ctx, u); err != nil {
		t.Fatalf("SendInvitation: %v", err)
	}
	if len(f.resetEmails) != 1 || f.resetEmails[0]["client_id"] != loginClient ||
		f.resetEmails[0]["connection"] != conn || f.resetEmails[0]["email"] != u.Email {
		t.Fatalf("reset emails = %v", f.resetEmails)
	}

	f, dir, _ = setup(t, map[string]any{"invitation": "verification_email", "invitation_client_id": mgmtClient})
	if u.ExternalID, err = dir.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := dir.(sdk.InvitationSender).SendInvitation(ctx, u); err != nil {
		t.Fatalf("SendInvitation: %v", err)
	}
	if len(f.verifyEmails) != 1 || f.verifyEmails[0]["user_id"] != u.ExternalID || f.verifyEmails[0]["client_id"] != mgmtClient {
		t.Fatalf("verify emails = %v", f.verifyEmails)
	}
}

func TestBadManagementCredentials(t *testing.T) {
	f := newFakeAuth0(t)
	reg := sdktest.NewRegistrar(map[string]any{"domain": f.URL, "client_id": mgmtClient, "client_secret": "nope", "connection": conn})
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if err := p.Health(context.Background()); err == nil {
		t.Fatal("Health succeeded with bad credentials")
	}
	if _, err := reg.Directory.CreateUser(context.Background(), ada); err == nil {
		t.Fatal("CreateUser succeeded with bad credentials")
	}
}

func TestConfigValidation(t *testing.T) {
	base := func(extra map[string]any) map[string]any {
		c := map[string]any{"domain": "acme.eu.auth0.com", "client_id": "c", "client_secret": "s", "connection": conn}
		for k, v := range extra {
			c[k] = v
		}
		return c
	}
	bad := map[string]map[string]any{
		"no domain":           {"domain": ""},
		"domain with path":    {"domain": "https://acme.auth0.com/api"},
		"bad scheme":          {"domain": "ftp://acme.auth0.com"},
		"no secret":           {"client_secret": ""},
		"no connection":       {"connection": ""},
		"bad invitation":      {"invitation": "carrier-pigeon"},
		"bad timeout":         {"timeout": "soon"},
		"login secret w/o id": {"password_login": map[string]any{"client_secret": "x"}},
		"unknown key":         {"nope": true},
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
	if p.base != "https://acme.eu.auth0.com" || p.cfg.Audience != "https://acme.eu.auth0.com/api/v2/" {
		t.Fatalf("base = %q, audience = %q", p.base, p.cfg.Audience)
	}

	sch, err := schema.Compile(p.Manifest().ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(base(map[string]any{"invitation": "change_password_email", "password_login": map[string]any{}})); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for _, c := range []map[string]any{base(map[string]any{"nope": 1}), base(map[string]any{"invitation": "x"}), {"domain": "x"}} {
		if err := sch.Validate(c); err == nil {
			t.Fatalf("config %v accepted", c)
		}
	}
}

func TestRandomPassword(t *testing.T) {
	seen := map[string]bool{}
	for range 50 {
		pw, err := randomPassword()
		if err != nil || len(pw) < 32 || hasTriple(pw) || seen[pw] {
			t.Fatalf("password %q, %v", pw, err)
		}
		seen[pw] = true
	}
}

func TestHasTriple(t *testing.T) {
	for s, want := range map[string]bool{
		"":        false,
		"aa":      false,
		"aaa":     true,
		"aab":     false,
		"abaa":    false,
		"xyzzz":   true,
		"aabbaab": false,
		"ab111cd": true,
		"abab":    false,
	} {
		if got := hasTriple(s); got != want {
			t.Errorf("hasTriple(%q) = %v, want %v", s, got, want)
		}
	}
}
