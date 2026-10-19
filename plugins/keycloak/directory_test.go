package keycloak

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
)

type dirEnv struct {
	kc  *fakeKeycloak
	reg *fakeRegistrar
	dir sdk.UserDirectory
	ctx context.Context
}

// setupDir starts a plugin offering only the directory, over realm
// "platform" (created at Init), merging users into the users block.
func setupDir(t *testing.T, users map[string]any) *dirEnv {
	t.Helper()
	kc := newFakeKeycloak(t)
	block := map[string]any{"realm": "platform", "create_realm": true}
	for k, v := range users {
		block[k] = v
	}
	reg := newRegistrar(map[string]any{
		"url": kc.URL, "username": "admin", "password": "secret",
		"provision_realms": false, "users": block,
	}, &fakeHost{})
	if err := (&Plugin{}).Init(context.Background(), reg); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if len(reg.directories) != 1 {
		t.Fatalf("directories = %v", reg.directories)
	}
	return &dirEnv{kc: kc, reg: reg, dir: reg.directories[0], ctx: context.Background()}
}

func (e *dirEnv) user(id string) map[string]any {
	e.kc.mu.Lock()
	defer e.kc.mu.Unlock()
	return e.kc.realms["platform"].users[id]
}

var ada = sdk.User{ID: "u-1", Email: "Ada@Example.com", Name: "Ada King Lovelace",
	Status: sdk.UserInvited, Attributes: map[string]string{"dept": "math"}}

func TestDirectoryRegistration(t *testing.T) {
	e := setupDir(t, nil)
	if e.dir.Name() != "keycloak" {
		t.Fatalf("Name = %q", e.dir.Name())
	}
	if _, ok := e.dir.(sdk.PasswordVerifier); ok {
		t.Fatal("PasswordVerifier offered without users.client_id")
	}
	if _, ok := e.dir.(sdk.InvitationSender); !ok {
		t.Fatal("not an InvitationSender")
	}
	if len(e.reg.provisioners) != 0 || len(e.reg.subs) != 0 {
		t.Fatalf("provision_realms=false registered %v / %v", e.reg.provisioners, e.reg.subs)
	}
	rl := e.kc.realm("platform")
	if rl == nil || !rl.enabled || rl.profile["unmanagedAttributePolicy"] != "ADMIN_EDIT" {
		t.Fatalf("realm = %+v", rl)
	}

	e = setupDir(t, map[string]any{"client_id": fakeClientID, "client_secret": fakeClientSecret})
	if _, ok := e.dir.(sdk.PasswordVerifier); !ok {
		t.Fatal("PasswordVerifier not offered with users.client_id")
	}
	if _, ok := e.dir.(sdk.InvitationSender); !ok {
		t.Fatal("verifying directory is not an InvitationSender")
	}
}

func TestDirectoryAlongsideRealms(t *testing.T) {
	e := setup(t, map[string]any{"users": map[string]any{"realm": "platform", "create_realm": true}})
	if len(e.reg.directories) != 1 {
		t.Fatalf("directories = %v", e.reg.directories)
	}
	if err := e.prov.Provision(e.ctx, acme); err != nil {
		t.Fatal(err)
	}
}

func TestDirectoryCreateUser(t *testing.T) {
	e := setupDir(t, nil)
	id, err := e.dir.CreateUser(e.ctx, ada)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	u := e.user(id)
	if u == nil {
		t.Fatalf("user %q not stored", id)
	}
	if u["username"] != "ada@example.com" || u["email"] != "Ada@Example.com" ||
		u["firstName"] != "Ada" || u["lastName"] != "King Lovelace" ||
		u["enabled"] != true || u["emailVerified"] != false {
		t.Fatalf("user = %v", u)
	}
	attrs, _ := u["attributes"].(map[string]any)
	if fmt.Sprint(attrs[UserIDAttribute]) != "[u-1]" || fmt.Sprint(attrs["dept"]) != "[math]" {
		t.Fatalf("attributes = %v", attrs)
	}

	// A retry finds the same identity.
	again, err := e.dir.CreateUser(e.ctx, ada)
	if err != nil || again != id {
		t.Fatalf("re-create = %q, %v; want %q", again, err, id)
	}

	// Another Tenarium user with the same email does not get it.
	other := ada
	other.ID = "u-2"
	if _, err := e.dir.CreateUser(e.ctx, other); err == nil || !strings.Contains(err.Error(), "another Tenarium user") {
		t.Fatalf("conflict err = %v", err)
	}

	// An identity created outside Tenarium (no owner attribute) is adopted.
	ext := sdk.User{ID: "u-3", Email: "ext@example.com", Name: "Ext", Status: sdk.UserDisabled}
	e.kc.mu.Lock()
	e.kc.realms["platform"].users["kc-ext"] = map[string]any{"id": "kc-ext", "username": "ext@example.com", "email": "ext@example.com"}
	e.kc.mu.Unlock()
	if got, err := e.dir.CreateUser(e.ctx, ext); err != nil || got != "kc-ext" {
		t.Fatalf("adopt = %q, %v", got, err)
	}

	if _, err := e.dir.CreateUser(e.ctx, sdk.User{ID: "u-4"}); err == nil {
		t.Fatal("want error without email")
	}
}

func TestDirectoryUpdateUser(t *testing.T) {
	e := setupDir(t, nil)
	u := ada
	id, err := e.dir.CreateUser(e.ctx, u)
	if err != nil {
		t.Fatal(err)
	}
	u.ExternalID = id
	u.Name = "Ada"
	u.Email = "ada@lovelace.org"
	u.Status = sdk.UserDisabled
	u.EmailVerified = true
	if err := e.dir.UpdateUser(e.ctx, u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	got := e.user(id)
	if got["firstName"] != "Ada" || got["lastName"] != "" || got["enabled"] != false ||
		got["emailVerified"] != true || got["username"] != "ada@lovelace.org" || got["email"] != "ada@lovelace.org" {
		t.Fatalf("user = %v", got)
	}
	if attrs, _ := got["attributes"].(map[string]any); fmt.Sprint(attrs[UserIDAttribute]) != "[u-1]" {
		t.Fatalf("attributes = %v", got["attributes"])
	}

	u.Status = sdk.UserActive
	if err := e.dir.UpdateUser(e.ctx, u); err != nil || e.user(id)["enabled"] != true {
		t.Fatalf("re-enable: %v, %v", err, e.user(id))
	}

	missing := u
	missing.ExternalID = "nope"
	if err := e.dir.UpdateUser(e.ctx, missing); err == nil {
		t.Fatal("want error for missing identity")
	}
}

func TestDirectoryDeleteUser(t *testing.T) {
	e := setupDir(t, nil)
	u := ada
	var err error
	if u.ExternalID, err = e.dir.CreateUser(e.ctx, u); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := e.dir.DeleteUser(e.ctx, u); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}
	}
	if e.user(u.ExternalID) != nil {
		t.Fatal("user still exists")
	}
	// Without an ExternalID nothing is found, which is fine too.
	u.ExternalID = ""
	if err := e.dir.DeleteUser(e.ctx, u); err != nil {
		t.Fatalf("DeleteUser without external ID: %v", err)
	}
}

func TestDirectoryPasswords(t *testing.T) {
	e := setupDir(t, map[string]any{"client_id": fakeClientID, "client_secret": fakeClientSecret})
	u := ada
	u.Status = sdk.UserActive
	var err error
	if u.ExternalID, err = e.dir.CreateUser(e.ctx, u); err != nil {
		t.Fatal(err)
	}
	err = e.dir.SetPassword(e.ctx, u, "short")
	if err == nil || !strings.Contains(err.Error(), "minimum length 8") || strings.Contains(err.Error(), "short") {
		t.Fatalf("policy err = %v", err)
	}
	if err := e.dir.SetPassword(e.ctx, u, "correct horse"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	v := e.dir.(sdk.PasswordVerifier)
	if err := v.VerifyPassword(e.ctx, u, "correct horse"); err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	err = v.VerifyPassword(e.ctx, u, "wrong password")
	if !errors.Is(err, ErrInvalidCredentials) || strings.Contains(err.Error(), "wrong password") {
		t.Fatalf("wrong password err = %v", err)
	}
	u.Status = sdk.UserDisabled
	if err := e.dir.UpdateUser(e.ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := v.VerifyPassword(e.ctx, u, "correct horse"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("disabled err = %v", err)
	}

	// A misconfigured client is not a credentials problem.
	e.reg.directories[0].(verifyingDirectory).cfg.ClientSecret = "bad"
	if err := v.VerifyPassword(e.ctx, u, "correct horse"); err == nil || errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("bad client err = %v", err)
	}
}

func TestDirectoryInvitation(t *testing.T) {
	e := setupDir(t, map[string]any{
		"send_invitation": true, "invitation_lifespan": "24h",
		"client_for_redirect": "console", "redirect_uri": "https://console.example.com/",
	})
	u := ada
	var err error
	if u.ExternalID, err = e.dir.CreateUser(e.ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := e.dir.(sdk.InvitationSender).SendInvitation(e.ctx, u); err != nil {
		t.Fatalf("SendInvitation: %v", err)
	}
	if len(e.kc.actionEmails) != 1 {
		t.Fatalf("emails = %v", e.kc.actionEmails)
	}
	got := e.kc.actionEmails[0]
	if got.realm != "platform" || got.id != u.ExternalID ||
		got.query.Get("lifespan") != "86400" || got.query.Get("client_id") != "console" ||
		got.query.Get("redirect_uri") != "https://console.example.com/" ||
		!slices.Equal(got.actions, []string{"UPDATE_PASSWORD", "VERIFY_EMAIL"}) {
		t.Fatalf("email = %+v", got)
	}

	// Defaults: 72h, custom actions, no redirect parameters.
	e = setupDir(t, map[string]any{"send_invitation": true, "invitation_actions": []string{"UPDATE_PASSWORD"}})
	if u.ExternalID, err = e.dir.CreateUser(e.ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := e.dir.(sdk.InvitationSender).SendInvitation(e.ctx, u); err != nil {
		t.Fatal(err)
	}
	got = e.kc.actionEmails[0]
	if got.query.Get("lifespan") != "259200" || got.query.Has("client_id") || got.query.Has("redirect_uri") ||
		!slices.Equal(got.actions, []string{"UPDATE_PASSWORD"}) {
		t.Fatalf("email = %+v", got)
	}

	// Disabled: Tenarium sends its own.
	e = setupDir(t, nil)
	if u.ExternalID, err = e.dir.CreateUser(e.ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := e.dir.(sdk.InvitationSender).SendInvitation(e.ctx, u); !errors.Is(err, sdk.ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
	if len(e.kc.actionEmails) != 0 {
		t.Fatalf("emails = %v", e.kc.actionEmails)
	}
}

func TestDirectoryConfigValidation(t *testing.T) {
	base := func(users map[string]any) map[string]any {
		return map[string]any{"url": "http://kc", "username": "a", "password": "b", "users": users}
	}
	cases := map[string]map[string]any{
		"no realm":            {"create_realm": false},
		"client w/o secret":   {"realm": "p", "client_id": "c"},
		"bad lifespan":        {"realm": "p", "invitation_lifespan": "forever"},
		"tiny lifespan":       {"realm": "p", "invitation_lifespan": "10ms"},
		"redirect w/o client": {"realm": "p", "redirect_uri": "https://x/"},
	}
	for name, users := range cases {
		t.Run(name, func(t *testing.T) {
			if err := (&Plugin{}).Init(context.Background(), newRegistrar(base(users), &fakeHost{})); err == nil {
				t.Fatal("want error")
			}
		})
	}
	ok := base(map[string]any{"realm": "p", "client_id": "c", "client_secret": "s", "redirect_uri": "https://x/"})
	if err := (&Plugin{}).Init(context.Background(), newRegistrar(ok, &fakeHost{})); err != nil {
		t.Fatalf("valid config: %v", err)
	}

	sch, err := schema.Compile((&Plugin{}).Manifest().ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	good := map[string]any{"url": "http://kc", "username": "a", "password": "b", "provision_realms": false,
		"users": map[string]any{"realm": "p", "send_invitation": true, "invitation_actions": []any{"UPDATE_PASSWORD"}}}
	if err := sch.Validate(good); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for _, users := range []map[string]any{{}, {"realm": "p", "nope": 1}} {
		if err := sch.Validate(map[string]any{"url": "http://kc", "users": users}); err == nil {
			t.Fatalf("users %v accepted", users)
		}
	}
}

// TestRealKeycloakDirectory runs the directory against a real server when
// TENARIUM_TEST_KEYCLOAK_URL is set; see TestRealKeycloak.
func TestRealKeycloakDirectory(t *testing.T) {
	base := os.Getenv("TENARIUM_TEST_KEYCLOAK_URL")
	if base == "" {
		t.Skip("TENARIUM_TEST_KEYCLOAK_URL not set")
	}
	user, pass := os.Getenv("TENARIUM_TEST_KEYCLOAK_USER"), os.Getenv("TENARIUM_TEST_KEYCLOAK_PASSWORD")
	if user == "" {
		user, pass = "admin", "admin"
	}
	realm := fmt.Sprintf("users-it%d", time.Now().UnixNano())
	const clientID, secret = "tenarium", "it-secret"
	reg := newRegistrar(map[string]any{
		"url": base, "username": user, "password": pass, "provision_realms": false,
		"users": map[string]any{"realm": realm, "create_realm": true, "client_id": clientID, "client_secret": secret},
	}, &fakeHost{})
	p := &Plugin{}
	ctx := context.Background()
	if err := p.Init(ctx, reg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = p.expect(ctx, http.MethodDelete, realmPath(realm), nil, http.StatusNoContent, http.StatusNotFound)
	})
	client := map[string]any{
		"clientId": clientID, "secret": secret, "publicClient": false, "enabled": true,
		"directAccessGrantsEnabled": true, "standardFlowEnabled": false, "protocol": "openid-connect",
	}
	if err := p.expect(ctx, http.MethodPost, realmPath(realm)+"/clients", client, http.StatusCreated); err != nil {
		t.Fatal(err)
	}

	dir := reg.directories[0]
	u := sdk.User{ID: "it-u1", Email: "It.User@Example.com", Name: "It User", Status: sdk.UserActive,
		EmailVerified: true, Attributes: map[string]string{"dept": "qa"}}
	id, err := dir.CreateUser(ctx, u)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if again, err := dir.CreateUser(ctx, u); err != nil || again != id {
		t.Fatalf("re-create = %q, %v; want %q", again, err, id)
	}
	other := u
	other.ID = "it-u2"
	if _, err := dir.CreateUser(ctx, other); err == nil {
		t.Fatal("identity owned by another Tenarium user was handed out")
	}
	u.ExternalID = id
	u.Name = "Ada Lovelace"
	if err := dir.UpdateUser(ctx, u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if err := dir.SetPassword(ctx, u, "correct horse battery"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	v := dir.(sdk.PasswordVerifier)
	if err := v.VerifyPassword(ctx, u, "correct horse battery"); err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if err := v.VerifyPassword(ctx, u, "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password err = %v", err)
	}
	if err := dir.(sdk.InvitationSender).SendInvitation(ctx, u); !errors.Is(err, sdk.ErrUnsupported) {
		t.Fatalf("SendInvitation err = %v", err)
	}
	for range 2 {
		if err := dir.DeleteUser(ctx, u); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}
	}
}
