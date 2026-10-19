package authz

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/AimTune/tenarium/internal/plugin"
	"github.com/AimTune/tenarium/pkg/sdk"
)

type fixed struct {
	d sdk.Decision
}

func (f fixed) Name() string { return "fixed" }
func (f fixed) Authorize(context.Context, *sdk.Principal, sdk.Action, sdk.Resource) (sdk.Decision, error) {
	return f.d, nil
}

// org → ws1 → ws1a ; other
var parents = map[string]string{"org": "", "ws1": "org", "ws1a": "ws1", "other": ""}

func parentOf(_ context.Context, id string) (string, error) {
	p, ok := parents[id]
	if !ok {
		return "", sdk.ErrNotFound
	}
	return p, nil
}

func engine(decisions ...sdk.Decision) *Engine {
	var refs []plugin.AuthorizerRef
	for _, d := range decisions {
		refs = append(refs, plugin.AuthorizerRef{Name: "t/fixed", Authorizer: fixed{d}})
	}
	return New(refs, parentOf, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func tenantRes(id string) sdk.Resource { return sdk.Resource{Type: "tenant", ID: id, TenantID: id} }

func TestTenantScope(t *testing.T) {
	ctx := context.Background()
	orgAdmin := &sdk.Principal{Subject: "a", TenantID: "org"}
	e := engine()
	for id, want := range map[string]bool{"org": true, "ws1": true, "ws1a": true, "other": false, "missing": false} {
		err := e.Authorize(ctx, orgAdmin, sdk.ActionTenantsUpdate, tenantRes(id))
		if (err == nil) != want {
			t.Errorf("%s: allowed=%v, want %v (%v)", id, err == nil, want, err)
		}
	}
	if err := e.Authorize(ctx, orgAdmin, sdk.ActionEventsRead, sdk.Resource{Type: "event"}); !errors.Is(err, sdk.ErrForbidden) {
		t.Errorf("scoped principal read global events: %v", err)
	}
	if err := e.Authorize(ctx, orgAdmin, sdk.ActionPlansRead, sdk.Resource{Type: "plan"}); err != nil {
		t.Errorf("scoped principal cannot read plans: %v", err)
	}
	for _, a := range []sdk.Action{sdk.ActionPlansWrite, sdk.ActionUsageWrite} {
		if err := e.Authorize(ctx, orgAdmin, a, tenantRes("org")); !errors.Is(err, sdk.ErrForbidden) {
			t.Errorf("scoped principal allowed platform-only %s: %v", a, err)
		}
	}
	// Scope cannot be lifted by an authorizer.
	if err := engine(sdk.Allow).Authorize(ctx, orgAdmin, sdk.ActionTenantsUpdate, tenantRes("other")); err == nil {
		t.Error("authorizer lifted tenant scope")
	}
}

func TestCombining(t *testing.T) {
	ctx := context.Background()
	p := &sdk.Principal{Subject: "x"}
	cases := []struct {
		ds    []sdk.Decision
		allow bool
	}{
		{nil, true},
		{[]sdk.Decision{sdk.Abstain}, false},
		{[]sdk.Decision{sdk.Allow}, true},
		{[]sdk.Decision{sdk.Allow, sdk.Deny}, false},
		{[]sdk.Decision{sdk.Abstain, sdk.Allow}, true},
	}
	for _, c := range cases {
		err := engine(c.ds...).Authorize(ctx, p, sdk.ActionTenantsRead, tenantRes("org"))
		if (err == nil) != c.allow {
			t.Errorf("%v: allowed=%v, want %v", c.ds, err == nil, c.allow)
		}
	}
	if err := engine().Authorize(ctx, nil, sdk.ActionTenantsRead, tenantRes("org")); err == nil {
		t.Error("nil principal allowed")
	}
}

func TestUserTokenRoles(t *testing.T) {
	ctx := context.Background()
	user := func(tenant string, roles ...string) *sdk.Principal {
		return &sdk.Principal{Subject: "u", Authenticator: UserTokenAuthenticator, TenantID: tenant, Roles: roles}
	}
	e := engine() // no authorizer plugins
	cases := []struct {
		p      *sdk.Principal
		action sdk.Action
		allow  bool
	}{
		{user("org", "viewer"), sdk.ActionTenantsRead, true},
		{user("org", "viewer"), sdk.ActionTenantsDelete, false},
		{user("org", "viewer"), sdk.ActionMembersWrite, false},
		{user("org", "owner"), sdk.ActionMembersWrite, true},
		{user("org", "owner"), sdk.ActionTenantsDelete, false},
		{user("org", "owner"), sdk.ActionPlansWrite, false},
		{user("", "admin"), sdk.ActionPlansWrite, true},
		{user("", "viewer"), sdk.ActionUsersWrite, false},
		{user("", "unknown"), sdk.ActionTenantsRead, false},
		// Other authenticators keep the "no authorizers = allow" behaviour.
		{&sdk.Principal{Subject: "k", Authenticator: "core/api-key"}, sdk.ActionTenantsDelete, true},
	}
	for _, c := range cases {
		err := e.Authorize(ctx, c.p, c.action, tenantRes("org"))
		if (err == nil) != c.allow {
			t.Errorf("%v %s: allowed=%v, want %v (%v)", c.p.Roles, c.action, err == nil, c.allow, err)
		}
	}
	// A plugin can still deny what the built-in table allows.
	if err := engine(sdk.Deny).Authorize(ctx, user("org", "owner"), sdk.ActionMembersWrite, tenantRes("org")); err == nil {
		t.Error("plugin deny ignored")
	}
	// With abstaining plugins, the built-in allow is enough.
	if err := engine(sdk.Abstain).Authorize(ctx, user("org", "owner"), sdk.ActionMembersWrite, tenantRes("org")); err != nil {
		t.Errorf("built-in allow lost: %v", err)
	}
}
