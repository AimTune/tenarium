package rbac

import (
	"context"
	"testing"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

func initPlugin(t *testing.T, cfg map[string]any) (*Plugin, error) {
	t.Helper()
	p := &Plugin{}
	return p, p.Init(context.Background(), sdktest.NewRegistrar(cfg))
}

func TestAuthorize(t *testing.T) {
	p, err := initPlugin(t, map[string]any{
		"roles": map[string]any{
			"admin":   []string{"*"},
			"viewer":  []string{"*:read"},
			"members": []string{"members:*"},
		},
		"bindings":     map[string]any{"core/api-key:ci": []string{"viewer"}},
		"tenant_roles": []string{"members"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	cases := []struct {
		name   string
		p      *sdk.Principal
		action sdk.Action
		want   sdk.Decision
	}{
		{"admin can do anything", &sdk.Principal{Roles: []string{"admin"}}, sdk.ActionPlansWrite, sdk.Allow},
		{"viewer reads", &sdk.Principal{Roles: []string{"viewer"}}, sdk.ActionTenantsRead, sdk.Allow},
		{"viewer cannot write", &sdk.Principal{Roles: []string{"viewer"}}, sdk.ActionTenantsUpdate, sdk.Abstain},
		{"binding", &sdk.Principal{Authenticator: "core/api-key", Subject: "ci"}, sdk.ActionEventsRead, sdk.Allow},
		{"tenant role", &sdk.Principal{TenantID: "t1"}, sdk.ActionMembersWrite, sdk.Allow},
		{"no roles", &sdk.Principal{Subject: "x"}, sdk.ActionTenantsRead, sdk.Abstain},
		{"unknown role ignored", &sdk.Principal{Roles: []string{"ghost"}}, sdk.ActionTenantsRead, sdk.Abstain},
	}
	for _, c := range cases {
		got, err := p.Authorize(ctx, c.p, c.action, sdk.Resource{})
		if err != nil || got != c.want {
			t.Errorf("%s: got %v %v, want %v", c.name, got, err, c.want)
		}
	}
	p.cfg.DenyUnknown = true
	if got, _ := p.Authorize(ctx, &sdk.Principal{}, sdk.ActionTenantsRead, sdk.Resource{}); got != sdk.Deny {
		t.Errorf("deny_unknown: got %v", got)
	}
}

func TestInitValidation(t *testing.T) {
	if _, err := initPlugin(t, map[string]any{"roles": map[string]any{"a": []string{"[bad"}}}); err == nil {
		t.Error("bad pattern accepted")
	}
	if _, err := initPlugin(t, map[string]any{"roles": map[string]any{}, "default_roles": []string{"nope"}}); err == nil {
		t.Error("undefined role accepted")
	}
}
