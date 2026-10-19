package opa

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

const integrationPolicy = `package tenarium.authz

import rego.v1

default allow := false

allow if "admin" in input.principal.roles

allow if {
	input.action_verb == "read"
	"viewer" in input.principal.roles
}

deny contains "tenant is frozen" if input.tenant.labels.frozen == "true"

deny contains "workspaces cannot be deleted by tenant admins" if {
	input.action == "tenants:delete"
	input.principal.tenant_id != ""
	count(input.tenant_ancestors) > 0
}

reason := "no matching role" if not allow
`

// TestIntegration runs against a real OPA, e.g.
//
//	docker run -d -p 18181:8181 openpolicyagent/opa run --server --addr=0.0.0.0:8181
//	TENARIUM_TEST_OPA_URL=http://localhost:18181 go test ./plugins/opa
func TestIntegration(t *testing.T) {
	base := os.Getenv("TENARIUM_TEST_OPA_URL")
	if base == "" {
		t.Skip("TENARIUM_TEST_OPA_URL not set")
	}
	req, _ := http.NewRequest(http.MethodPut, base+"/v1/policies/tenarium-test", strings.NewReader(integrationPolicy))
	req.Header.Set("Content-Type", "text/plain")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put policy: %s", resp.Status)
	}
	t.Cleanup(func() {
		req, _ := http.NewRequest(http.MethodDelete, base+"/v1/policies/tenarium-test", nil)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	})

	ctx := context.Background()
	reg := sdktest.NewRegistrar(map[string]any{"url": base, "path": "tenarium/authz", "include_tenant": true, "on_not_allowed": "deny"})
	p := &Plugin{}
	if err := p.Init(ctx, reg); err != nil {
		t.Fatal(err)
	}
	if err := p.Health(ctx); err != nil {
		t.Fatal(err)
	}
	org := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "org"})
	ws := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "ws", ParentID: org.ID})
	frozen := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "ice", Labels: map[string]string{"frozen": "true"}})
	res := func(t sdk.Tenant) sdk.Resource { return sdk.Resource{Type: "tenant", ID: t.ID, TenantID: t.ID} }

	admin := &sdk.Principal{Subject: "a", Kind: "user", Roles: []string{"admin"}}
	scopedAdmin := &sdk.Principal{Subject: "b", Kind: "user", Roles: []string{"admin"}, TenantID: org.ID}
	viewer := &sdk.Principal{Subject: "c", Kind: "user", Roles: []string{"viewer"}}
	cases := []struct {
		p      *sdk.Principal
		action sdk.Action
		res    sdk.Resource
		want   sdk.Decision
		reason string
	}{
		{admin, sdk.ActionTenantsUpdate, res(org), sdk.Allow, ""},
		{viewer, sdk.ActionTenantsRead, res(org), sdk.Allow, ""},
		{viewer, sdk.ActionTenantsUpdate, res(org), sdk.Deny, "no matching role"},
		{admin, sdk.ActionTenantsUpdate, res(frozen), sdk.Deny, "tenant is frozen"},
		{scopedAdmin, sdk.ActionTenantsDelete, res(ws), sdk.Deny, "cannot be deleted"},
		{admin, sdk.ActionTenantsDelete, res(ws), sdk.Allow, ""},
	}
	for _, c := range cases {
		r := p.Check(ctx, c.p, c.action, c.res)
		if r.Decision != c.want || !strings.Contains(r.Reason, c.reason) {
			t.Errorf("%s %s: got %+v, want %v (%s)", c.p.Subject, c.action, r, c.want, c.reason)
		}
	}
	// An undefined document abstains.
	reg2 := sdktest.NewRegistrar(map[string]any{"url": base, "path": "tenarium/missing"})
	p2 := &Plugin{}
	if err := p2.Init(ctx, reg2); err != nil {
		t.Fatal(err)
	}
	if r := p2.Check(ctx, admin, sdk.ActionTenantsRead, res(org)); r.Decision != sdk.Abstain {
		t.Errorf("undefined: %+v", r)
	}
}
