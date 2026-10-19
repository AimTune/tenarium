package openfga

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

// model: tenant admins (direct or on any ancestor) can update; members can read.
const integrationModel = `{
  "schema_version": "1.1",
  "type_definitions": [
    {"type": "user"},
    {"type": "tenant",
     "relations": {
       "parent": {"this": {}},
       "admin": {"union": {"child": [
         {"this": {}},
         {"tupleToUserset": {"tupleset": {"relation": "parent"}, "computedUserset": {"relation": "admin"}}}
       ]}},
       "member": {"this": {}},
       "can_update": {"computedUserset": {"relation": "admin"}},
       "can_read": {"union": {"child": [{"computedUserset": {"relation": "admin"}}, {"computedUserset": {"relation": "member"}}]}}
     },
     "metadata": {"relations": {
       "parent": {"directly_related_user_types": [{"type": "tenant"}]},
       "admin": {"directly_related_user_types": [{"type": "user"}]},
       "member": {"directly_related_user_types": [{"type": "user"}]}
     }}}
  ]
}`

func fgaPost(t *testing.T, url string, body any, out any) {
	t.Helper()
	var b []byte
	switch v := body.(type) {
	case string:
		b = []byte(v)
	default:
		b, _ = json.Marshal(v)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		t.Fatalf("POST %s: %s", url, resp.Status)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
}

// TestIntegration runs against a real OpenFGA, e.g.
//
//	docker run -d -p 18080:8080 openfga/openfga run --playground-enabled=false
//	TENARIUM_TEST_OPENFGA_URL=http://localhost:18080 go test ./plugins/openfga
func TestIntegration(t *testing.T) {
	base := os.Getenv("TENARIUM_TEST_OPENFGA_URL")
	if base == "" {
		t.Skip("TENARIUM_TEST_OPENFGA_URL not set")
	}
	var store struct {
		ID string `json:"id"`
	}
	fgaPost(t, base+"/stores", map[string]string{"name": "tenarium-test"}, &store)
	var model struct {
		ID string `json:"authorization_model_id"`
	}
	fgaPost(t, base+"/stores/"+store.ID+"/authorization-models", integrationModel, &model)

	ctx := context.Background()
	cfg := map[string]any{
		"url": base, "store_id": store.ID, "authorization_model_id": model.ID,
		"cache_ttl": "0s", "on_not_allowed": "deny",
		"sync": map[string]any{"tenant_parents": true, "members": true, "roles": map[string]any{"owner": "admin", "member": "member"}},
	}
	reg := sdktest.NewRegistrar(cfg)
	p := &Plugin{}
	if err := p.Init(ctx, reg); err != nil {
		t.Fatal(err)
	}
	if err := p.Health(ctx); err != nil {
		t.Fatalf("health: %v", err)
	}
	deliver := func(e sdk.Event) {
		t.Helper()
		if err := reg.Deliver(ctx, "tuples", e); err != nil {
			t.Fatal(err)
		}
	}
	org := sdk.Tenant{ID: "org1", Slug: "org1"}
	ws := sdk.Tenant{ID: "ws1", Slug: "ws1", ParentID: "org1"}
	deliver(sdktest.TenantEvent(sdk.EventTenantCreated, org))
	deliver(sdktest.TenantEvent(sdk.EventTenantCreated, ws))
	deliver(sdktest.TenantEvent(sdk.EventTenantCreated, ws)) // duplicate write tolerated
	owner := sdk.Member{ID: "m1", TenantID: "org1", UserID: "alice", Role: "owner", Status: sdk.MemberActive}
	reader := sdk.Member{ID: "m2", TenantID: "ws1", UserID: "bob", Role: "member", Status: sdk.MemberActive}
	deliver(sdktest.MemberEvent(sdk.EventMemberAdded, owner))
	deliver(sdktest.MemberEvent(sdk.EventMemberAdded, reader))

	alice := &sdk.Principal{Subject: "alice", Kind: "user"}
	bob := &sdk.Principal{Subject: "bob", Kind: "user"}
	wsRes := sdk.Resource{Type: "tenant", ID: "ws1", TenantID: "ws1"}
	check := func(pr *sdk.Principal, a sdk.Action, want sdk.Decision) {
		t.Helper()
		r := p.Check(ctx, pr, a, wsRes)
		if r.Decision != want {
			t.Errorf("%s %s: got %+v, want %v", pr.Subject, a, r, want)
		}
	}
	check(alice, sdk.ActionTenantsUpdate, sdk.Allow) // inherited admin
	check(bob, sdk.ActionTenantsRead, sdk.Allow)
	check(bob, sdk.ActionTenantsUpdate, sdk.Deny)
	// Relation not in the model: an error, so fail_mode (abstain) applies.
	check(alice, sdk.ActionTenantsPurge, sdk.Abstain)

	deliver(sdktest.MemberEvent(sdk.EventMemberRemoved, reader))
	deliver(sdktest.MemberEvent(sdk.EventMemberRemoved, reader)) // duplicate delete tolerated
	check(bob, sdk.ActionTenantsRead, sdk.Deny)
	deliver(sdktest.TenantEvent(sdk.EventTenantDeleted, ws))
	check(alice, sdk.ActionTenantsUpdate, sdk.Deny)

	// Contextual hierarchy without synced parent tuples.
	reg.HostImpl.AddTenant(org)
	reg.HostImpl.AddTenant(ws)
	p.cfg.ContextualParents = true
	check(alice, sdk.ActionTenantsUpdate, sdk.Allow)
}
