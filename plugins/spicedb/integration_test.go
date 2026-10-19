package spicedb

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

const integrationSchema = `
definition user {}

definition tenant {
	relation parent: tenant
	relation owner: user
	relation member: user

	permission admin = owner + parent->admin
	permission can_update = admin
	permission can_read = admin + member
}
`

// TestIntegration runs against a real SpiceDB with the HTTP gateway, e.g.
//
//	docker run -d -p 18443:8443 authzed/spicedb serve --grpc-preshared-key key \
//	  --http-enabled --datastore-engine memory
//	TENARIUM_TEST_SPICEDB_URL=http://localhost:18443 TENARIUM_TEST_SPICEDB_TOKEN=key go test ./plugins/spicedb
func TestIntegration(t *testing.T) {
	base, token := os.Getenv("TENARIUM_TEST_SPICEDB_URL"), os.Getenv("TENARIUM_TEST_SPICEDB_TOKEN")
	if base == "" || token == "" {
		t.Skip("TENARIUM_TEST_SPICEDB_URL / TENARIUM_TEST_SPICEDB_TOKEN not set")
	}
	b, _ := json.Marshal(map[string]string{"schema": integrationSchema})
	req, _ := http.NewRequest(http.MethodPost, base+"/v1/schema/write", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("write schema: %s", resp.Status)
	}

	ctx := context.Background()
	reg := sdktest.NewRegistrar(map[string]any{
		"url": base, "token": token, "consistency": "at_least_as_fresh", "on_not_allowed": "deny",
		"sync": map[string]any{"tenant_parents": true, "members": true},
	})
	p := &Plugin{}
	if err := p.Init(ctx, reg); err != nil {
		t.Fatal(err)
	}
	if err := p.Health(ctx); err != nil {
		t.Fatalf("health: %v", err)
	}
	deliver := func(e sdk.Event) {
		t.Helper()
		if err := reg.Deliver(ctx, "relationships", e); err != nil {
			t.Fatal(err)
		}
	}
	ws := sdk.Tenant{ID: "ws1", ParentID: "org1"}
	deliver(sdktest.TenantEvent(sdk.EventTenantCreated, ws))
	deliver(sdktest.TenantEvent(sdk.EventTenantCreated, ws))
	owner := sdk.Member{ID: "m1", TenantID: "org1", UserID: "alice", Role: "owner", Status: sdk.MemberActive}
	reader := sdk.Member{ID: "m2", TenantID: "ws1", UserID: "bob", Role: "member", Status: sdk.MemberActive}
	deliver(sdktest.MemberEvent(sdk.EventMemberAdded, owner))
	deliver(sdktest.MemberEvent(sdk.EventMemberAdded, reader))

	res := sdk.Resource{Type: "tenant", ID: "ws1", TenantID: "ws1"}
	check := func(subject string, a sdk.Action, want sdk.Decision) {
		t.Helper()
		r := p.Check(ctx, &sdk.Principal{Subject: subject, Kind: "user"}, a, res)
		if r.Decision != want {
			t.Errorf("%s %s: got %+v, want %v", subject, a, r, want)
		}
	}
	check("alice", sdk.ActionTenantsUpdate, sdk.Allow)
	check("bob", sdk.ActionTenantsRead, sdk.Allow)
	check("bob", sdk.ActionTenantsUpdate, sdk.Deny)
	check("alice", sdk.ActionTenantsPurge, sdk.Abstain) // unknown permission: error → fail_mode

	deliver(sdktest.MemberEvent(sdk.EventMemberRemoved, reader))
	deliver(sdktest.MemberEvent(sdk.EventMemberRemoved, reader))
	check("bob", sdk.ActionTenantsRead, sdk.Deny)
	deliver(sdktest.TenantEvent(sdk.EventTenantDeleted, ws))
	check("alice", sdk.ActionTenantsUpdate, sdk.Deny)
}
