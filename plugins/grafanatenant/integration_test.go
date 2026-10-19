package grafanatenant

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

// Integration tests run against a Grafana server named by
// TENARIUM_TEST_GRAFANA_URL, signing in as the server admin
// TENARIUM_TEST_GRAFANA_USER (default "admin") with
// TENARIUM_TEST_GRAFANA_PASSWORD. Quota tests need GF_QUOTA_ENABLED=true:
//
//	docker run -d --name tenarium-test-grafana -p 47700:3000 \
//	  -e GF_SECURITY_ADMIN_PASSWORD=testpass123 -e GF_QUOTA_ENABLED=true grafana/grafana:11.3.0
//	TENARIUM_TEST_GRAFANA_URL=http://localhost:47700 TENARIUM_TEST_GRAFANA_PASSWORD=testpass123 \
//	  go test ./plugins/grafanatenant/ -run Integration

func integrationConfig(t *testing.T, cfg map[string]any) map[string]any {
	t.Helper()
	u := os.Getenv("TENARIUM_TEST_GRAFANA_URL")
	if u == "" {
		t.Skip("TENARIUM_TEST_GRAFANA_URL not set")
	}
	user := os.Getenv("TENARIUM_TEST_GRAFANA_USER")
	if user == "" {
		user = "admin"
	}
	full := map[string]any{"url": u, "username": user, "password": os.Getenv("TENARIUM_TEST_GRAFANA_PASSWORD")}
	for k, v := range cfg {
		full[k] = v
	}
	return full
}

func newIntegrationPlugin(t *testing.T, cfg map[string]any) (*Plugin, *sdktest.Registrar) {
	t.Helper()
	reg := sdktest.NewRegistrar(integrationConfig(t, cfg))
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if err := p.Health(context.Background()); err != nil {
		t.Fatalf("health: %v", err)
	}
	return p, reg
}

func randSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// cleanupOrg deletes the named organization at the end of the test.
func cleanupOrg(t *testing.T, p *Plugin, name string) {
	t.Cleanup(func() {
		ctx := context.Background()
		if o, err := p.orgByName(ctx, name); err == nil && o != nil {
			_ = p.deleteOrg(ctx, o.ID)
		}
	})
}

func cleanupUser(t *testing.T, p *Plugin, email string) {
	t.Cleanup(func() {
		ctx := context.Background()
		if u, err := p.lookupUser(ctx, email); err == nil && u != nil {
			_, _ = p.call(ctx, "delete user", http.MethodDelete, "/api/admin/users/"+strconv.FormatInt(u.ID, 10), 0, nil, nil)
		}
	})
}

func orgRole(t *testing.T, p *Plugin, orgID, userID int64) string {
	t.Helper()
	users, err := p.orgUsers(context.Background(), orgID)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		if u.UserID == userID {
			return u.Role
		}
	}
	return ""
}

func TestIntegrationLifecycle(t *testing.T) {
	ctx := context.Background()
	p, reg := newIntegrationPlugin(t, map[string]any{
		"quota": map[string]any{"dashboard": "dashboards", "data_source": "datasources"},
		"datasources": []any{map[string]any{
			"name": "Metrics", "type": "prometheus", "url": "http://prometheus:9090/{{.Tenant.Slug}}",
			"json_data":        map[string]any{"httpHeaderName1": "X-Scope-OrgID"},
			"secure_json_data": map[string]any{"httpHeaderValue1": "{{.Tenant.ID}}"},
		}},
	})
	reg.HostImpl.AddPlan(sdk.Plan{ID: "pro", Limits: map[string]int64{"dashboards": 7}})
	slug := "it-" + randSuffix(t)
	name := "tenant-" + slug
	cleanupOrg(t, p, name)
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug, Name: slug, Plan: "pro"})

	for range 2 {
		if err := p.Provision(ctx, ten); err != nil {
			t.Fatal(err)
		}
	}
	o, err := p.orgByName(ctx, name)
	if err != nil || o == nil || o.owner() != ten.ID {
		t.Fatalf("org %+v, %v", o, err)
	}
	qs, err := p.orgQuotas(ctx, o.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range qs {
		switch q.Target {
		case "dashboard":
			if q.Limit != 7 {
				t.Errorf("dashboard quota %d", q.Limit)
			}
		case "data_source":
			if q.Limit != -1 {
				t.Errorf("data_source quota %d", q.Limit)
			}
		}
	}
	var ds struct {
		URL      string          `json:"url"`
		JSONData map[string]any  `json:"jsonData"`
		Secure   map[string]bool `json:"secureJsonFields"`
	}
	if _, err := p.call(ctx, "get ds", http.MethodGet, "/api/datasources/name/Metrics", o.ID, nil, &ds); err != nil {
		t.Fatal(err)
	}
	if ds.URL != "http://prometheus:9090/"+slug || ds.JSONData["httpHeaderName1"] != "X-Scope-OrgID" || !ds.Secure["httpHeaderValue1"] {
		t.Fatalf("datasource %+v", ds)
	}

	// Another tenant with the same name can neither adopt nor delete it.
	other := reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug})
	if err := p.Provision(ctx, other); err == nil || !strings.Contains(err.Error(), "another tenant") {
		t.Fatalf("foreign provision: %v", err)
	}
	if err := p.Deprovision(ctx, other); err != nil {
		t.Fatal(err)
	}
	if o2, _ := p.orgByName(ctx, name); o2 == nil || o2.ID != o.ID {
		t.Fatal("foreign deprovision touched the org")
	}

	// Route.
	req := httptest.NewRequest(http.MethodGet, "/tenants/"+slug, nil)
	req = req.WithContext(sdk.WithPrincipal(req.Context(), &sdk.Principal{Subject: "admin"}))
	rec := httptest.NewRecorder()
	reg.Mux.ServeHTTP(rec, req)
	var info TenantInfo
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &info) != nil || info.OrgID != o.ID || !info.Provisioned {
		t.Fatalf("route: %d %s", rec.Code, rec.Body)
	}

	for range 2 {
		if err := p.Deprovision(ctx, ten); err != nil {
			t.Fatal(err)
		}
	}
	if o, _ := p.orgByName(ctx, name); o != nil {
		t.Fatal("org not deleted")
	}
}

func TestIntegrationAdoptAndRetain(t *testing.T) {
	ctx := context.Background()
	p, reg := newIntegrationPlugin(t, map[string]any{"on_deprovision": "retain"})
	slug := "it-" + randSuffix(t)
	name := "tenant-" + slug
	cleanupOrg(t, p, name)
	// An unmarked, empty organization (interrupted Provision) is adopted.
	id, err := p.createOrg(ctx, name)
	if err != nil || id == 0 {
		t.Fatalf("create org: %d %v", id, err)
	}
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug})
	if err := p.Provision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	o, err := p.orgByName(ctx, name)
	if err != nil || o != nil {
		t.Fatalf("org not renamed: %+v %v", o, err)
	}
	var retained org
	if _, err := p.call(ctx, "get org", http.MethodGet, orgPath(id), 0, nil, &retained); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.deleteOrg(context.Background(), id) })
	if !strings.HasPrefix(retained.Name, name+"-deleted-") || retained.retainedFrom() != ten.ID || retained.owner() != "" {
		t.Fatalf("retained %+v", retained)
	}
	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatal(err)
	}

	// An unmarked organization with content is never adopted.
	busy := "tenant-" + slug + "-busy"
	cleanupOrg(t, p, busy)
	bid, err := p.createOrg(ctx, busy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.call(ctx, "create ds", http.MethodPost, "/api/datasources", bid,
		map[string]any{"name": "x", "type": "prometheus", "url": "http://x", "access": "proxy"}, nil); err != nil {
		t.Fatal(err)
	}
	bt := reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug + "-busy"})
	if err := p.Provision(ctx, bt); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("busy adopt: %v", err)
	}
}

func TestIntegrationMembers(t *testing.T) {
	ctx := context.Background()
	p, reg := newIntegrationPlugin(t, map[string]any{
		"sync_members": true, "create_users": true, "remove_creator": true,
	})
	slug := "it-" + randSuffix(t)
	name := "tenant-" + slug
	cleanupOrg(t, p, name)
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug})
	if err := p.Provision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	o, _ := p.orgByName(ctx, name)
	self, err := p.self(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if orgRole(t, p, o.ID, self) != RoleAdmin {
		t.Fatal("creator should stay as the last admin")
	}

	ownerEmail := slug + "-owner@example.com"
	viewerEmail := slug + "-viewer@example.com"
	cleanupUser(t, p, ownerEmail)
	cleanupUser(t, p, viewerEmail)
	deliver := func(typ string, m sdk.Member) {
		t.Helper()
		if err := reg.Deliver(ctx, "members", sdktest.MemberEvent(typ, m)); err != nil {
			t.Fatal(err)
		}
	}
	owner := sdk.Member{ID: "m1", TenantID: ten.ID, Email: ownerEmail, Role: "owner", Status: sdk.MemberActive}
	viewer := sdk.Member{ID: "m2", TenantID: ten.ID, Email: viewerEmail, Role: "guest", Status: sdk.MemberActive}
	deliver(sdk.EventMemberAdded, owner)
	deliver(sdk.EventMemberAdded, owner)
	deliver(sdk.EventMemberAdded, viewer)
	ou, _ := p.lookupUser(ctx, ownerEmail)
	vu, _ := p.lookupUser(ctx, viewerEmail)
	if ou == nil || vu == nil {
		t.Fatal("users not created")
	}
	if r := orgRole(t, p, o.ID, ou.ID); r != RoleAdmin {
		t.Fatalf("owner role %q", r)
	}
	if r := orgRole(t, p, o.ID, vu.ID); r != RoleViewer {
		t.Fatalf("viewer role %q", r)
	}
	if r := orgRole(t, p, o.ID, self); r != "" {
		t.Fatalf("creator still in org as %q", r)
	}
	viewer.Role = "member"
	deliver(sdk.EventMemberUpdated, viewer)
	if r := orgRole(t, p, o.ID, vu.ID); r != RoleEditor {
		t.Fatalf("updated role %q", r)
	}
	deliver(sdk.EventMemberRemoved, viewer)
	deliver(sdk.EventMemberRemoved, viewer)
	if r := orgRole(t, p, o.ID, vu.ID); r != "" {
		t.Fatalf("removed member still has %q", r)
	}
	// The last admin cannot be removed; the event is not retried forever.
	deliver(sdk.EventMemberRemoved, owner)

	// Re-provisioning works without the plugin's membership.
	if err := p.Provision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	if o, _ := p.orgByName(ctx, name); o != nil {
		t.Fatal("org not deleted")
	}
}
