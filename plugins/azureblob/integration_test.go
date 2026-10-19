package azureblob

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

// Integration tests run against the Blob service named by the connection
// string in TENARIUM_TEST_AZURE_CONNECTION_STRING, e.g. Azurite:
//
//	docker run -d -p 10000:10000 mcr.microsoft.com/azure-storage/azurite \
//	  azurite-blob --blobHost 0.0.0.0 --skipApiVersionCheck --loose
//	TENARIUM_TEST_AZURE_CONNECTION_STRING='UseDevelopmentStorage=true'

func integrationPlugin(t *testing.T, extra map[string]any) (*Plugin, *sdktest.Registrar) {
	t.Helper()
	cs := os.Getenv("TENARIUM_TEST_AZURE_CONNECTION_STRING")
	if cs == "" {
		t.Skip("TENARIUM_TEST_AZURE_CONNECTION_STRING not set")
	}
	cfg := map[string]any{"connection_string": cs}
	for k, v := range extra {
		cfg[k] = v
	}
	reg := sdktest.NewRegistrar(cfg)
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if err := p.Health(context.Background()); err != nil {
		t.Fatalf("health: %v", err)
	}
	return p, reg
}

func randSlug(t *testing.T, prefix string) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return prefix + "-" + hex.EncodeToString(b)
}

// cleanupContainer deletes name at the end of the test, whatever its state.
func cleanupContainer(t *testing.T, p *Plugin, name string) {
	t.Cleanup(func() {
		err := p.client.deleteContainer(context.Background(), name, "")
		if err != nil && errCode(err) != "ContainerNotFound" && errCode(err) != "ContainerBeingDeleted" {
			t.Logf("cleanup %s: %v", name, err)
		}
	})
}

func putBlob(t *testing.T, p *Plugin, container, blob, body string) {
	t.Helper()
	h := http.Header{}
	h.Set("x-ms-blob-type", "BlockBlob")
	h.Set("Content-Type", "text/plain")
	resp, err := p.client.do(context.Background(), http.MethodPut, container+"/"+blob, url.Values{}, h, []byte(body))
	if err != nil {
		t.Fatalf("put blob %s/%s: %v", container, blob, err)
	}
	drain(resp)
}

func props(t *testing.T, p *Plugin, name string) (containerProps, bool) {
	t.Helper()
	pr, ok, err := p.client.getContainer(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	return pr, ok
}

func TestIntegrationLifecycle(t *testing.T) {
	ctx := context.Background()
	p, reg := integrationPlugin(t, map[string]any{"quota_from_limit": "storage_gb"})
	reg.HostImpl.AddPlan(sdk.Plan{ID: "pro", Limits: map[string]int64{"storage_gb": 25}})
	acme := reg.HostImpl.AddTenant(sdk.Tenant{Slug: randSlug(t, "life"), Plan: "pro"})
	name := mustName(t, p, acme)
	cleanupContainer(t, p, name)

	if err := p.Provision(ctx, acme); err != nil {
		t.Fatal(err)
	}
	pr, ok := props(t, p, name)
	if !ok || pr.Metadata[MetaTenantID] != acme.ID || pr.Metadata[MetaQuotaGB] != "25" || pr.PublicAccess != PublicAccessNone {
		t.Fatalf("after provision: %v %+v", ok, pr)
	}
	if err := p.Provision(ctx, acme); err != nil {
		t.Fatalf("second provision: %v", err)
	}
	putBlob(t, p, name, "data/hello.txt", "hello")

	other := reg.HostImpl.AddTenant(sdk.Tenant{ID: "other-" + acme.ID, Slug: acme.Slug})
	if err := p.Provision(ctx, other); err == nil || !strings.Contains(err.Error(), "belongs to another tenant") {
		t.Fatalf("collision: %v", err)
	}
	if err := p.Deprovision(ctx, other); err != nil {
		t.Fatal(err)
	}
	if _, ok := props(t, p, name); !ok {
		t.Fatal("foreign deprovision deleted the container")
	}

	if err := p.Deprovision(ctx, acme); err != nil {
		t.Fatal(err)
	}
	if _, ok := props(t, p, name); ok {
		t.Fatal("container still exists after delete")
	}
	if err := p.Deprovision(ctx, acme); err != nil {
		t.Fatalf("second deprovision: %v", err)
	}
	// Re-provisioning right after deletion works (Azure may report
	// ContainerBeingDeleted for a while, which Provision waits out).
	if err := p.Provision(ctx, acme); err != nil {
		t.Fatalf("re-provision: %v", err)
	}
}

func TestIntegrationAdoption(t *testing.T) {
	ctx := context.Background()
	p, reg := integrationPlugin(t, nil)
	a := reg.HostImpl.AddTenant(sdk.Tenant{Slug: randSlug(t, "adopt")})
	b := reg.HostImpl.AddTenant(sdk.Tenant{Slug: randSlug(t, "foreign")})
	na, nb := mustName(t, p, a), mustName(t, p, b)
	cleanupContainer(t, p, na)
	cleanupContainer(t, p, nb)

	// An empty unmarked container (an interrupted provision) is adopted,
	// keeping its other metadata.
	if err := p.client.createContainer(ctx, na, map[string]string{"team": "ops"}, PublicAccessNone); err != nil {
		t.Fatal(err)
	}
	if err := p.Provision(ctx, a); err != nil {
		t.Fatal(err)
	}
	if pr, _ := props(t, p, na); pr.Metadata[MetaTenantID] != a.ID || pr.Metadata["team"] != "ops" {
		t.Fatalf("adopted metadata %v", pr.Metadata)
	}

	// An unmarked container with data is neither adopted nor deleted.
	if err := p.client.createContainer(ctx, nb, nil, PublicAccessNone); err != nil {
		t.Fatal(err)
	}
	putBlob(t, p, nb, "x.txt", "x")
	if err := p.Provision(ctx, b); err == nil || !strings.Contains(err.Error(), "not managed by tenarium") {
		t.Fatalf("unmarked non-empty: %v", err)
	}
	if err := p.Deprovision(ctx, b); err != nil {
		t.Fatal(err)
	}
	if _, ok := props(t, p, nb); !ok {
		t.Fatal("unmanaged container deleted")
	}
}

func TestIntegrationRetainAndPublicAccess(t *testing.T) {
	ctx := context.Background()
	p, reg := integrationPlugin(t, map[string]any{"public_access": "blob", "on_deprovision": "retain"})
	a := reg.HostImpl.AddTenant(sdk.Tenant{Slug: randSlug(t, "retain")})
	name := mustName(t, p, a)
	cleanupContainer(t, p, name)

	if err := p.Provision(ctx, a); err != nil {
		t.Fatal(err)
	}
	if pr, _ := props(t, p, name); pr.PublicAccess != PublicAccessBlob {
		t.Fatalf("public access %q", pr.PublicAccess)
	}
	// Drift is corrected.
	if err := p.client.setPublicAccess(ctx, name, PublicAccessContainer); err != nil {
		t.Fatal(err)
	}
	if err := p.Provision(ctx, a); err != nil {
		t.Fatal(err)
	}
	if pr, _ := props(t, p, name); pr.PublicAccess != PublicAccessBlob {
		t.Fatalf("public access after fix %q", pr.PublicAccess)
	}
	putBlob(t, p, name, "keep.txt", "data")

	if err := p.Deprovision(ctx, a); err != nil {
		t.Fatal(err)
	}
	pr, ok := props(t, p, name)
	if !ok || pr.PublicAccess != PublicAccessNone || pr.Metadata[MetaTenantID] != "" ||
		pr.Metadata[MetaDeletedTenantID] != a.ID || pr.Metadata[MetaDeletedAt] == "" {
		t.Fatalf("retained: %v %+v", ok, pr)
	}
	if empty, err := p.client.isEmpty(ctx, name); err != nil || empty {
		t.Fatalf("retained data lost: %v %v", empty, err)
	}
	if err := p.Deprovision(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := p.Provision(ctx, a); err == nil || !strings.Contains(err.Error(), "retained") {
		t.Fatalf("provision over retained data: %v", err)
	}
}

func TestIntegrationKeepAndRoute(t *testing.T) {
	ctx := context.Background()
	p, reg := integrationPlugin(t, map[string]any{"on_deprovision": "keep", "name_template": "it-{{.ID}}"})
	a := reg.HostImpl.AddTenant(sdk.Tenant{Slug: randSlug(t, "keep")})
	name := mustName(t, p, a)
	cleanupContainer(t, p, name)
	if err := p.Provision(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := p.Deprovision(ctx, a); err != nil {
		t.Fatal(err)
	}
	if pr, ok := props(t, p, name); !ok || pr.Metadata[MetaTenantID] != a.ID {
		t.Fatalf("keep: %v %+v", ok, pr)
	}

	req := httptest.NewRequest(http.MethodGet, "/tenants/"+a.Slug, nil)
	req = req.WithContext(sdk.WithPrincipal(req.Context(), &sdk.Principal{Subject: "admin"}))
	rec := httptest.NewRecorder()
	reg.Mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"container":"`+name+`"`) {
		t.Fatalf("route: %d %s", rec.Code, rec.Body)
	}
}

func TestIntegrationBadKey(t *testing.T) {
	p, _ := integrationPlugin(t, nil)
	p.client.creds.Key = []byte("definitely-not-the-key")
	if err := p.Health(context.Background()); err == nil {
		t.Fatal("health succeeded with a wrong key")
	}
}
