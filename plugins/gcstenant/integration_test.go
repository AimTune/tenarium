package gcstenant

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

// Integration tests run against a GCS emulator named by
// TENARIUM_TEST_GCS_ENDPOINT (e.g. http://localhost:4443 for
// fsouza/fake-gcs-server started with "-scheme http -public-host
// localhost:4443"), with anonymous requests. TENARIUM_TEST_GCS_PROJECT
// sets the project (default "test-project"); when it is set without an
// endpoint, the tests run against real GCS with Application Default
// Credentials and create (and delete) buckets named tnt-it-<random>.

func testConfig(t *testing.T) map[string]any {
	t.Helper()
	endpoint := os.Getenv("TENARIUM_TEST_GCS_ENDPOINT")
	project := os.Getenv("TENARIUM_TEST_GCS_PROJECT")
	if endpoint == "" && project == "" {
		t.Skip("TENARIUM_TEST_GCS_ENDPOINT / TENARIUM_TEST_GCS_PROJECT not set")
	}
	cfg := map[string]any{"project": project}
	if project == "" {
		cfg["project"] = "test-project"
	}
	if endpoint != "" {
		cfg["endpoint"] = endpoint
		cfg["anonymous"] = true
	}
	return cfg
}

func randHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// newIntegrationPlugin initializes the plugin with cfg merged over the
// connection settings.
func newIntegrationPlugin(t *testing.T, cfg map[string]any) (*Plugin, *sdktest.Registrar) {
	t.Helper()
	full := testConfig(t)
	for k, v := range cfg {
		full[k] = v
	}
	if full["mode"] == ModePrefix {
		delete(full, "project")
	}
	reg := sdktest.NewRegistrar(full)
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if err := p.Health(context.Background()); err != nil {
		t.Fatalf("health: %v", err)
	}
	return p, reg
}

// cleanupBucket force-deletes bkt at the end of the test.
func cleanupBucket(t *testing.T, p *Plugin, bkt string) {
	t.Cleanup(func() {
		ctx := context.Background()
		if _, err := p.gcs.getBucket(ctx, bkt); err != nil {
			return
		}
		if err := p.removeAll(ctx, bkt, "", ""); err != nil {
			t.Logf("cleanup %s: %v", bkt, err)
		}
		if err := p.gcs.deleteBucket(ctx, bkt); err != nil {
			t.Logf("cleanup %s: %v", bkt, err)
		}
	})
}

func putObject(t *testing.T, p *Plugin, bkt, key, body string) {
	t.Helper()
	if err := p.gcs.putObject(context.Background(), bkt, key, "text/plain", []byte(body), nil, ""); err != nil {
		t.Fatalf("put %s/%s: %v", bkt, key, err)
	}
}

func bucketExists(t *testing.T, p *Plugin, bkt string) bool {
	t.Helper()
	_, err := p.gcs.getBucket(context.Background(), bkt)
	if isNotFound(err) {
		return false
	} else if err != nil {
		t.Fatal(err)
	}
	return true
}

func countObjects(t *testing.T, p *Plugin, bkt, prefix string) int {
	t.Helper()
	n := 0
	err := p.gcs.listObjects(context.Background(), bkt, prefix, 0, func(object) error {
		n++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func readMarkerOf(t *testing.T, p *Plugin, bkt, key string) (*object, string) {
	t.Helper()
	o, content, err := p.readMarker(context.Background(), bkt, key)
	if err != nil {
		t.Fatal(err)
	}
	return o, content
}

func TestIntegrationBucketObjectOwnership(t *testing.T) {
	p, reg := newIntegrationPlugin(t, map[string]any{
		"name_template": "tnt-it-{{.Slug}}", "ownership": "object", "versioning": true,
		"quota_from_limit": "storage_gb",
	})
	ctx := context.Background()
	slug := "obj-" + randHex(t)
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug, Limits: map[string]int64{"storage_gb": 25}})
	bkt := "tnt-it-" + slug
	cleanupBucket(t, p, bkt)

	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatalf("deprovision of never-provisioned tenant: %v", err)
	}
	for range 2 {
		if err := p.Provision(ctx, ten); err != nil {
			t.Fatalf("provision: %v", err)
		}
	}
	b, err := p.gcs.getBucket(ctx, bkt)
	if err != nil {
		t.Fatal(err)
	}
	if !b.versioningEnabled() {
		t.Error("versioning not enabled")
	}
	m, owner := readMarkerOf(t, p, bkt, ownerObject)
	if m == nil || owner != ten.ID || m.Metadata[LabelQuotaGB] != "25" || m.Metadata[LabelTenantID] != ten.ID {
		t.Fatalf("marker %+v %q", m, owner)
	}

	// Another tenant with the same slug cannot take the bucket over.
	other := reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug})
	if err := p.Provision(ctx, other); err == nil || !strings.Contains(err.Error(), "another tenant") {
		t.Fatalf("provision of other tenant: %v", err)
	}
	if err := p.Deprovision(ctx, other); err != nil || !bucketExists(t, p, bkt) {
		t.Fatalf("deprovision of other tenant: %v", err)
	}

	putObject(t, p, bkt, "a.txt", "1")
	putObject(t, p, bkt, "a.txt", "2") // noncurrent generation
	putObject(t, p, bkt, "dir/b.txt", "b")
	if n := countObjects(t, p, bkt, ""); n < 4 {
		t.Fatalf("expected noncurrent generations, got %d objects", n)
	}
	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatalf("deprovision: %v", err)
	}
	if bucketExists(t, p, bkt) {
		t.Fatal("bucket still exists after delete")
	}
	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatalf("second deprovision: %v", err)
	}
}

func TestIntegrationBucketObjectRetain(t *testing.T) {
	p, reg := newIntegrationPlugin(t, map[string]any{
		"name_template": "tnt-it-{{.Slug}}", "ownership": "object", "on_deprovision": "retain",
	})
	ctx := context.Background()
	slug := "ret-" + randHex(t)
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug})
	bkt := "tnt-it-" + slug
	cleanupBucket(t, p, bkt)

	if err := p.Provision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	putObject(t, p, bkt, "data.txt", "x")
	for range 2 {
		if err := p.Deprovision(ctx, ten); err != nil {
			t.Fatal(err)
		}
	}
	if o, _ := readMarkerOf(t, p, bkt, ownerObject); o != nil {
		t.Fatal("owner marker still present")
	}
	if o, raw := readMarkerOf(t, p, bkt, retainedObject); o == nil || !strings.Contains(raw, ten.ID) {
		t.Fatalf("retained marker %q", raw)
	}
	if o, _ := readMarkerOf(t, p, bkt, "data.txt"); o == nil {
		t.Fatal("data removed")
	}
	again := reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug})
	if err := p.Provision(ctx, again); err == nil || !strings.Contains(err.Error(), "retained from deleted tenant") {
		t.Fatalf("provision over retained data: %v", err)
	}
}

func TestIntegrationBucketLabels(t *testing.T) {
	p, reg := newIntegrationPlugin(t, map[string]any{
		"name_template": "tnt-it-{{.Slug}}", "lifecycle_expire_days": 30, "quota_from_limit": "storage_gb",
		"labels": map[string]any{"slug": "{{.Slug}}"},
	})
	ctx := context.Background()
	slug := "lbl-" + randHex(t)
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug, Limits: map[string]int64{"storage_gb": 5}})
	bkt := "tnt-it-" + slug
	cleanupBucket(t, p, bkt)

	err := p.Provision(ctx, ten)
	if err != nil && strings.Contains(err.Error(), "ownership: object") {
		// fake-gcs-server does not persist bucket labels: the plugin must
		// refuse to run unmarked rather than lose track of ownership.
		t.Skipf("endpoint does not support bucket labels (handled): %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Provision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	b, err := p.gcs.getBucket(ctx, bkt)
	if err != nil {
		t.Fatal(err)
	}
	if b.Labels[LabelTenantID] != ten.ID || b.Labels[LabelQuotaGB] != "5" || b.Labels["slug"] != slug {
		t.Fatalf("labels %v", b.Labels)
	}
	putObject(t, p, bkt, "a.txt", "a")

	p.cfg.OnDeprovision = DeprovisionRetain
	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	b, err = p.gcs.getBucket(ctx, bkt)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Labels[LabelTenantID]; ok || b.Labels[LabelDeletedTenantID] != ten.ID {
		t.Fatalf("labels after retain %v", b.Labels)
	}
}

func TestIntegrationPrefix(t *testing.T) {
	shared := "tnt-it-shared-" + randHex(t)
	setup, _ := newIntegrationPlugin(t, map[string]any{"ownership": "object"})
	ctx := context.Background()
	if err := setup.gcs.createBucket(ctx, setup.cfg.Project, map[string]any{"name": shared}); err != nil {
		t.Fatal(err)
	}
	cleanupBucket(t, setup, shared)

	p, reg := newIntegrationPlugin(t, map[string]any{"mode": "prefix", "bucket": shared, "quota_from_limit": "storage_gb"})
	acme := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Limits: map[string]int64{"storage_gb": 3}})
	beta := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "beta"})
	for _, ten := range []sdk.Tenant{acme, acme, beta} {
		if err := p.Provision(ctx, ten); err != nil {
			t.Fatal(err)
		}
	}
	m, owner := readMarkerOf(t, p, shared, "tenant-acme/"+ownerObject)
	if m == nil || owner != acme.ID || m.Metadata[LabelQuotaGB] != "3" {
		t.Fatalf("marker %+v %q", m, owner)
	}
	putObject(t, p, shared, "tenant-acme/a", "1")
	putObject(t, p, shared, "tenant-acme/d/b", "2")
	putObject(t, p, shared, "tenant-beta/a", "3")

	for range 2 {
		if err := p.Deprovision(ctx, acme); err != nil {
			t.Fatal(err)
		}
	}
	if n := countObjects(t, p, shared, "tenant-acme/"); n != 0 {
		t.Fatalf("%d objects left under acme", n)
	}
	if n := countObjects(t, p, shared, "tenant-beta/"); n != 2 {
		t.Fatalf("beta objects touched: %d", n)
	}

	// An unmarked prefix holding data is neither adopted nor deleted.
	putObject(t, p, shared, "tenant-acme/stray", "x")
	if err := p.Provision(ctx, acme); err == nil || !strings.Contains(err.Error(), "not managed") {
		t.Fatalf("provision over unmanaged prefix: %v", err)
	}
	if err := p.Deprovision(ctx, acme); err != nil || countObjects(t, p, shared, "tenant-acme/") != 1 {
		t.Fatalf("deprovision touched unmanaged prefix: %v", err)
	}

	p.cfg.OnDeprovision = DeprovisionRetain
	if err := p.Deprovision(ctx, beta); err != nil {
		t.Fatal(err)
	}
	if o, _ := readMarkerOf(t, p, shared, "tenant-beta/"+ownerObject); o != nil {
		t.Fatal("owner marker still present")
	}
	beta2 := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "beta"})
	if err := p.Provision(ctx, beta2); err == nil || !strings.Contains(err.Error(), "retained") {
		t.Fatalf("provision over retained prefix: %v", err)
	}
}

func TestIntegrationRoute(t *testing.T) {
	p, reg := newIntegrationPlugin(t, map[string]any{"name_template": "tnt-it-{{.Slug}}", "ownership": "object"})
	acme := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reg.Mux.ServeHTTP(w, r.WithContext(sdk.WithPrincipal(r.Context(), &sdk.Principal{Subject: "admin"})))
	}))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/tenants/" + acme.Slug)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var info TenantInfo
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &info) != nil {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if info.Bucket != "tnt-it-acme" || info.Project != p.cfg.Project || info.Mode != ModeBucket {
		t.Fatalf("info %+v", info)
	}
}
