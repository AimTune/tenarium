package s3tenant

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
	"github.com/minio/minio-go/v7"
)

// Integration tests run against an S3-compatible server named by
// TENARIUM_TEST_S3_ENDPOINT (host:port, plain HTTP), e.g. SeaweedFS or
// MinIO. Credentials default to "any"/"any" and can be overridden with
// TENARIUM_TEST_S3_ACCESS_KEY / TENARIUM_TEST_S3_SECRET_KEY.

func testEndpoint(t *testing.T) string {
	t.Helper()
	e := os.Getenv("TENARIUM_TEST_S3_ENDPOINT")
	if e == "" {
		t.Skip("TENARIUM_TEST_S3_ENDPOINT not set")
	}
	return e
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func randHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// newPlugin initializes the plugin against the test server with cfg merged
// over connection defaults.
func newPlugin(t *testing.T, cfg map[string]any) (*Plugin, *sdktest.Registrar) {
	t.Helper()
	full := map[string]any{
		"endpoint":   testEndpoint(t),
		"access_key": envOr("TENARIUM_TEST_S3_ACCESS_KEY", "any"),
		"secret_key": envOr("TENARIUM_TEST_S3_SECRET_KEY", "any"),
		"region":     "us-east-1",
		"secure":     false,
	}
	for k, v := range cfg {
		full[k] = v
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

// newTenant adds a tenant with a unique slug.
func newTenant(reg *sdktest.Registrar, slug string) sdk.Tenant {
	return reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug, Name: slug})
}

// cleanupBucket force-deletes bucket at the end of the test.
func cleanupBucket(t *testing.T, p *Plugin, bucket string) {
	t.Cleanup(func() {
		ctx := context.Background()
		if ok, _ := p.client.BucketExists(ctx, bucket); !ok {
			return
		}
		if err := p.removeAll(ctx, bucket, "", ""); err != nil {
			t.Logf("cleanup %s: %v", bucket, err)
		}
		if err := p.client.RemoveBucket(ctx, bucket); err != nil {
			t.Logf("cleanup %s: %v", bucket, err)
		}
	})
}

func putObject(t *testing.T, p *Plugin, bucket, key, body string) {
	t.Helper()
	if err := p.putMarker(context.Background(), bucket, key, "text/plain", []byte(body), nil); err != nil {
		t.Fatalf("put %s/%s: %v", bucket, key, err)
	}
}

func countObjects(t *testing.T, p *Plugin, bucket, prefix string) int {
	t.Helper()
	versions, err := p.versioned(context.Background(), bucket)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for o := range p.client.ListObjects(context.Background(), bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true, WithVersions: versions}) {
		if o.Err != nil {
			t.Fatal(o.Err)
		}
		n++
	}
	return n
}

func bucketExists(t *testing.T, p *Plugin, bucket string) bool {
	t.Helper()
	ok, err := p.client.BucketExists(context.Background(), bucket)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

// unsupported reports whether err means the server lacks a feature.
func unsupported(err error) bool {
	if err == nil {
		return false
	}
	switch errCode(err) {
	case "NotImplemented", "InvalidRequest", "MethodNotAllowed", "NotSupported":
		return true
	}
	s := err.Error()
	return strings.Contains(s, "NotImplemented") || strings.Contains(s, "not implemented") ||
		strings.Contains(s, "not supported")
}

func TestIntegrationBucketDelete(t *testing.T) {
	p, reg := newPlugin(t, map[string]any{
		"name_template":    "tnt-{{.Slug}}",
		"quota_from_limit": "storage_gb",
	})
	ctx := context.Background()
	slug := "del-" + randHex(t)
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug, Limits: map[string]int64{"storage_gb": 25}})
	bucket := "tnt-" + slug
	cleanupBucket(t, p, bucket)

	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatalf("deprovision of never-provisioned tenant: %v", err)
	}
	for range 2 {
		if err := p.Provision(ctx, ten); err != nil {
			t.Fatalf("provision: %v", err)
		}
	}
	if !bucketExists(t, p, bucket) {
		t.Fatal("bucket not created")
	}
	tags, err := p.bucketTags(ctx, bucket)
	if err != nil {
		t.Fatal(err)
	}
	if tags[TagTenantID] != ten.ID || tags[TagQuotaGB] != "25" {
		t.Fatalf("tags = %v", tags)
	}

	putObject(t, p, bucket, "a.txt", "a")
	putObject(t, p, bucket, "dir/b.txt", "b")
	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatalf("deprovision: %v", err)
	}
	if bucketExists(t, p, bucket) {
		t.Fatal("bucket still exists after delete")
	}
	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatalf("second deprovision: %v", err)
	}
}

func TestIntegrationBucketVersioning(t *testing.T) {
	p, reg := newPlugin(t, map[string]any{"versioning": true})
	ctx := context.Background()
	ten := newTenant(reg, "ver-"+randHex(t))
	tg, _ := p.target(ten)
	cleanupBucket(t, p, tg.Bucket)

	if err := p.Provision(ctx, ten); err != nil {
		if unsupported(err) {
			t.Skipf("server does not support bucket versioning: %v", err)
		}
		t.Fatal(err)
	}
	v, err := p.client.GetBucketVersioning(ctx, tg.Bucket)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Enabled() {
		t.Fatalf("versioning = %+v", v)
	}
	if err := p.Provision(ctx, ten); err != nil {
		t.Fatalf("second provision: %v", err)
	}
	// Two versions of one object, plus a delete marker.
	putObject(t, p, tg.Bucket, "doc", "v1")
	putObject(t, p, tg.Bucket, "doc", "v2")
	if err := p.client.RemoveObject(ctx, tg.Bucket, "doc", minio.RemoveObjectOptions{}); err != nil {
		t.Fatal(err)
	}
	if n := countObjects(t, p, tg.Bucket, ""); n < 2 {
		t.Fatalf("expected versions to be listed, got %d", n)
	}
	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatalf("deprovision: %v", err)
	}
	if bucketExists(t, p, tg.Bucket) {
		t.Fatal("versioned bucket still exists after delete")
	}
}

func TestIntegrationBucketObjectLock(t *testing.T) {
	p, reg := newPlugin(t, map[string]any{"object_lock": true})
	ctx := context.Background()
	ten := newTenant(reg, "lock-"+randHex(t))
	tg, _ := p.target(ten)
	cleanupBucket(t, p, tg.Bucket)

	if err := p.Provision(ctx, ten); err != nil {
		if unsupported(err) {
			t.Skipf("server does not support object lock: %v", err)
		}
		t.Fatal(err)
	}
	enabled, _, _, _, err := p.client.GetObjectLockConfig(ctx, tg.Bucket)
	if err != nil || enabled != "Enabled" {
		if unsupported(err) || errCode(err) == "ObjectLockConfigurationNotFoundError" || err == nil {
			t.Skipf("server accepted the bucket but does not report object lock (enabled=%q, err=%v)", enabled, err)
		}
		t.Fatal(err)
	}
	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatalf("deprovision: %v", err)
	}
}

func TestIntegrationBucketLifecycle(t *testing.T) {
	p, reg := newPlugin(t, map[string]any{"lifecycle_expire_days": 7})
	ctx := context.Background()
	ten := newTenant(reg, "lc-"+randHex(t))
	tg, _ := p.target(ten)
	cleanupBucket(t, p, tg.Bucket)

	if err := p.Provision(ctx, ten); err != nil {
		if unsupported(err) {
			t.Skipf("server does not support bucket lifecycle: %v", err)
		}
		t.Fatal(err)
	}
	cfg, err := p.client.GetBucketLifecycle(ctx, tg.Bucket)
	if err != nil {
		if unsupported(err) {
			t.Skipf("server does not support reading bucket lifecycle: %v", err)
		}
		t.Fatal(err)
	}
	found := false
	for _, r := range cfg.Rules {
		if r.ID == lifecycleRuleID && r.Expiration.Days == 7 {
			found = true
		}
	}
	if !found {
		t.Fatalf("lifecycle rule missing: %+v", cfg.Rules)
	}
	if err := p.Provision(ctx, ten); err != nil {
		t.Fatalf("second provision: %v", err)
	}
}

func TestIntegrationBucketPolicy(t *testing.T) {
	p, reg := newPlugin(t, map[string]any{"policy_template": `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": ["*"]},
    "Action": ["s3:GetObject"],
    "Resource": ["arn:aws:s3:::{{.Bucket}}/*"]
  }]
}`})
	ctx := context.Background()
	ten := newTenant(reg, "pol-"+randHex(t))
	tg, _ := p.target(ten)
	cleanupBucket(t, p, tg.Bucket)
	if err := p.Provision(ctx, ten); err != nil {
		if unsupported(err) {
			t.Skipf("server does not support bucket policies: %v", err)
		}
		t.Fatal(err)
	}
	pol, err := p.client.GetBucketPolicy(ctx, tg.Bucket)
	if err != nil {
		if unsupported(err) {
			t.Skipf("server does not support reading bucket policies: %v", err)
		}
		t.Fatal(err)
	}
	if !strings.Contains(pol, tg.Bucket) {
		t.Fatalf("policy %s", pol)
	}
}

func TestIntegrationBucketKeep(t *testing.T) {
	p, reg := newPlugin(t, map[string]any{"on_deprovision": "keep"})
	ctx := context.Background()
	ten := newTenant(reg, "keep-"+randHex(t))
	tg, _ := p.target(ten)
	cleanupBucket(t, p, tg.Bucket)
	if err := p.Provision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	putObject(t, p, tg.Bucket, "a.txt", "a")
	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	if !bucketExists(t, p, tg.Bucket) || countObjects(t, p, tg.Bucket, "") != 1 {
		t.Fatal("keep mode removed data")
	}
	// The bucket stays owned: a new tenant with the same slug cannot adopt it.
	successor := reg.HostImpl.AddTenant(sdk.Tenant{Slug: ten.Slug})
	if err := p.Provision(ctx, successor); err == nil || !strings.Contains(err.Error(), "belongs to another tenant") {
		t.Fatalf("successor provision: %v", err)
	}
}

func TestIntegrationBucketRetain(t *testing.T) {
	p, reg := newPlugin(t, map[string]any{"on_deprovision": "retain"})
	ctx := context.Background()
	ten := newTenant(reg, "ret-"+randHex(t))
	tg, _ := p.target(ten)
	cleanupBucket(t, p, tg.Bucket)
	if err := p.Provision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	putObject(t, p, tg.Bucket, "a.txt", "a")
	for range 2 {
		if err := p.Deprovision(ctx, ten); err != nil {
			t.Fatal(err)
		}
	}
	tags, err := p.bucketTags(ctx, tg.Bucket)
	if err != nil {
		t.Fatal(err)
	}
	if tags[TagTenantID] != "" || tags[TagDeletedAt] == "" || tags[TagDeletedTenantID] != ten.ID {
		t.Fatalf("retained tags = %v", tags)
	}
	if countObjects(t, p, tg.Bucket, "") != 1 {
		t.Fatal("retain mode removed data")
	}
	successor := reg.HostImpl.AddTenant(sdk.Tenant{Slug: ten.Slug})
	err = p.Provision(ctx, successor)
	if err == nil || !strings.Contains(err.Error(), "retained from deleted tenant "+ten.ID) {
		t.Fatalf("successor provision: %v", err)
	}
	// The successor's deprovision must not touch the retained data.
	if err := p.Deprovision(ctx, successor); err != nil {
		t.Fatal(err)
	}
	if countObjects(t, p, tg.Bucket, "") != 1 {
		t.Fatal("successor deprovision removed retained data")
	}
}

func TestIntegrationBucketOwnershipConflict(t *testing.T) {
	p, reg := newPlugin(t, nil)
	ctx := context.Background()
	owner := newTenant(reg, "own-"+randHex(t))
	tg, _ := p.target(owner)
	cleanupBucket(t, p, tg.Bucket)
	if err := p.Provision(ctx, owner); err != nil {
		t.Fatal(err)
	}
	putObject(t, p, tg.Bucket, "a.txt", "a")

	// Another tenant whose name renders to the same bucket.
	other := sdk.Tenant{ID: "other-" + randHex(t), Slug: owner.Slug}
	err := p.Provision(ctx, other)
	if err == nil || !strings.Contains(err.Error(), "belongs to another tenant") {
		t.Fatalf("provision of conflicting tenant: %v", err)
	}
	if err := p.Deprovision(ctx, other); err != nil {
		t.Fatal(err)
	}
	if !bucketExists(t, p, tg.Bucket) || countObjects(t, p, tg.Bucket, "") != 1 {
		t.Fatal("deprovision of another tenant touched the bucket")
	}

	// An untagged, non-empty bucket is not adopted.
	foreign := "foreign-" + randHex(t)
	if err := p.client.MakeBucket(ctx, foreign, minio.MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	cleanupBucket(t, p, foreign)
	putObject(t, p, foreign, "x", "x")
	p2, reg2 := newPlugin(t, map[string]any{"name_template": "{{.Slug}}"})
	ft := reg2.HostImpl.AddTenant(sdk.Tenant{Slug: foreign})
	if err := p2.Provision(ctx, ft); err == nil || !strings.Contains(err.Error(), "not managed by tenarium") {
		t.Fatalf("provision over unmanaged bucket: %v", err)
	}
	if err := p2.Deprovision(ctx, ft); err != nil {
		t.Fatal(err)
	}
	if countObjects(t, p, foreign, "") != 1 {
		t.Fatal("deprovision touched an unmanaged bucket")
	}
}

func TestIntegrationPrefixMode(t *testing.T) {
	endpoint := testEndpoint(t)
	shared := "shared-" + randHex(t)
	// Create the shared bucket with a bootstrap plugin in bucket mode.
	boot, _ := newPlugin(t, nil)
	ctx := context.Background()
	if err := boot.client.MakeBucket(ctx, shared, minio.MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	cleanupBucket(t, boot, shared)

	p, reg := newPlugin(t, map[string]any{"mode": "prefix", "bucket": shared, "quota_from_limit": "storage_gb"})
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "pfx-" + randHex(t), Limits: map[string]int64{"storage_gb": 3}})
	tg, _ := p.target(ten)
	marker := tg.Prefix + ownerObject

	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatalf("deprovision of never-provisioned tenant: %v", err)
	}
	for range 2 {
		if err := p.Provision(ctx, ten); err != nil {
			t.Fatal(err)
		}
	}
	owner, meta, found, err := p.readObject(ctx, shared, marker)
	if err != nil || !found || owner != ten.ID {
		t.Fatalf("marker = %q, %v, %v", owner, found, err)
	}
	if meta[quotaMetaKey] != "3" {
		t.Fatalf("marker metadata = %v", meta)
	}

	// Another tenant whose name collides cannot claim the prefix.
	other := reg.HostImpl.AddTenant(sdk.Tenant{ID: "other-" + randHex(t), Slug: ten.Slug})
	if err := p.Provision(ctx, other); err == nil || !strings.Contains(err.Error(), "belongs to another tenant") {
		t.Fatalf("conflicting provision: %v", err)
	}

	putObject(t, p, shared, tg.Prefix+"a.txt", "a")
	putObject(t, p, shared, tg.Prefix+"dir/b.txt", "b")
	putObject(t, p, shared, "outside.txt", "keep me")
	if err := p.Deprovision(ctx, other); err != nil {
		t.Fatal(err)
	}
	if n := countObjects(t, p, shared, tg.Prefix); n != 3 {
		t.Fatalf("conflicting deprovision changed the prefix: %d objects", n)
	}

	// Route.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reg.Mux.ServeHTTP(w, r.WithContext(sdk.WithPrincipal(r.Context(), &sdk.Principal{Subject: "admin"})))
	}))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/tenants/" + ten.Slug)
	if err != nil {
		t.Fatal(err)
	}
	var info TenantInfo
	_ = json.NewDecoder(resp.Body).Decode(&info)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || info != (TenantInfo{Mode: ModePrefix, Bucket: shared, Prefix: tg.Prefix, Endpoint: endpoint}) {
		t.Fatalf("route: %d %+v", resp.StatusCode, info)
	}

	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	if n := countObjects(t, p, shared, tg.Prefix); n != 0 {
		t.Fatalf("%d objects left under prefix", n)
	}
	if n := countObjects(t, p, shared, "outside.txt"); n != 1 {
		t.Fatal("delete removed data outside the prefix")
	}
	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatalf("second deprovision: %v", err)
	}
}

func TestIntegrationPrefixRetain(t *testing.T) {
	shared := "shared-" + randHex(t)
	boot, _ := newPlugin(t, nil)
	ctx := context.Background()
	if err := boot.client.MakeBucket(ctx, shared, minio.MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	cleanupBucket(t, boot, shared)

	p, reg := newPlugin(t, map[string]any{"mode": "prefix", "bucket": shared, "on_deprovision": "retain"})
	ten := newTenant(reg, "pret-"+randHex(t))
	tg, _ := p.target(ten)
	if err := p.Provision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	putObject(t, p, shared, tg.Prefix+"a.txt", "a")
	for range 2 {
		if err := p.Deprovision(ctx, ten); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, found, _ := p.readObject(ctx, shared, tg.Prefix+ownerObject); found {
		t.Fatal("owner marker still present after retain")
	}
	if n := countObjects(t, p, shared, tg.Prefix+"a.txt"); n != 1 {
		t.Fatal("retain removed data")
	}
	successor := reg.HostImpl.AddTenant(sdk.Tenant{Slug: ten.Slug})
	if err := p.Provision(ctx, successor); err == nil || !strings.Contains(err.Error(), "retained from deleted tenant "+ten.ID) {
		t.Fatalf("successor provision: %v", err)
	}
}

func TestIntegrationRoute(t *testing.T) {
	endpoint := testEndpoint(t)
	_, reg := newPlugin(t, nil)
	acme := newTenant(reg, "acme")
	other := newTenant(reg, "other")

	get := func(path string, principal *sdk.Principal) (*http.Response, string) {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req = req.WithContext(sdk.WithPrincipal(req.Context(), principal))
		rec := httptest.NewRecorder()
		reg.Mux.ServeHTTP(rec, req)
		body, _ := io.ReadAll(rec.Result().Body)
		return rec.Result(), string(body)
	}

	resp, body := get("/tenants/acme", &sdk.Principal{Subject: "admin"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	var info TenantInfo
	if err := json.Unmarshal([]byte(body), &info); err != nil {
		t.Fatal(err)
	}
	if info != (TenantInfo{Mode: ModeBucket, Bucket: "tenant-acme", Endpoint: endpoint}) {
		t.Fatalf("info %+v", info)
	}

	// A principal scoped to another tenant gets 404, not 403.
	resp, _ = get("/tenants/acme", &sdk.Principal{Subject: "u", TenantID: other.ID})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("forbidden status %d", resp.StatusCode)
	}
	resp, _ = get("/tenants/"+acme.ID, &sdk.Principal{Subject: "u", TenantID: acme.ID})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("own tenant status %d", resp.StatusCode)
	}
	resp, _ = get("/tenants/missing", &sdk.Principal{Subject: "admin"})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("missing status %d", resp.StatusCode)
	}
}
