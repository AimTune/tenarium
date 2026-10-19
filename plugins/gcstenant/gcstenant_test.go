package gcstenant

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

func TestSanitizeName(t *testing.T) {
	for in, want := range map[string]string{
		"tenant-acme":          "tenant-acme",
		"Tenant_Acme Corp.":    "tenant-acme-corp",
		"a..b--c__d":           "a-b-c-d",
		"--x--":                "x",
		"ümlaut":               "mlaut",
		"tenant-google-inc":    "tenant-ggl-inc",
		"goog-thing":           "t-goog-thing",
		"googlers":             "gglrs",
		"10.0.0.1":             "10-0-0-1",
		"":                     "",
		`x"; rm -rf /; echo y`: "x-rm-rf-echo-y",
	} {
		if got := SanitizeName(in); got != want {
			t.Errorf("SanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRenderNameLimits(t *testing.T) {
	tmpl, err := parseNameTemplate(DefaultNameTemplate)
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("very-long-slug-", 10)
	a := sdk.Tenant{ID: "11111111-1111-1111-1111-111111111111", Slug: long}
	b := sdk.Tenant{ID: "22222222-2222-2222-2222-222222222222", Slug: long}
	na, err := renderName(tmpl, a)
	if err != nil {
		t.Fatal(err)
	}
	nb, err := renderName(tmpl, b)
	if err != nil {
		t.Fatal(err)
	}
	if na == nb {
		t.Fatalf("long names collide: %q", na)
	}
	for _, n := range []string{na, nb} {
		if len(n) > maxNameLen || !strings.HasPrefix(n, "tenant-very-long-slug") {
			t.Errorf("bad shortened name %q", n)
		}
		if err := checkBucketName(n); err != nil {
			t.Error(err)
		}
	}
	if again, _ := renderName(tmpl, a); again != na {
		t.Fatalf("name not stable: %q vs %q", again, na)
	}

	short, err := parseNameTemplate("{{.Slug}}")
	if err != nil {
		t.Fatal(err)
	}
	n, err := renderName(short, sdk.Tenant{ID: "x", Slug: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if len(n) < minNameLen || !strings.HasPrefix(n, "a-") || checkBucketName(n) != nil {
		t.Fatalf("short name %q", n)
	}
}

func TestLabelValue(t *testing.T) {
	id := "0192f5e4-7c1a-7b3e-9a6f-1d2c3b4a5f60"
	if LabelValue(id) != id {
		t.Fatalf("uuid changed: %q", LabelValue(id))
	}
	v1, v2 := LabelValue("Tenant:ONE"), LabelValue("Tenant:TWO")
	if v1 == v2 || !strings.HasPrefix(v1, "sha256-") || len(v1) > maxLabelLen || !labelValueRE.MatchString(v1) {
		t.Fatalf("label values %q %q", v1, v2)
	}
	if got := sanitizeLabelValue("Acme Corp. GmbH"); got != "acme_corp__gmbh" {
		t.Fatalf("sanitizeLabelValue = %q", got)
	}
}

func TestConfigValidation(t *testing.T) {
	no := false
	base := func(c Config) Config {
		if c.Project == "" && c.Mode != ModePrefix {
			c.Project = "proj"
		}
		return c
	}
	for _, tc := range []struct {
		cfg     Config
		wantErr string
	}{
		{base(Config{}), ""},
		{base(Config{Endpoint: "http://localhost:4443/", Anonymous: true}), ""},
		{Config{Mode: ModePrefix, Bucket: "shared-bucket"}, ""},
		{base(Config{Endpoint: "localhost:4443"}), "endpoint"},
		{base(Config{Endpoint: "http://localhost/storage/v1"}), "endpoint"},
		{base(Config{CredentialsFile: "a", CredentialsJSON: "{}"}), "only one"},
		{base(Config{Anonymous: true, CredentialsJSON: "{}"}), "anonymous"},
		{Config{}, "project is required"},
		{base(Config{Mode: "zone"}), "mode"},
		{base(Config{OnDeprovision: "archive"}), "on_deprovision"},
		{base(Config{Ownership: "tags"}), "ownership"},
		{base(Config{LifecycleExpireDays: -1}), "lifecycle_expire_days"},
		{base(Config{StorageClass: "glacier"}), "storage_class"},
		{base(Config{StorageClass: "nearline"}), ""},
		{base(Config{PublicAccessPrevention: "on"}), "public_access_prevention"},
		{Config{Mode: ModePrefix}, "bucket is required"},
		{Config{Mode: ModePrefix, Bucket: "Bad_Bucket"}, "bucket:"},
		{Config{Mode: ModePrefix, Bucket: "my-google-data"}, "google"},
		{Config{Mode: ModePrefix, Bucket: "shared", Versioning: true}, "versioning is only supported in bucket mode"},
		{Config{Mode: ModePrefix, Bucket: "shared", LifecycleExpireDays: 3}, "lifecycle_expire_days"},
		{Config{Mode: ModePrefix, Bucket: "shared", Ownership: "object"}, "ownership"},
		{Config{Mode: ModePrefix, Bucket: "shared", UniformBucketLevelAccess: &no}, "uniform_bucket_level_access"},
		{Config{Mode: ModePrefix, Bucket: "shared", Labels: map[string]string{"a": "b"}}, "labels"},
		{base(Config{Bucket: "shared"}), "only used in prefix mode"},
		{base(Config{NameTemplate: "t-{{.Slug"}), "name_template"},
		{base(Config{NameTemplate: "t-{{.Nope}}"}), "name_template"},
		{base(Config{NameTemplate: "{{if false}}x{{end}}"}), "empty name"},
		{base(Config{NameTemplate: "static-name"}), "must depend on the tenant"},
		{base(Config{Labels: map[string]string{"Env": "x"}}), "invalid key"},
		{base(Config{Labels: map[string]string{"tenarium-x": "x"}}), "reserved"},
		{base(Config{Labels: map[string]string{"slug": "{{.Nope}}"}}), "labels.slug"},
		{base(Config{Labels: map[string]string{"slug": "{{.Slug}}", "env": "prod"}}), ""},
	} {
		p := &Plugin{cfg: tc.cfg}
		err := p.validate()
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("%+v: unexpected error %v", tc.cfg, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%+v: error %v, want containing %q", tc.cfg, err, tc.wantErr)
		}
	}

	p := &Plugin{cfg: base(Config{})}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	c := p.cfg
	if c.Mode != ModeBucket || c.OnDeprovision != DeprovisionDelete || c.Ownership != OwnershipLabels ||
		c.NameTemplate != DefaultNameTemplate || c.Endpoint != DefaultEndpoint || !*c.UniformBucketLevelAccess {
		t.Fatalf("defaults not applied: %+v", c)
	}
	tg, err := p.target(sdk.Tenant{ID: "id", Slug: "acme-corp"})
	if err != nil || tg.Bucket != "tenant-acme-corp" || tg.Prefix != "" {
		t.Fatalf("target = %+v, %v", tg, err)
	}

	p = &Plugin{cfg: Config{Mode: ModePrefix, Bucket: "shared"}}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	if p.cfg.Ownership != OwnershipObject {
		t.Fatalf("prefix ownership %q", p.cfg.Ownership)
	}
	tg, err = p.target(sdk.Tenant{ID: "id", Slug: "acme"})
	if err != nil || tg.Bucket != "shared" || tg.Prefix != "tenant-acme/" {
		t.Fatalf("target = %+v, %v", tg, err)
	}
}

func TestConfigSchemaCompiles(t *testing.T) {
	m := (&Plugin{}).Manifest()
	if m.ID != "gcs-tenant" {
		t.Fatalf("id %q", m.ID)
	}
	s, err := schema.Compile(m.ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(map[string]any{"project": "p", "mode": "prefix", "bucket": "x", "labels": map[string]any{"a": "b"}}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []map[string]any{
		{"mode": "zone"},
		{"storage_class": "GLACIER"},
		{"unknown": true},
		{"labels": map[string]any{"a": 1}},
	} {
		if err := s.Validate(bad); err == nil {
			t.Errorf("expected schema error for %v", bad)
		}
	}
}

func TestInitRegisters(t *testing.T) {
	reg := sdktest.NewRegistrar(map[string]any{"endpoint": "http://localhost:9", "anonymous": true, "project": "p"})
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if len(reg.Provisioners) != 1 || reg.Provisioners[0].Name() != "gcs" {
		t.Fatalf("provisioners %v", reg.Provisioners)
	}
	if len(reg.Routes) != 1 || reg.Routes[0] != "GET /tenants/{tenant}" {
		t.Fatalf("routes %v", reg.Routes)
	}
	var _ sdk.HealthChecker = p
}

// newTestPlugin initializes the plugin against the fake server.
func newTestPlugin(t *testing.T, f *fakeGCS, cfg map[string]any) (*Plugin, *sdktest.Registrar) {
	t.Helper()
	full := map[string]any{"endpoint": f.srv.URL, "anonymous": true, "project": "proj"}
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
	p.now = func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }
	return p, reg
}

func TestBucketLabelsLifecycle(t *testing.T) {
	f := newFakeGCS(t)
	p, reg := newTestPlugin(t, f, map[string]any{
		"versioning": true, "lifecycle_expire_days": 30, "storage_class": "NEARLINE",
		"location": "EU", "public_access_prevention": "enforced", "quota_from_limit": "storage_gb",
		"labels": map[string]any{"slug": "{{.Slug}}", "env": "Prod"},
	})
	ctx := context.Background()
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Limits: map[string]int64{"storage_gb": 25}})

	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatalf("deprovision of never-provisioned tenant: %v", err)
	}
	for range 2 {
		if err := p.Provision(ctx, ten); err != nil {
			t.Fatalf("provision: %v", err)
		}
	}
	b := f.bucket("tenant-acme")
	if b == nil {
		t.Fatal("bucket not created")
	}
	if b.Metageneration != 1 {
		t.Errorf("second provision patched the bucket (metageneration %d)", b.Metageneration)
	}
	if b.Labels[LabelTenantID] != ten.ID || b.Labels[LabelQuotaGB] != "25" || b.Labels["slug"] != "acme" || b.Labels["env"] != "prod" {
		t.Errorf("labels = %v", b.Labels)
	}
	if !b.Versioning || b.StorageClass != "NEARLINE" || b.Location != "EU" {
		t.Errorf("bucket = %+v", b)
	}
	if b.IAM["publicAccessPrevention"] != "enforced" || b.IAM["uniformBucketLevelAccess"].(map[string]any)["enabled"] != true {
		t.Errorf("iam = %v", b.IAM)
	}
	if len(b.Lifecycle) != 2 {
		t.Errorf("lifecycle = %v", b.Lifecycle)
	}

	// An operator adds a rule of their own, and the plan's limit is removed:
	// the next Provision keeps the rule and drops the quota label.
	f.mu.Lock()
	b.Lifecycle = append(b.Lifecycle, map[string]any{
		"action": map[string]any{"type": "SetStorageClass", "storageClass": "COLDLINE"}, "condition": map[string]any{"age": 90.0},
	})
	f.mu.Unlock()
	p.cfg.LifecycleExpireDays = 7
	ten.Limits = nil
	reg.HostImpl.AddTenant(ten)
	if err := p.Provision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Labels[LabelQuotaGB]; ok {
		t.Errorf("quota label not removed: %v", b.Labels)
	}
	if len(b.Lifecycle) != 3 {
		t.Fatalf("lifecycle = %v", b.Lifecycle)
	}
	raw, _ := json.Marshal(b.Lifecycle)
	if !strings.Contains(string(raw), "SetStorageClass") || !strings.Contains(string(raw), `"age":7`) ||
		!strings.Contains(string(raw), `"daysSinceNoncurrentTime":7`) || strings.Contains(string(raw), `"age":30`) {
		t.Errorf("lifecycle = %s", raw)
	}

	f.put("tenant-acme", "a.txt", "1")
	f.put("tenant-acme", "a.txt", "2") // noncurrent generation
	f.put("tenant-acme", "dir/b.txt", "b")
	for range 2 {
		if err := p.Deprovision(ctx, ten); err != nil {
			t.Fatalf("deprovision: %v", err)
		}
	}
	if f.bucket("tenant-acme") != nil {
		t.Fatal("bucket still exists after delete")
	}
}

func TestBucketOwnership(t *testing.T) {
	f := newFakeGCS(t)
	p, reg := newTestPlugin(t, f, nil)
	ctx := context.Background()
	acme := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})

	// Bucket of another tenant: refused, and never deleted.
	f.addBucket("tenant-acme", map[string]string{LabelTenantID: "someone-else"})
	f.put("tenant-acme", "x", "data")
	if err := p.Provision(ctx, acme); err == nil || !strings.Contains(err.Error(), "another tenant") {
		t.Fatalf("provision over foreign bucket: %v", err)
	}
	if err := p.Deprovision(ctx, acme); err != nil || f.bucket("tenant-acme") == nil {
		t.Fatalf("deprovision touched a foreign bucket: %v", err)
	}

	// Unmarked bucket with data: refused, never deleted.
	f.addBucket("tenant-acme", nil)
	f.put("tenant-acme", "x", "data")
	if err := p.Provision(ctx, acme); err == nil || !strings.Contains(err.Error(), "not managed by tenarium") {
		t.Fatalf("provision over unmanaged bucket: %v", err)
	}
	if err := p.Deprovision(ctx, acme); err != nil || f.count("tenant-acme") != 1 {
		t.Fatalf("deprovision touched an unmanaged bucket: %v", err)
	}

	// Empty unmarked bucket (interrupted provision): adopted.
	f.addBucket("tenant-acme", nil)
	if err := p.Provision(ctx, acme); err != nil {
		t.Fatal(err)
	}
	if f.bucket("tenant-acme").Labels[LabelTenantID] != acme.ID {
		t.Fatalf("labels %v", f.bucket("tenant-acme").Labels)
	}
	// The owner label is authoritative: once it changes, the bucket is no
	// longer this tenant's.
	f.mu.Lock()
	f.buckets["tenant-acme"].Labels[LabelTenantID] = "stale"
	f.mu.Unlock()
	if err := p.Provision(ctx, acme); err == nil {
		t.Fatal("expected conflict for relabeled bucket")
	}
}

func TestBucketRetain(t *testing.T) {
	f := newFakeGCS(t)
	p, reg := newTestPlugin(t, f, map[string]any{"on_deprovision": "retain"})
	ctx := context.Background()
	acme := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	if err := p.Provision(ctx, acme); err != nil {
		t.Fatal(err)
	}
	f.put("tenant-acme", "data", "x")
	for range 2 {
		if err := p.Deprovision(ctx, acme); err != nil {
			t.Fatal(err)
		}
	}
	b := f.bucket("tenant-acme")
	if b == nil || f.count("tenant-acme") != 1 {
		t.Fatal("retained bucket or data missing")
	}
	if _, ok := b.Labels[LabelTenantID]; ok || b.Labels[LabelDeletedTenantID] != acme.ID || b.Labels[LabelDeletedAt] != "2026-01-02t03-04-05z" {
		t.Fatalf("labels %v", b.Labels)
	}
	again := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	if err := p.Provision(ctx, again); err == nil || !strings.Contains(err.Error(), "retained from deleted tenant") {
		t.Fatalf("provision over retained bucket: %v", err)
	}
}

func TestBucketKeep(t *testing.T) {
	f := newFakeGCS(t)
	p, reg := newTestPlugin(t, f, map[string]any{"on_deprovision": "keep"})
	ctx := context.Background()
	acme := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	if err := p.Provision(ctx, acme); err != nil {
		t.Fatal(err)
	}
	if err := p.Deprovision(ctx, acme); err != nil {
		t.Fatal(err)
	}
	if b := f.bucket("tenant-acme"); b == nil || b.Labels[LabelTenantID] != acme.ID {
		t.Fatal("keep changed the bucket")
	}
}

func TestBucketLabelsNotPersisted(t *testing.T) {
	f := newFakeGCS(t)
	f.dropLabels = true
	p, reg := newTestPlugin(t, f, nil)
	acme := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	err := p.Provision(context.Background(), acme)
	if err == nil || !strings.Contains(err.Error(), "ownership: object") {
		t.Fatalf("expected label support error, got %v", err)
	}
}

func TestBucketObjectOwnership(t *testing.T) {
	f := newFakeGCS(t)
	f.dropLabels = true
	p, reg := newTestPlugin(t, f, map[string]any{"ownership": "object", "versioning": true, "quota_from_limit": "storage_gb"})
	ctx := context.Background()
	acme := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Limits: map[string]int64{"storage_gb": 5}})
	other := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"}) // same name, different tenant

	for range 2 {
		if err := p.Provision(ctx, acme); err != nil {
			t.Fatal(err)
		}
	}
	m := f.object("tenant-acme", ownerObject)
	if m == nil || string(m.Content) != acme.ID || m.Metadata[LabelQuotaGB] != "5" {
		t.Fatalf("marker %+v", m)
	}
	gen := m.Gen
	acme.Limits["storage_gb"] = 10
	reg.HostImpl.AddTenant(acme)
	if err := p.Provision(ctx, acme); err != nil {
		t.Fatal(err)
	}
	if m := f.object("tenant-acme", ownerObject); m.Gen == gen || m.Metadata[LabelQuotaGB] != "10" {
		t.Fatalf("marker not updated: %+v", m)
	}

	// Another tenant whose name renders to this bucket is refused.
	if err := p.Provision(ctx, other); err == nil || !strings.Contains(err.Error(), "another tenant") {
		t.Fatalf("provision of other tenant: %v", err)
	}
	if err := p.Deprovision(ctx, other); err != nil || f.bucket("tenant-acme") == nil {
		t.Fatalf("deprovision of other tenant: %v", err)
	}

	f.put("tenant-acme", "a", "1")
	f.put("tenant-acme", "a", "2")
	for range 2 {
		if err := p.Deprovision(ctx, acme); err != nil {
			t.Fatal(err)
		}
	}
	if f.bucket("tenant-acme") != nil {
		t.Fatal("bucket not deleted")
	}

	// retain swaps the owner marker for a retained marker.
	p.cfg.OnDeprovision = DeprovisionRetain
	if err := p.Provision(ctx, acme); err != nil {
		t.Fatal(err)
	}
	f.put("tenant-acme", "a", "1")
	if err := p.Deprovision(ctx, acme); err != nil {
		t.Fatal(err)
	}
	if f.object("tenant-acme", ownerObject) != nil || f.object("tenant-acme", retainedObject) == nil || f.object("tenant-acme", "a") == nil {
		t.Fatal("retain did not swap markers")
	}
	again := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	if err := p.Provision(ctx, again); err == nil || !strings.Contains(err.Error(), "retained from deleted tenant") {
		t.Fatalf("provision over retained bucket: %v", err)
	}
}

func TestPrefixMode(t *testing.T) {
	f := newFakeGCS(t)
	f.addBucket("shared", nil)
	p, reg := newTestPlugin(t, f, map[string]any{"mode": "prefix", "bucket": "shared", "quota_from_limit": "storage_gb"})
	ctx := context.Background()
	acme := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Limits: map[string]int64{"storage_gb": 3}})
	beta := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "beta"})

	if err := p.Health(ctx); err != nil {
		t.Fatal(err)
	}
	for _, ten := range []sdk.Tenant{acme, acme, beta} {
		if err := p.Provision(ctx, ten); err != nil {
			t.Fatal(err)
		}
	}
	m := f.object("shared", "tenant-acme/"+ownerObject)
	if m == nil || string(m.Content) != acme.ID || m.Metadata[LabelQuotaGB] != "3" {
		t.Fatalf("marker %+v", m)
	}
	f.put("shared", "tenant-acme/a", "1")
	f.put("shared", "tenant-acme/d/b", "2")
	f.put("shared", "tenant-beta/a", "3")

	for range 2 {
		if err := p.Deprovision(ctx, acme); err != nil {
			t.Fatal(err)
		}
	}
	if f.count("shared") != 2 || f.object("shared", "tenant-beta/a") == nil {
		t.Fatalf("delete removed the wrong objects: %d left", f.count("shared"))
	}

	// Unmarked prefix with data is refused.
	f.put("shared", "tenant-acme/stray", "x")
	if err := p.Provision(ctx, acme); err == nil || !strings.Contains(err.Error(), "not managed") {
		t.Fatalf("provision over unmanaged prefix: %v", err)
	}
	if err := p.Deprovision(ctx, acme); err != nil || f.object("shared", "tenant-acme/stray") == nil {
		t.Fatalf("deprovision touched an unmanaged prefix: %v", err)
	}

	// retain
	p.cfg.OnDeprovision = DeprovisionRetain
	if err := p.Deprovision(ctx, beta); err != nil {
		t.Fatal(err)
	}
	if f.object("shared", "tenant-beta/"+ownerObject) != nil || f.object("shared", "tenant-beta/"+retainedObject) == nil || f.object("shared", "tenant-beta/a") == nil {
		t.Fatal("retain did not swap markers")
	}
	beta2 := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "beta"})
	if err := p.Provision(ctx, beta2); err == nil || !strings.Contains(err.Error(), "retained") {
		t.Fatalf("provision over retained prefix: %v", err)
	}

	// Missing shared bucket.
	p.cfg.Bucket = "missing"
	gamma := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "gamma"})
	p.cfg.Mode = ModePrefix
	if err := p.Health(ctx); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("health: %v", err)
	}
	if err := p.Provision(ctx, gamma); err == nil {
		t.Fatal("provision into a missing bucket succeeded")
	}
}

func TestRoute(t *testing.T) {
	f := newFakeGCS(t)
	_, reg := newTestPlugin(t, f, nil)
	acme := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	other := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "other"})
	get := func(path string, principal *sdk.Principal) (int, string) {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if principal != nil {
			req = req.WithContext(sdk.WithPrincipal(req.Context(), principal))
		}
		rec := httptest.NewRecorder()
		reg.Mux.ServeHTTP(rec, req)
		body, _ := io.ReadAll(rec.Result().Body)
		return rec.Code, string(body)
	}
	code, body := get("/tenants/acme", &sdk.Principal{Subject: "admin"})
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	var info TenantInfo
	if err := json.Unmarshal([]byte(body), &info); err != nil {
		t.Fatal(err)
	}
	if info != (TenantInfo{Mode: ModeBucket, Bucket: "tenant-acme", Project: "proj", URL: "gs://tenant-acme/"}) {
		t.Fatalf("info %+v", info)
	}
	if code, _ := get("/tenants/acme", &sdk.Principal{Subject: "u", TenantID: other.ID}); code != http.StatusNotFound {
		t.Fatalf("foreign tenant status %d", code)
	}
	if code, _ := get("/tenants/acme", nil); code != http.StatusNotFound {
		t.Fatalf("anonymous status %d", code)
	}
	if code, _ := get("/tenants/"+acme.ID, &sdk.Principal{Subject: "u", TenantID: acme.ID}); code != http.StatusOK {
		t.Fatalf("own tenant status %d", code)
	}
	if code, _ := get("/tenants/missing", &sdk.Principal{Subject: "admin"}); code != http.StatusNotFound {
		t.Fatalf("missing status %d", code)
	}
}

func TestLifecycleRules(t *testing.T) {
	p := &Plugin{cfg: Config{LifecycleExpireDays: 10}}
	b := &bucket{}
	rules, changed := p.lifecycleRules(b)
	if !changed || len(rules) != 1 {
		t.Fatalf("rules %v", rules)
	}
	raw, _ := json.Marshal(map[string]any{"lifecycle": map[string]any{"rule": rules}})
	_ = json.Unmarshal(raw, b)
	if _, changed := p.lifecycleRules(b); changed {
		t.Fatal("rules not stable")
	}
	// Managed-looking duplicates are collapsed.
	b.Lifecycle.Rule = append(b.Lifecycle.Rule, b.Lifecycle.Rule[0])
	if rules, changed := p.lifecycleRules(b); !changed || len(rules) != 1 {
		t.Fatalf("duplicates kept: %v", rules)
	}
	if isManagedRule(map[string]any{"action": map[string]any{"type": "Delete"}, "condition": map[string]any{"age": 1.0, "matchesPrefix": []any{"x"}}}) {
		t.Fatal("rule with extra conditions considered managed")
	}
}

// TestCredentialsJSON runs the service account flow against a fake token
// endpoint and checks that GCS requests carry the bearer token.
func TestCredentialsJSON(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	tokens := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || r.Form.Get("assertion") == "" {
			http.Error(w, "bad grant", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"tok-123","token_type":"Bearer","expires_in":3600}`)
	}))
	defer tokens.Close()
	creds, _ := json.Marshal(map[string]string{
		"type": "service_account", "project_id": "proj", "private_key_id": "k1",
		"private_key": string(pemKey), "client_email": "sa@proj.iam.gserviceaccount.com",
		"token_uri": tokens.URL,
	})

	f := newFakeGCS(t)
	f.wantAuth = "Bearer tok-123"
	for _, viaFile := range []bool{false, true} {
		cfg := map[string]any{"endpoint": f.srv.URL, "project": "proj"}
		if viaFile {
			path := filepath.Join(t.TempDir(), "sa.json")
			if err := os.WriteFile(path, creds, 0o600); err != nil {
				t.Fatal(err)
			}
			cfg["credentials_file"] = path
		} else {
			cfg["credentials_json"] = string(creds)
		}
		p := &Plugin{}
		if err := p.Init(context.Background(), sdktest.NewRegistrar(cfg)); err != nil {
			t.Fatal(err)
		}
		if err := p.Health(context.Background()); err != nil {
			t.Fatalf("health with credentials (file=%v): %v", viaFile, err)
		}
	}

	for _, bad := range []string{`{"type":"weird"}`, `not json`} {
		err := (&Plugin{}).Init(context.Background(), sdktest.NewRegistrar(map[string]any{"project": "p", "credentials_json": bad}))
		if err == nil || !strings.Contains(err.Error(), "credentials_json") {
			t.Errorf("credentials_json %q: %v", bad, err)
		}
	}
	err = (&Plugin{}).Init(context.Background(), sdktest.NewRegistrar(map[string]any{"project": "p", "credentials_file": filepath.Join(t.TempDir(), "missing.json")}))
	if err == nil || !strings.Contains(err.Error(), "credentials_file") {
		t.Errorf("missing credentials_file: %v", err)
	}
}
