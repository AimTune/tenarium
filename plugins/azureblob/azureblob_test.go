package azureblob

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

// TestSharedKeyVector checks the string-to-sign and signature of a fixed
// request. The expected signature was computed independently with
//
//	printf '<string-to-sign>' | openssl dgst -sha256 -mac HMAC -macopt hexkey:<dev key hex> -binary | base64
func TestSharedKeyVector(t *testing.T) {
	req, err := http.NewRequest(http.MethodPut, "http://127.0.0.1:10000/devstoreaccount1/mycontainer?restype=container&comp=metadata", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("x-ms-date", "Fri, 02 Jan 2026 03:04:05 GMT")
	req.Header.Set("x-ms-version", "2023-11-03")
	req.Header["x-ms-meta-tenarium_tenant_id"] = []string{"t1"}

	wantSTS := "PUT\n\n\n\n\n\n\n\n\n\n\n\n" +
		"x-ms-date:Fri, 02 Jan 2026 03:04:05 GMT\n" +
		"x-ms-meta-tenarium_tenant_id:t1\n" +
		"x-ms-version:2023-11-03\n" +
		"/devstoreaccount1/devstoreaccount1/mycontainer\ncomp:metadata\nrestype:container"
	if got := stringToSign(req, DevAccountName); got != wantSTS {
		t.Fatalf("string-to-sign:\n%q\nwant\n%q", got, wantSTS)
	}
	key, _ := base64.StdEncoding.DecodeString(DevAccountKey)
	sign(req, DevAccountName, key)
	want := "SharedKey devstoreaccount1:sg4OY37U2IFb2EaDoRBKS51jIJsEEzGBPY9P2QHDke0="
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("Authorization = %q, want %q", got, want)
	}
}

func TestStringToSignDetails(t *testing.T) {
	body := []byte("<SignedIdentifiers />")
	req, _ := http.NewRequest(http.MethodPut, "https://acct.blob.core.windows.net/c1?restype=container&comp=acl&b=2&B=1", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("If-Unmodified-Since", "Fri, 02 Jan 2026 03:04:05 GMT")
	req.Header.Set("X-Ms-Blob-Public-Access", "  blob  ")
	req.Header.Set("x-ms-date", "D")
	got := stringToSign(req, "acct")
	want := "PUT\n\n\n21\n\napplication/xml\n\n\n\n\nFri, 02 Jan 2026 03:04:05 GMT\n\n" +
		"x-ms-blob-public-access:blob\nx-ms-date:D\n" +
		"/acct/c1\nb:1,2\ncomp:acl\nrestype:container"
	if got != want {
		t.Fatalf("got\n%q\nwant\n%q", got, want)
	}
	// Account root: path "/" even for host-style endpoints.
	req, _ = http.NewRequest(http.MethodGet, "https://acct.blob.core.windows.net?comp=list", nil)
	if got := canonicalizedResource(req.URL, "acct"); got != "/acct/\ncomp:list" {
		t.Fatalf("root resource %q", got)
	}
}

func TestParseConnectionString(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("secret-key"))
	for _, tc := range []struct {
		in, account, url, wantErr string
	}{
		{"UseDevelopmentStorage=true", DevAccountName, DevBlobURL, ""},
		{"UseDevelopmentStorage=true;DevelopmentStorageProxyUri=http://10.0.0.5:10000", DevAccountName, "http://10.0.0.5:10000/devstoreaccount1", ""},
		{"DefaultEndpointsProtocol=https;AccountName=acme;AccountKey=" + key + ";EndpointSuffix=core.windows.net", "acme", "https://acme.blob.core.windows.net", ""},
		{"AccountName=acme;AccountKey=" + key, "acme", "https://acme.blob.core.windows.net", ""},
		{"accountname=acme;accountkey=" + key + ";endpointsuffix=core.chinacloudapi.cn;", "acme", "https://acme.blob.core.chinacloudapi.cn", ""},
		{"DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=" + DevAccountKey + ";BlobEndpoint=http://127.0.0.1:47210/devstoreaccount1;", DevAccountName, "http://127.0.0.1:47210/devstoreaccount1", ""},
		{"AccountName=acme;AccountKey=" + key + ";BlobEndpoint=http://127.0.0.1:10000/", "acme", "http://127.0.0.1:10000/acme", ""},
		{"AccountName=acme;AccountKey=" + key + ";BlobEndpoint=https://blob.example.com/", "acme", "https://blob.example.com", ""},
		{"AccountName=acme", "", "", "AccountKey"},
		{"AccountName=acme;AccountKey=not base64!", "", "", "base64"},
		{"AccountName=Acme;AccountKey=" + key, "", "", "account name"},
		{"AccountName=acme;AccountKey=" + key + ";DefaultEndpointsProtocol=ftp", "", "", "DefaultEndpointsProtocol"},
		{"BlobEndpoint=https://x;SharedAccessSignature=sv=1", "", "", "SharedAccessSignature"},
		{"garbage", "", "", "malformed"},
		{"AccountName=acme;AccountKey=" + key + ";BlobEndpoint=ftp://x", "", "", "http(s)"},
	} {
		c, err := parseConnectionString(tc.in)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%q: error %v, want %q", tc.in, err, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", tc.in, err)
			continue
		}
		if c.Account != tc.account || c.Endpoint.String() != tc.url {
			t.Errorf("%q: got %s %s, want %s %s", tc.in, c.Account, c.Endpoint, tc.account, tc.url)
		}
	}
	// The key must not leak into errors.
	_, err := parseConnectionString("AccountKey" + strings.Repeat("x", 40))
	if err == nil || strings.Contains(err.Error(), strings.Repeat("x", 20)) {
		t.Fatalf("error leaks the segment: %v", err)
	}
}

func TestSanitizeAndValidate(t *testing.T) {
	for in, want := range map[string]string{
		"tenant-acme":       "tenant-acme",
		"Tenant_Acme Corp.": "tenant-acme-corp",
		"a..b--c__d":        "a-b-c-d",
		"--x--":             "x",
		"ümlaut":            "mlaut",
		"$root":             "root",
		"":                  "",
	} {
		if got := SanitizeName(in); got != want {
			t.Errorf("SanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
	for s, ok := range map[string]bool{
		"abc": true, "a-b-c": true, "1ab": true, strings.Repeat("a", 63): true,
		"ab": false, strings.Repeat("a", 64): false, "-ab": false, "ab-": false,
		"a--b": false, "Abc": false, "a_b": false, "a.b": false,
	} {
		if ValidContainerName(s) != ok {
			t.Errorf("ValidContainerName(%q) != %v", s, ok)
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
		if !ValidContainerName(n) || !strings.HasPrefix(n, "tenant-very-long-slug") {
			t.Errorf("bad shortened name %q", n)
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
	if err != nil || !ValidContainerName(n) || !strings.HasPrefix(n, "a-") {
		t.Fatalf("short name %q, %v", n, err)
	}
}

func TestConfigValidation(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("k"))
	base := func(c Config) Config {
		if c.ConnectionString == "" && c.AccountName == "" {
			c.ConnectionString = "UseDevelopmentStorage=true"
		}
		return c
	}
	for _, tc := range []struct {
		cfg     Config
		wantErr string
	}{
		{base(Config{}), ""},
		{Config{AccountName: "acme", AccountKey: key}, ""},
		{Config{AccountName: "acme", AccountKey: key, Endpoint: "http://localhost:10000"}, ""},
		{Config{}, "are required"},
		{Config{AccountName: "acme"}, "are required"},
		{Config{ConnectionString: "UseDevelopmentStorage=true", AccountName: "acme"}, "not both"},
		{Config{AccountName: "acme", AccountKey: "%%%"}, "base64"},
		{Config{AccountName: "acme", AccountKey: key, Endpoint: "acme.blob.core.windows.net"}, "absolute"},
		{base(Config{PublicAccess: "public"}), "public_access"},
		{base(Config{OnDeprovision: "archive"}), "on_deprovision"},
		{base(Config{NameTemplate: "t-{{.Slug"}), "name_template"},
		{base(Config{NameTemplate: "t-{{.Nope}}"}), "name_template"},
		{base(Config{NameTemplate: "{{if false}}x{{end}}"}), "empty name"},
		{base(Config{NameTemplate: "static-name"}), "must depend on the tenant"},
	} {
		p := &Plugin{cfg: tc.cfg}
		_, err := p.validate()
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
	creds, err := p.validate()
	if err != nil {
		t.Fatal(err)
	}
	if p.cfg.PublicAccess != PublicAccessNone || p.cfg.OnDeprovision != DeprovisionDelete || p.cfg.NameTemplate != DefaultNameTemplate {
		t.Fatalf("defaults not applied: %+v", p.cfg)
	}
	if creds.Account != DevAccountName || creds.Endpoint.String() != DevBlobURL {
		t.Fatalf("creds %+v", creds)
	}
	p = &Plugin{cfg: Config{AccountName: "acme", AccountKey: key}}
	if creds, err = p.validate(); err != nil || creds.Endpoint.String() != "https://acme.blob.core.windows.net" {
		t.Fatalf("default endpoint %v, %v", creds.Endpoint, err)
	}
}

func TestConfigSchema(t *testing.T) {
	m := (&Plugin{}).Manifest()
	if m.ID != "azure-blob-tenant" {
		t.Fatalf("id %q", m.ID)
	}
	s, err := schema.Compile(m.ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	for _, ok := range []map[string]any{
		{"connection_string": "UseDevelopmentStorage=true", "public_access": "blob", "on_deprovision": "retain"},
		{"account_name": "acme", "account_key": "a2V5", "endpoint": "https://x"},
	} {
		if err := s.Validate(ok); err != nil {
			t.Errorf("%v: %v", ok, err)
		}
	}
	for _, bad := range []map[string]any{
		{},
		{"account_name": "acme"},
		{"connection_string": "x", "account_name": "acme", "account_key": "k"},
		{"connection_string": "x", "public_access": "private"},
		{"connection_string": "x", "unknown": 1},
		{"account_name": "Acme", "account_key": "k"},
	} {
		if err := s.Validate(bad); err == nil {
			t.Errorf("%v: expected schema error", bad)
		}
	}
}

// newTestPlugin initializes the plugin against a fake Blob service.
func newTestPlugin(t *testing.T, extra map[string]any) (*Plugin, *sdktest.Registrar, *fakeBlob) {
	t.Helper()
	f, srv := newFakeBlob(t)
	cfg := map[string]any{"account_name": f.account, "account_key": f.keyB64(), "endpoint": srv.URL}
	for k, v := range extra {
		cfg[k] = v
	}
	reg := sdktest.NewRegistrar(cfg)
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	p.now = func() time.Time { return time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC) }
	p.pollInterval = time.Millisecond
	p.beingDeletedWait = 2 * time.Second
	return p, reg, f
}

func TestInitRegisters(t *testing.T) {
	p, reg, _ := newTestPlugin(t, nil)
	if len(reg.Provisioners) != 1 || reg.Provisioners[0].Name() != "azure-blob" {
		t.Fatalf("provisioners %v", reg.Provisioners)
	}
	if len(reg.Routes) != 1 || reg.Routes[0] != "GET /tenants/{tenant}" {
		t.Fatalf("routes %v", reg.Routes)
	}
	var _ sdk.HealthChecker = p
}

func TestHealth(t *testing.T) {
	p, _, _ := newTestPlugin(t, nil)
	if err := p.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A wrong key is reported.
	p.client.creds.Key = []byte("wrong")
	err := p.Health(context.Background())
	if errCode(err) != "AuthenticationFailed" {
		t.Fatalf("health with wrong key: %v", err)
	}
}

func TestProvisionLifecycle(t *testing.T) {
	ctx := context.Background()
	p, reg, f := newTestPlugin(t, map[string]any{"quota_from_limit": "storage_gb"})
	reg.HostImpl.AddPlan(sdk.Plan{ID: "pro", Limits: map[string]int64{"storage_gb": 50}})
	acme := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})

	if err := p.Provision(ctx, acme); err != nil {
		t.Fatal(err)
	}
	c := f.get("tenant-acme")
	if c == nil || c.meta[MetaTenantID] != acme.ID || c.meta[MetaQuotaGB] != "50" || c.access != PublicAccessNone {
		t.Fatalf("container %+v", c)
	}
	// Idempotent: no further writes.
	n := len(f.writeLog())
	if err := p.Provision(ctx, acme); err != nil {
		t.Fatal(err)
	}
	if w := f.writeLog(); len(w) != n {
		t.Fatalf("second provision wrote: %v", w[n:])
	}

	// Quota changes are applied on retry; other metadata is preserved.
	c.meta["owner_team"] = "ops"
	reg.HostImpl.AddPlan(sdk.Plan{ID: "pro"})
	if err := p.Provision(ctx, acme); err != nil {
		t.Fatal(err)
	}
	if c := f.get("tenant-acme"); c.meta[MetaQuotaGB] != "" || c.meta["owner_team"] != "ops" || c.meta[MetaTenantID] != acme.ID {
		t.Fatalf("metadata after quota removal %v", c.meta)
	}

	// Another tenant whose name collides is refused.
	other := reg.HostImpl.AddTenant(sdk.Tenant{ID: "other-id", Slug: "acme"})
	if err := p.Provision(ctx, other); err == nil || !strings.Contains(err.Error(), "belongs to another tenant") {
		t.Fatalf("collision: %v", err)
	}
	// ... and cannot deprovision it.
	if err := p.Deprovision(ctx, other); err != nil {
		t.Fatal(err)
	}
	if f.get("tenant-acme") == nil {
		t.Fatal("foreign deprovision deleted the container")
	}

	if err := p.Deprovision(ctx, acme); err != nil {
		t.Fatal(err)
	}
	if f.get("tenant-acme") != nil {
		t.Fatal("container not deleted")
	}
	// Idempotent.
	if err := p.Deprovision(ctx, acme); err != nil {
		t.Fatal(err)
	}
}

func TestProvisionAdoption(t *testing.T) {
	ctx := context.Background()
	p, reg, f := newTestPlugin(t, nil)
	a := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "a1"})
	b := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "b1"})

	// Unmarked and empty: adopted.
	f.put("tenant-a1", &fakeContainer{meta: map[string]string{"x": "y"}})
	if err := p.Provision(ctx, a); err != nil {
		t.Fatal(err)
	}
	if c := f.get("tenant-a1"); c.meta[MetaTenantID] != a.ID || c.meta["x"] != "y" {
		t.Fatalf("not adopted: %v", c.meta)
	}
	// Unmarked with data: refused, and left alone by deprovision.
	f.put("tenant-b1", &fakeContainer{blobs: 1})
	if err := p.Provision(ctx, b); err == nil || !strings.Contains(err.Error(), "not managed by tenarium") {
		t.Fatalf("unmarked non-empty: %v", err)
	}
	if err := p.Deprovision(ctx, b); err != nil {
		t.Fatal(err)
	}
	if f.get("tenant-b1") == nil {
		t.Fatal("unmanaged container deleted")
	}
	// Unmarked and empty is cleaned up by delete.
	f.put("tenant-b1", &fakeContainer{})
	if err := p.Deprovision(ctx, b); err != nil {
		t.Fatal(err)
	}
	if f.get("tenant-b1") != nil {
		t.Fatal("empty unmarked container not cleaned up")
	}
	// Retained data blocks a new tenant with the same name.
	f.put("tenant-b1", &fakeContainer{meta: map[string]string{MetaDeletedAt: "2026-01-01T00:00:00Z", MetaDeletedTenantID: "old"}})
	if err := p.Provision(ctx, b); err == nil || !strings.Contains(err.Error(), "retained from deleted tenant old") {
		t.Fatalf("retained: %v", err)
	}
}

func TestPublicAccess(t *testing.T) {
	ctx := context.Background()
	p, reg, f := newTestPlugin(t, map[string]any{"public_access": "blob", "on_deprovision": "retain"})
	a := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "pub"})
	if err := p.Provision(ctx, a); err != nil {
		t.Fatal(err)
	}
	if c := f.get("tenant-pub"); c.access != PublicAccessBlob {
		t.Fatalf("access %q", c.access)
	}
	// A drifted level is corrected and stored access policies are kept.
	acl := `<?xml version="1.0" encoding="utf-8"?><SignedIdentifiers><SignedIdentifier><Id>p1</Id></SignedIdentifier></SignedIdentifiers>`
	c := f.get("tenant-pub")
	c.access, c.acl = PublicAccessContainer, acl
	if err := p.Provision(ctx, a); err != nil {
		t.Fatal(err)
	}
	if c := f.get("tenant-pub"); c.access != PublicAccessBlob || c.acl != acl {
		t.Fatalf("after fix: %q %q", c.access, c.acl)
	}

	// Retain releases ownership and turns public access off.
	if err := p.Deprovision(ctx, a); err != nil {
		t.Fatal(err)
	}
	c = f.get("tenant-pub")
	if c == nil || c.access != PublicAccessNone || c.acl != acl {
		t.Fatalf("retained container %+v", c)
	}
	if c.meta[MetaTenantID] != "" || c.meta[MetaDeletedTenantID] != a.ID || c.meta[MetaDeletedAt] != "2026-05-06T07:08:09Z" {
		t.Fatalf("retained metadata %v", c.meta)
	}
	// Idempotent; and the same tenant cannot re-adopt it.
	n := len(f.writeLog())
	if err := p.Deprovision(ctx, a); err != nil {
		t.Fatal(err)
	}
	if len(f.writeLog()) != n {
		t.Fatal("second retain wrote")
	}
	if err := p.Provision(ctx, a); err == nil {
		t.Fatal("provision over retained data succeeded")
	}
}

func TestDeprovisionKeep(t *testing.T) {
	ctx := context.Background()
	p, reg, f := newTestPlugin(t, map[string]any{"on_deprovision": "keep"})
	a := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "k"})
	if err := p.Provision(ctx, a); err != nil {
		t.Fatal(err)
	}
	n := len(f.writeLog())
	if err := p.Deprovision(ctx, a); err != nil {
		t.Fatal(err)
	}
	c := f.get(mustName(t, p, a))
	if c == nil || c.meta[MetaTenantID] != a.ID || len(f.writeLog()) != n {
		t.Fatalf("keep touched the container: %+v", c)
	}
}

func mustName(t *testing.T, p *Plugin, ten sdk.Tenant) string {
	t.Helper()
	n, err := p.containerName(ten)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestBeingDeleted(t *testing.T) {
	ctx := context.Background()
	p, reg, f := newTestPlugin(t, nil)
	a := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "slow"})
	f.beingDeleted["tenant-slow"] = 3
	if err := p.Provision(ctx, a); err != nil {
		t.Fatal(err)
	}
	if f.get("tenant-slow") == nil {
		t.Fatal("not created after deletion finished")
	}

	b := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "stuck"})
	f.beingDeleted["tenant-stuck"] = 1 << 30
	p.beingDeletedWait = 20 * time.Millisecond
	p.pollInterval = 5 * time.Millisecond
	err := p.Provision(ctx, b)
	if err == nil || !strings.Contains(err.Error(), "still being deleted") || errCode(err) != "ContainerBeingDeleted" {
		t.Fatalf("stuck: %v", err)
	}
}

func TestDeprovisionConcurrentChange(t *testing.T) {
	ctx := context.Background()
	p, reg, f := newTestPlugin(t, nil)
	a := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "race"})
	if err := p.Provision(ctx, a); err != nil {
		t.Fatal(err)
	}
	f.touchBeforeDelete = true
	if err := p.Deprovision(ctx, a); err == nil || !strings.Contains(err.Error(), "changed while deprovisioning") {
		t.Fatalf("got %v", err)
	}
	if f.get("tenant-race") == nil {
		t.Fatal("deleted despite the change")
	}
	f.touchBeforeDelete = false
	if err := p.Deprovision(ctx, a); err != nil || f.get("tenant-race") != nil {
		t.Fatalf("retry: %v", err)
	}
}

func TestServeTenant(t *testing.T) {
	p, reg, _ := newTestPlugin(t, nil)
	acme := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	other := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "other"})
	get := func(path string, principal *sdk.Principal) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if principal != nil {
			req = req.WithContext(sdk.WithPrincipal(req.Context(), principal))
		}
		rec := httptest.NewRecorder()
		reg.Mux.ServeHTTP(rec, req)
		return rec
	}
	rec := get("/tenants/acme", &sdk.Principal{Subject: "admin"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var info TenantInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	want := p.client.creds.Endpoint.String() + "/tenant-acme"
	if info.Container != "tenant-acme" || info.Account != "testacct" || info.URL != want {
		t.Fatalf("info %+v (want url %s)", info, want)
	}
	if rec := get("/tenants/"+acme.ID, &sdk.Principal{Subject: "u", TenantID: acme.ID}); rec.Code != http.StatusOK {
		t.Fatalf("own tenant: %d", rec.Code)
	}
	if rec := get("/tenants/acme", &sdk.Principal{Subject: "u", TenantID: other.ID}); rec.Code != http.StatusNotFound {
		t.Fatalf("other tenant: %d", rec.Code)
	}
	if rec := get("/tenants/acme", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("no principal: %d", rec.Code)
	}
	if rec := get("/tenants/missing", &sdk.Principal{Subject: "admin"}); rec.Code != http.StatusNotFound {
		t.Fatalf("missing: %d", rec.Code)
	}
}
