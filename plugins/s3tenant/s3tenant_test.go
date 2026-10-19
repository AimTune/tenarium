package s3tenant

import (
	"context"
	"strings"
	"testing"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
	"github.com/minio/minio-go/v7/pkg/s3utils"
)

func TestSanitizeName(t *testing.T) {
	for in, want := range map[string]string{
		"tenant-acme":          "tenant-acme",
		"Tenant_Acme Corp.":    "tenant-acme-corp",
		"a..b--c__d":           "a-b-c-d",
		"--x--":                "x",
		"ümlaut":               "mlaut",
		"xn--punycode":         "xn-punycode",
		"sthree-thing":         "t-sthree-thing",
		"data-s3alias":         "data-s3alias-t",
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
		if err := s3utils.CheckValidBucketNameStrict(n); err != nil {
			t.Errorf("%q: %v", n, err)
		}
	}
	// Deterministic.
	if again, _ := renderName(tmpl, a); again != na {
		t.Fatalf("name not stable: %q vs %q", again, na)
	}

	// Too short names are padded with the hash.
	short, err := parseNameTemplate("{{.Slug}}")
	if err != nil {
		t.Fatal(err)
	}
	n, err := renderName(short, sdk.Tenant{ID: "x", Slug: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if len(n) < minNameLen || !strings.HasPrefix(n, "a-") {
		t.Fatalf("short name %q", n)
	}
	if err := s3utils.CheckValidBucketNameStrict(n); err != nil {
		t.Fatal(err)
	}
}

func TestConfigValidation(t *testing.T) {
	base := func(c Config) Config {
		if c.Endpoint == "" {
			c.Endpoint = "s3.amazonaws.com"
		}
		if c.AccessKey == "" {
			c.AccessKey, c.SecretKey = "ak", "sk"
		}
		return c
	}
	for _, tc := range []struct {
		cfg     Config
		wantErr string
	}{
		{base(Config{}), ""},
		{base(Config{Mode: ModePrefix, Bucket: "shared-bucket"}), ""},
		{Config{AccessKey: "a", SecretKey: "b"}, "endpoint is required"},
		{base(Config{Endpoint: "https://s3.amazonaws.com"}), "without scheme"},
		{Config{Endpoint: "s3", AccessKey: "a"}, "secret_key"},
		{base(Config{Mode: "account"}), "mode"},
		{base(Config{OnDeprovision: "archive"}), "on_deprovision"},
		{base(Config{LifecycleExpireDays: -1}), "lifecycle_expire_days"},
		{base(Config{Mode: ModePrefix}), "bucket is required"},
		{base(Config{Mode: ModePrefix, Bucket: "Bad_Bucket"}), "bucket:"},
		{base(Config{Mode: ModePrefix, Bucket: "shared", Versioning: true}), "versioning is only supported in bucket mode"},
		{base(Config{Mode: ModePrefix, Bucket: "shared", ObjectLock: true}), "object_lock"},
		{base(Config{Mode: ModePrefix, Bucket: "shared", LifecycleExpireDays: 3}), "lifecycle_expire_days"},
		{base(Config{Mode: ModePrefix, Bucket: "shared", PolicyTemplate: "{}"}), "policy_template"},
		{base(Config{Bucket: "shared"}), "only used in prefix mode"},
		{base(Config{NameTemplate: "t-{{.Slug"}), "name_template"},
		{base(Config{NameTemplate: "t-{{.Nope}}"}), "name_template"},
		{base(Config{NameTemplate: "{{if false}}x{{end}}"}), "empty name"},
		{base(Config{NameTemplate: "static-name"}), "must depend on the tenant"},
		{base(Config{PolicyTemplate: `{"Statement": [`}), "invalid JSON"},
		{base(Config{PolicyTemplate: `{{.Nope}}`}), "policy_template"},
		{base(Config{PolicyTemplate: `{"Resource": "arn:aws:s3:::{{.Bucket}}/*", "Tenant": "{{.Tenant.ID}}"}`}), ""},
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
	if p.cfg.Mode != ModeBucket || p.cfg.OnDeprovision != DeprovisionDelete ||
		p.cfg.NameTemplate != DefaultNameTemplate || !*p.cfg.Secure {
		t.Fatalf("defaults not applied: %+v", p.cfg)
	}
	tg, err := p.target(sdk.Tenant{ID: "id", Slug: "acme-corp"})
	if err != nil || tg.Bucket != "tenant-acme-corp" || tg.Prefix != "" {
		t.Fatalf("target = %+v, %v", tg, err)
	}

	p = &Plugin{cfg: base(Config{Mode: ModePrefix, Bucket: "shared"})}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	tg, err = p.target(sdk.Tenant{ID: "id", Slug: "acme"})
	if err != nil || tg.Bucket != "shared" || tg.Prefix != "tenant-acme/" {
		t.Fatalf("target = %+v, %v", tg, err)
	}
}

func TestConfigSchemaCompiles(t *testing.T) {
	m := (&Plugin{}).Manifest()
	if m.ID != "s3-tenant" {
		t.Fatalf("id %q", m.ID)
	}
	s, err := schema.Compile(m.ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(map[string]any{"endpoint": "s3.amazonaws.com", "access_key": "a", "secret_key": "b", "mode": "prefix", "bucket": "x"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(map[string]any{"endpoint": "x", "access_key": "a", "secret_key": "b", "mode": "zone"}); err == nil {
		t.Fatal("expected schema error for mode")
	}
	if err := s.Validate(map[string]any{"endpoint": "x"}); err == nil {
		t.Fatal("expected schema error for missing keys")
	}
}

func TestInitRegisters(t *testing.T) {
	reg := sdktest.NewRegistrar(map[string]any{
		"endpoint": "localhost:9", "access_key": "a", "secret_key": "b", "secure": false,
	})
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if len(reg.Provisioners) != 1 || reg.Provisioners[0].Name() != "s3" {
		t.Fatalf("provisioners %v", reg.Provisioners)
	}
	if len(reg.Routes) != 1 || reg.Routes[0] != "GET /tenants/{tenant}" {
		t.Fatalf("routes %v", reg.Routes)
	}
	var _ sdk.HealthChecker = p
}
