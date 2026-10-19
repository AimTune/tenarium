package dns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"text/template"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
	"github.com/aws/aws-sdk-go-v2/service/route53"
)

func TestSanitizeLabel(t *testing.T) {
	for in, want := range map[string]string{
		"acme":              "acme",
		"Acme Corp":         "acme-corp",
		"a__b--c":           "a-b-c",
		"--x--":             "x",
		"_acme-challenge":   "_acme-challenge",
		"__x":               "_x",
		"ümlaut":            "mlaut",
		"":                  "",
		"_":                 "",
		`x"; rm -rf /; y`:   "x-rm-rf-y",
		"tenant.with.dots?": "tenant-with-dots",
	} {
		if got := SanitizeLabel(in); got != want {
			t.Errorf("SanitizeLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func mustTemplate(t *testing.T, s string) *template.Template {
	t.Helper()
	tmpl, err := parseTemplate("name", s)
	if err != nil {
		t.Fatal(err)
	}
	return tmpl
}

func TestRenderName(t *testing.T) {
	ten := sdk.Tenant{ID: "11111111-1111-1111-1111-111111111111", Slug: "Acme_Corp"}
	for _, tc := range []struct {
		tmpl, want, wantErr string
	}{
		{"{{.Slug}}", "acme-corp.example.com", ""},
		{"{{.Slug}}.example.com", "acme-corp.example.com", ""},
		{"{{.Slug}}.EXAMPLE.com.", "acme-corp.example.com", ""},
		{"{{.Slug}}.apps", "acme-corp.apps.example.com", ""},
		{"*.{{.Slug}}", "*.acme-corp.example.com", ""},
		{"_acme-challenge.{{.Slug}}", "_acme-challenge.acme-corp.example.com", ""},
		{"{{.Slug}}.other.org.", "", "not inside zone"},
		{"example.com.", "", "zone apex"},
		{"{{.Slug}}..x", "", "empty label"},
		{"a.*.{{.Slug}}", "", "empty label"},
		{"{{.Nope}}", "", "Nope"},
	} {
		got, err := renderName(mustTemplate(t, tc.tmpl), ten, "example.com")
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%q: error %v, want %q", tc.tmpl, err, tc.wantErr)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%q: got %q, %v; want %q", tc.tmpl, got, err, tc.want)
		}
	}

	// Long labels are shortened with a tenant hash; names stay distinct.
	long := strings.Repeat("very-long-slug-", 10)
	a := sdk.Tenant{ID: "11111111-1111-1111-1111-111111111111", Slug: long}
	b := sdk.Tenant{ID: "22222222-2222-2222-2222-222222222222", Slug: long}
	tmpl := mustTemplate(t, "{{.Slug}}")
	na, err := renderName(tmpl, a, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	nb, _ := renderName(tmpl, b, "example.com")
	if na == nb {
		t.Fatalf("long names collide: %q", na)
	}
	label, _, _ := strings.Cut(na, ".")
	if len(label) > maxLabelLen || !strings.HasPrefix(label, "very-long-slug") || !strings.HasSuffix(na, ".example.com") {
		t.Fatalf("bad shortened name %q", na)
	}
	if again, _ := renderName(tmpl, a, "example.com"); again != na {
		t.Fatal("name not stable")
	}
	// Whole names over 253 characters are rejected.
	deep := mustTemplate(t, strings.Repeat("abcdefghij.", 25)+"{{.Slug}}")
	if _, err := renderName(deep, a, "example.com"); err == nil || !strings.Contains(err.Error(), "longer than 253") {
		t.Fatalf("expected length error, got %v", err)
	}
}

func TestTXTCodec(t *testing.T) {
	for _, v := range []string{"hello", `with "quotes" and \ backslash`, strings.Repeat("x", 600), "v=spf1 -all"} {
		enc := txtEncode(v)
		if !strings.HasPrefix(enc, `"`) {
			t.Fatalf("not quoted: %s", enc)
		}
		if got := txtDecode(enc); got != v {
			t.Errorf("roundtrip %q -> %s -> %q", v, enc, got)
		}
	}
	if n := strings.Count(txtEncode(strings.Repeat("x", 600)), `"`); n != 6 {
		t.Errorf("600 bytes should be 3 strings, got %d quotes", n)
	}
	if got := txtDecode("plain"); got != "plain" {
		t.Errorf("unquoted %q", got)
	}
	if got := txtDecode(`"a\052b"`); got != "a*b" {
		t.Errorf("octal escape %q", got)
	}
}

func TestNormalizeValue(t *testing.T) {
	for _, tc := range []struct{ typ, in, want string }{
		{TypeA, "192.0.2.1", "192.0.2.1"},
		{TypeA, "2001:db8::1", ""},
		{TypeA, "host", ""},
		{TypeAAAA, "2001:DB8:0::1", "2001:db8::1"},
		{TypeAAAA, "192.0.2.1", ""},
		{TypeAAAA, "::ffff:192.0.2.1", ""},
		{TypeCNAME, "Ingress.Example.com.", "ingress.example.com"},
		{TypeCNAME, "bad host", ""},
		{TypeCNAME, "-bad.example.com", ""},
		{TypeTXT, "v=1", "v=1"},
		{TypeTXT, "tab\there", ""},
	} {
		got, err := normalizeValue(tc.typ, tc.in)
		if tc.want == "" {
			if err == nil {
				t.Errorf("%s %q: expected error, got %q", tc.typ, tc.in, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%s %q: got %q, %v", tc.typ, tc.in, got, err)
		}
	}
}

func r53Cfg() *Route53Config { return &Route53Config{} }
func cfCfg() *CloudflareConfig {
	return &CloudflareConfig{APIToken: "tok"}
}

func cname() []RecordConfig {
	return []RecordConfig{{NameTemplate: "{{.Slug}}", Type: TypeCNAME, Values: []string{"ingress.example.com"}}}
}

func TestConfigValidation(t *testing.T) {
	base := func(c Config) Config {
		if c.Provider == "" {
			c.Provider = ProviderRoute53
		}
		if c.Provider == ProviderRoute53 && c.Route53 == nil && c.Cloudflare == nil {
			c.Route53 = r53Cfg()
		}
		if c.Zone == "" {
			c.Zone = "example.com"
		}
		if c.Records == nil {
			c.Records = cname()
		}
		return c
	}
	rec := func(r ...RecordConfig) []RecordConfig { return r }
	for _, tc := range []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{"ok route53", base(Config{}), ""},
		{"ok cloudflare", base(Config{Provider: ProviderCloudflare, Cloudflare: cfCfg()}), ""},
		{"zone trailing dot", base(Config{Zone: "Example.COM."}), ""},
		{"missing provider", Config{Zone: "example.com", Records: cname()}, "provider is required"},
		{"bad provider", base(Config{Provider: "bind"}), "provider must be"},
		{"no route53 block", base(Config{Provider: ProviderRoute53, Cloudflare: cfCfg()}), "requires a route53 block"},
		{"both blocks", base(Config{Route53: r53Cfg(), Cloudflare: cfCfg()}), "cloudflare block is set"},
		{"no cloudflare block", base(Config{Provider: ProviderCloudflare, Route53: r53Cfg()}), "requires a cloudflare block"},
		{"cf no token", base(Config{Provider: ProviderCloudflare, Cloudflare: &CloudflareConfig{}}), "api_token"},
		{"cf bad url", base(Config{Provider: ProviderCloudflare, Cloudflare: &CloudflareConfig{APIToken: "x", BaseURL: "ftp://x"}}), "base_url"},
		{"r53 half creds", base(Config{Route53: &Route53Config{AccessKeyID: "a"}}), "set together"},
		{"r53 token only", base(Config{Route53: &Route53Config{SessionToken: "t"}}), "session_token"},
		{"r53 bad endpoint", base(Config{Route53: &Route53Config{Endpoint: "localhost:4566"}}), "endpoint"},
		{"r53 bad wait", base(Config{Route53: &Route53Config{WaitTimeout: "soon"}}), "wait_timeout"},
		{"bad zone", base(Config{Zone: "exa mple.com"}), "zone"},
		{"retain", base(Config{OnDeprovision: "retain"}), "retain is not supported"},
		{"bad deprovision", base(Config{OnDeprovision: "archive"}), "on_deprovision"},
		{"prefix no dot", base(Config{OwnershipTXTPrefix: "_owner"}), "must end with"},
		{"prefix bad label", base(Config{OwnershipTXTPrefix: "Owner Of."}), "invalid label"},
		{"no records", base(Config{Records: []RecordConfig{}}), "at least one record"},
		{"bad type", base(Config{Records: rec(RecordConfig{NameTemplate: "{{.Slug}}", Type: "MX", Values: []string{"x"}})}), "type must be"},
		{"no values", base(Config{Records: rec(RecordConfig{NameTemplate: "{{.Slug}}", Type: TypeA})}), "values"},
		{"cname two values", base(Config{Records: rec(RecordConfig{NameTemplate: "{{.Slug}}", Type: TypeCNAME, Values: []string{"a.com", "b.com"}})}), "exactly one value"},
		{"bad ip", base(Config{Records: rec(RecordConfig{NameTemplate: "{{.Slug}}", Type: TypeA, Values: []string{"10.0.0.300"}})}), "invalid IP"},
		{"aaaa v4", base(Config{Records: rec(RecordConfig{NameTemplate: "{{.Slug}}", Type: TypeAAAA, Values: []string{"10.0.0.1"}})}), "not an IPv6"},
		{"static name", base(Config{Records: rec(RecordConfig{NameTemplate: "www", Type: TypeA, Values: []string{"10.0.0.1"}})}), "must depend on the tenant"},
		{"name outside zone", base(Config{Records: rec(RecordConfig{NameTemplate: "{{.Slug}}.example.org.", Type: TypeA, Values: []string{"10.0.0.1"}})}), "not inside zone"},
		{"name parse", base(Config{Records: rec(RecordConfig{NameTemplate: "{{.Slug", Type: TypeA, Values: []string{"10.0.0.1"}})}), "name_template"},
		{"name missing key", base(Config{Records: rec(RecordConfig{NameTemplate: "{{.Nope}}", Type: TypeA, Values: []string{"10.0.0.1"}})}), "name_template"},
		{"value missing key", base(Config{Records: rec(RecordConfig{NameTemplate: "{{.Slug}}", Type: TypeTXT, Values: []string{"{{.Nope}}"}})}), "values[0]"},
		{"proxied route53", base(Config{Records: rec(RecordConfig{NameTemplate: "{{.Slug}}", Type: TypeA, Values: []string{"10.0.0.1"}, Proxied: true})}), "only supported by the cloudflare"},
		{"proxied txt", base(Config{Provider: ProviderCloudflare, Cloudflare: cfCfg(), Records: rec(RecordConfig{NameTemplate: "{{.Slug}}", Type: TypeTXT, Values: []string{"x"}, Proxied: true})}), "cannot be proxied"},
		{"cf ttl", base(Config{Provider: ProviderCloudflare, Cloudflare: cfCfg(), Records: rec(RecordConfig{NameTemplate: "{{.Slug}}", Type: TypeA, Values: []string{"10.0.0.1"}, TTL: 5})}), "cloudflare ttl"},
		{"negative ttl", base(Config{Records: rec(RecordConfig{NameTemplate: "{{.Slug}}", Type: TypeA, Values: []string{"10.0.0.1"}, TTL: -1})}), "ttl"},
		{"cname coexist", base(Config{Records: rec(
			RecordConfig{NameTemplate: "{{.Slug}}", Type: TypeCNAME, Values: []string{"x.example.net"}},
			RecordConfig{NameTemplate: "{{.Slug}}", Type: TypeTXT, Values: []string{"hi"}},
		)}), "CNAME cannot coexist"},
		{"duplicate", base(Config{Records: rec(
			RecordConfig{NameTemplate: "{{.Slug}}", Type: TypeA, Values: []string{"10.0.0.1"}},
			RecordConfig{NameTemplate: "{{.Slug}}.example.com", Type: TypeA, Values: []string{"10.0.0.2"}},
		)}), "duplicate A record"},
		{"marker clash", base(Config{Records: rec(
			RecordConfig{NameTemplate: "{{.Slug}}", Type: TypeA, Values: []string{"10.0.0.1"}},
			RecordConfig{NameTemplate: "_tenarium.{{.Slug}}", Type: TypeTXT, Values: []string{"x"}},
		)}), "ownership marker"},
		{"cname self", base(Config{Records: rec(RecordConfig{NameTemplate: "{{.Slug}}", Type: TypeCNAME, Values: []string{"{{.Slug}}.example.com"}})}), "points to itself"},
		{"a and aaaa ok", base(Config{Records: rec(
			RecordConfig{NameTemplate: "{{.Slug}}", Type: TypeA, Values: []string{"10.0.0.1", "10.0.0.2"}},
			RecordConfig{NameTemplate: "{{.Slug}}", Type: TypeAAAA, Values: []string{"2001:db8::1"}},
			RecordConfig{NameTemplate: "*.{{.Slug}}", Type: TypeCNAME, Values: []string{"{{.Slug}}.example.com"}},
			RecordConfig{NameTemplate: "_verify.{{.Slug}}", Type: TypeTXT, Values: []string{"tenant={{.ID}}"}},
		)}), ""},
	} {
		p := &Plugin{cfg: tc.cfg}
		err := p.validate()
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("%s: unexpected error %v", tc.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: error %v, want containing %q", tc.name, err, tc.wantErr)
		}
	}

	p := &Plugin{cfg: base(Config{Zone: "Example.COM."})}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	c := p.cfg
	if c.Zone != "example.com" || c.OnDeprovision != DeprovisionDelete || c.OwnershipTXTPrefix != DefaultOwnershipTXTPrefix ||
		c.Records[0].TTL != DefaultTTL || c.Route53.Region != DefaultRoute53Region || c.Route53.waitTimeout != DefaultWaitTimeout {
		t.Fatalf("defaults not applied: %+v %+v", c, c.Route53)
	}
	p = &Plugin{cfg: base(Config{Provider: ProviderCloudflare, Cloudflare: cfCfg()})}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	if p.cfg.Cloudflare.BaseURL != DefaultCloudflareBaseURL {
		t.Fatalf("base_url default %q", p.cfg.Cloudflare.BaseURL)
	}
}

func TestConfigSchemaCompiles(t *testing.T) {
	m := (&Plugin{}).Manifest()
	if m.ID != "dns-tenant" || m.Version != "0.1.0" {
		t.Fatalf("manifest %+v", m)
	}
	s, err := schema.Compile(m.ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	good := map[string]any{
		"provider": "cloudflare", "zone": "example.com",
		"cloudflare": map[string]any{"api_token": "x"},
		"records":    []any{map[string]any{"name_template": "{{.Slug}}", "type": "A", "values": []any{"10.0.0.1"}, "proxied": true}},
	}
	if err := s.Validate(good); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]map[string]any{
		"missing keys":    {"provider": "route53"},
		"bad provider":    {"provider": "bind", "zone": "x", "records": []any{}},
		"unknown root":    {"provider": "route53", "zone": "x", "records": []any{map[string]any{"name_template": "x", "type": "A", "values": []any{"1"}}}, "nope": 1},
		"unknown record":  {"provider": "route53", "zone": "x", "records": []any{map[string]any{"name_template": "x", "type": "A", "values": []any{"1"}, "weight": 1}}},
		"bad record type": {"provider": "route53", "zone": "x", "records": []any{map[string]any{"name_template": "x", "type": "MX", "values": []any{"1"}}}},
		"unknown r53":     {"provider": "route53", "zone": "x", "records": []any{map[string]any{"name_template": "x", "type": "A", "values": []any{"1"}}}, "route53": map[string]any{"zone": "x"}},
		"retain":          {"provider": "route53", "zone": "x", "records": []any{map[string]any{"name_template": "x", "type": "A", "values": []any{"1"}}}, "on_deprovision": "retain"},
	} {
		if err := s.Validate(bad); err == nil {
			t.Errorf("%s: expected schema error", name)
		}
	}
}

func TestInitRegisters(t *testing.T) {
	for _, cfg := range []map[string]any{
		{"provider": "route53", "zone": "example.com", "route53": map[string]any{"endpoint": "http://127.0.0.1:9", "access_key_id": "a", "secret_access_key": "b"},
			"records": []any{map[string]any{"name_template": "{{.Slug}}", "type": "CNAME", "values": []any{"ingress.example.com"}}}},
		{"provider": "cloudflare", "zone": "example.com", "cloudflare": map[string]any{"api_token": "x", "base_url": "http://127.0.0.1:9"},
			"records": []any{map[string]any{"name_template": "{{.Slug}}", "type": "A", "values": []any{"10.0.0.1"}}}},
	} {
		reg := sdktest.NewRegistrar(cfg)
		p := &Plugin{}
		if err := p.Init(context.Background(), reg); err != nil {
			t.Fatal(err)
		}
		if len(reg.Provisioners) != 1 || reg.Provisioners[0].Name() != "dns" {
			t.Fatalf("provisioners %v", reg.Provisioners)
		}
		if len(reg.Routes) != 1 || reg.Routes[0] != "GET /tenants/{tenant}" {
			t.Fatalf("routes %v", reg.Routes)
		}
		var _ sdk.HealthChecker = p
	}
	// Strict decoding rejects unknown keys.
	reg := sdktest.NewRegistrar(map[string]any{"provider": "route53", "zone": "example.com", "bogus": true})
	if err := (&Plugin{}).Init(context.Background(), reg); err == nil {
		t.Fatal("expected error for unknown key")
	}
}

// testPlugin initializes the plugin against a fake provider.
func testPlugin(t *testing.T, provider string, cfg map[string]any) (*Plugin, *sdktest.Registrar, fakeDNS) {
	t.Helper()
	full := map[string]any{
		"provider": provider, "zone": "example.com",
		"records": []any{
			map[string]any{"name_template": "{{.Slug}}", "type": "CNAME", "values": []any{"ingress.example.com"}},
			map[string]any{"name_template": "api.{{.Slug}}", "type": "A", "values": []any{"192.0.2.10", "192.0.2.11"}, "ttl": 120},
			map[string]any{"name_template": "api.{{.Slug}}", "type": "TXT", "values": []any{"tenant={{.ID}}"}},
		},
	}
	for k, v := range cfg {
		full[k] = v
	}
	var fake fakeDNS
	switch provider {
	case ProviderRoute53:
		full["route53"] = map[string]any{"endpoint": "http://127.0.0.1:9", "access_key_id": "a", "secret_access_key": "b", "wait": true}
	case ProviderCloudflare:
		cf := newFakeCloudflare(t)
		full["cloudflare"] = map[string]any{"api_token": "tok", "base_url": cf.srv.URL}
		fake = cf
	}
	reg := sdktest.NewRegistrar(full)
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if provider == ProviderRoute53 {
		f := newFakeRoute53()
		p.backend.(*route53Backend).api = f
		fake = f
	}
	return p, reg, fake
}

var providers = []string{ProviderRoute53, ProviderCloudflare}

var (
	tenantA = sdk.Tenant{ID: "aaaaaaaa-0000-0000-0000-000000000001", Slug: "acme"}
	tenantB = sdk.Tenant{ID: "bbbbbbbb-0000-0000-0000-000000000002", Slug: "acme"} // same slug
)

func expect(t *testing.T, f fakeDNS, name, typ string, want ...string) {
	t.Helper()
	got := f.values(name, typ)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("%s %s = %q, want %q", typ, name, got, want)
	}
}

func TestProvisionAndDeprovision(t *testing.T) {
	for _, prov := range providers {
		t.Run(prov, func(t *testing.T) {
			ctx := context.Background()
			p, _, f := testPlugin(t, prov, nil)
			if err := p.Health(ctx); err != nil {
				t.Fatalf("health: %v", err)
			}
			if err := p.Provision(ctx, tenantA); err != nil {
				t.Fatal(err)
			}
			expect(t, f, "acme.example.com", TypeCNAME, "ingress.example.com")
			expect(t, f, "api.acme.example.com", TypeA, "192.0.2.10", "192.0.2.11")
			expect(t, f, "api.acme.example.com", TypeTXT, "tenant="+tenantA.ID)
			expect(t, f, "_tenarium.acme.example.com", TypeTXT, OwnerValuePrefix+tenantA.ID)
			expect(t, f, "_tenarium.api.acme.example.com", TypeTXT, OwnerValuePrefix+tenantA.ID)

			// Idempotent: a second run writes nothing.
			w := f.writes()
			if err := p.Provision(ctx, tenantA); err != nil {
				t.Fatal(err)
			}
			if f.writes() != w {
				t.Fatalf("second provision wrote %d changes", f.writes()-w)
			}

			if err := p.Deprovision(ctx, tenantA); err != nil {
				t.Fatal(err)
			}
			for _, n := range []string{"acme.example.com", "api.acme.example.com", "_tenarium.acme.example.com", "_tenarium.api.acme.example.com"} {
				for _, typ := range []string{TypeA, TypeCNAME, TypeTXT} {
					expect(t, f, n, typ)
				}
			}
			// Already deprovisioned and never provisioned tenants are fine.
			if err := p.Deprovision(ctx, tenantA); err != nil {
				t.Fatal(err)
			}
			if err := p.Deprovision(ctx, sdk.Tenant{ID: "never", Slug: "never"}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProvisionConvergesDrift(t *testing.T) {
	for _, prov := range providers {
		t.Run(prov, func(t *testing.T) {
			ctx := context.Background()
			p, _, f := testPlugin(t, prov, nil)
			// An owned name with stale values (left by an older config).
			f.seed("_tenarium.api.acme.example.com", TypeTXT, OwnerValuePrefix+tenantA.ID)
			f.seed("api.acme.example.com", TypeA, "192.0.2.99", "192.0.2.10")
			if err := p.Provision(ctx, tenantA); err != nil {
				t.Fatal(err)
			}
			expect(t, f, "api.acme.example.com", TypeA, "192.0.2.10", "192.0.2.11")
			w := f.writes()
			if err := p.Provision(ctx, tenantA); err != nil {
				t.Fatal(err)
			}
			if f.writes() != w {
				t.Fatal("not converged")
			}
		})
	}
}

func TestOwnershipConflicts(t *testing.T) {
	for _, prov := range providers {
		t.Run(prov, func(t *testing.T) {
			ctx := context.Background()
			for _, tc := range []struct {
				name    string
				seed    func(f fakeDNS)
				wantErr string
			}{
				{"other tenant", func(f fakeDNS) {
					f.seed("_tenarium.acme.example.com", TypeTXT, OwnerValuePrefix+tenantB.ID)
					f.seed("acme.example.com", TypeCNAME, "elsewhere.example.net")
				}, "owned by tenant " + tenantB.ID},
				{"unmarked record", func(f fakeDNS) {
					f.seed("acme.example.com", TypeCNAME, "elsewhere.example.net")
				}, "already exists without a tenarium ownership marker"},
				{"unmarked other type at cname name", func(f fakeDNS) {
					f.seed("acme.example.com", "MX", "10 mail.example.com")
				}, "cannot create CNAME"},
				{"unmarked cname at a name", func(f fakeDNS) {
					f.seed("api.acme.example.com", TypeCNAME, "x.example.net")
				}, "a CNAME exists"},
				{"foreign txt at marker name", func(f fakeDNS) {
					f.seed("_tenarium.acme.example.com", TypeTXT, "something else")
				}, "not a tenarium ownership marker"},
			} {
				p, _, f := testPlugin(t, prov, nil)
				tc.seed(f)
				w := f.writes()
				err := p.Provision(ctx, tenantA)
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("%s: error %v, want %q", tc.name, err, tc.wantErr)
				}
				if f.writes() != w {
					t.Errorf("%s: wrote despite conflict", tc.name)
				}
			}
		})
	}
}

func TestDeprovisionLeavesForeignRecords(t *testing.T) {
	for _, prov := range providers {
		t.Run(prov, func(t *testing.T) {
			ctx := context.Background()
			p, _, f := testPlugin(t, prov, nil)
			if err := p.Provision(ctx, tenantB); err != nil {
				t.Fatal(err)
			}
			// tenantA renders the same names (same slug) but owns nothing.
			if err := p.Deprovision(ctx, tenantA); err != nil {
				t.Fatal(err)
			}
			expect(t, f, "acme.example.com", TypeCNAME, "ingress.example.com")
			expect(t, f, "_tenarium.acme.example.com", TypeTXT, OwnerValuePrefix+tenantB.ID)
			// Unmarked records are left alone too.
			f.seed("unrelated.example.com", TypeA, "192.0.2.1")
			if err := p.Deprovision(ctx, sdk.Tenant{ID: "x", Slug: "unrelated"}); err != nil {
				t.Fatal(err)
			}
			expect(t, f, "unrelated.example.com", TypeA, "192.0.2.1")
		})
	}
}

func TestDeprovisionKeep(t *testing.T) {
	for _, prov := range providers {
		t.Run(prov, func(t *testing.T) {
			ctx := context.Background()
			p, _, f := testPlugin(t, prov, map[string]any{"on_deprovision": "keep"})
			if err := p.Provision(ctx, tenantA); err != nil {
				t.Fatal(err)
			}
			if err := p.Deprovision(ctx, tenantA); err != nil {
				t.Fatal(err)
			}
			expect(t, f, "acme.example.com", TypeCNAME, "ingress.example.com")
			expect(t, f, "_tenarium.acme.example.com", TypeTXT, OwnerValuePrefix+tenantA.ID)
			// The kept marker still blocks a new tenant with the same slug.
			if err := p.Provision(ctx, tenantB); err == nil || !strings.Contains(err.Error(), "owned by tenant") {
				t.Fatalf("expected ownership error, got %v", err)
			}
		})
	}
}

func TestWildcardAndCustomPrefix(t *testing.T) {
	for _, prov := range providers {
		t.Run(prov, func(t *testing.T) {
			ctx := context.Background()
			p, _, f := testPlugin(t, prov, map[string]any{
				"ownership_txt_prefix": "_owner.dns.",
				"records": []any{
					map[string]any{"name_template": "*.{{.Slug}}.example.com.", "type": "A", "values": []any{"192.0.2.5"}},
				},
			})
			if err := p.Provision(ctx, tenantA); err != nil {
				t.Fatal(err)
			}
			expect(t, f, "*.acme.example.com", TypeA, "192.0.2.5")
			expect(t, f, "_owner.dns._wildcard.acme.example.com", TypeTXT, OwnerValuePrefix+tenantA.ID)
			w := f.writes()
			if err := p.Provision(ctx, tenantA); err != nil || f.writes() != w {
				t.Fatalf("not idempotent: %v", err)
			}
			if err := p.Deprovision(ctx, tenantA); err != nil {
				t.Fatal(err)
			}
			expect(t, f, "*.acme.example.com", TypeA)
			expect(t, f, "_owner.dns._wildcard.acme.example.com", TypeTXT)
		})
	}
}

// Cloudflare is not atomic: after a failure between marker and records the
// retry must converge.
func TestCloudflarePartialFailureRetry(t *testing.T) {
	ctx := context.Background()
	p, _, f := testPlugin(t, ProviderCloudflare, nil)
	cf := f.(*fakeCloudflare)
	cf.failPost = "api.acme.example.com"
	if err := p.Provision(ctx, tenantA); err == nil || !strings.Contains(err.Error(), "injected failure") {
		t.Fatalf("expected injected failure, got %v", err)
	}
	// Markers were written first.
	expect(t, f, "_tenarium.api.acme.example.com", TypeTXT, OwnerValuePrefix+tenantA.ID)
	expect(t, f, "api.acme.example.com", TypeA)
	cf.failPost = ""
	if err := p.Provision(ctx, tenantA); err != nil {
		t.Fatal(err)
	}
	expect(t, f, "acme.example.com", TypeCNAME, "ingress.example.com")
	expect(t, f, "api.acme.example.com", TypeA, "192.0.2.10", "192.0.2.11")
}

func TestCloudflareProxiedAndZoneLookup(t *testing.T) {
	ctx := context.Background()
	p, _, f := testPlugin(t, ProviderCloudflare, map[string]any{
		"records": []any{map[string]any{"name_template": "{{.Slug}}", "type": "A", "values": []any{"192.0.2.7"}, "proxied": true, "ttl": 300}},
	})
	if err := p.Provision(ctx, tenantA); err != nil {
		t.Fatal(err)
	}
	cf := f.(*fakeCloudflare)
	var rec cfRecord
	for _, r := range cf.records {
		if r.Name == "acme.example.com" {
			rec = r
		}
	}
	if rec.Proxied == nil || !*rec.Proxied || rec.TTL != 1 || !strings.Contains(rec.Comment, tenantA.ID) {
		t.Fatalf("record %+v", rec)
	}
	if p.backend.(*cloudflareBackend).zoneID != "zone1" {
		t.Fatal("zone not looked up")
	}
	w := f.writes()
	if err := p.Provision(ctx, tenantA); err != nil || f.writes() != w {
		t.Fatalf("not idempotent: %v", err)
	}
	// Changing proxying patches in place.
	p.records[0].proxied = false
	p.records[0].ttl = 300
	if err := p.Provision(ctx, tenantA); err != nil {
		t.Fatal(err)
	}
	for _, r := range cf.records {
		if r.Name == "acme.example.com" && (*r.Proxied || r.TTL != 300 || r.ID != rec.ID) {
			t.Fatalf("not patched: %+v", r)
		}
	}
}

func TestCloudflareAuthError(t *testing.T) {
	p, _, f := testPlugin(t, ProviderCloudflare, nil)
	f.(*fakeCloudflare).token = "other"
	err := p.Health(context.Background())
	if err == nil || !strings.Contains(err.Error(), "Invalid API Token") {
		t.Fatalf("health error %v", err)
	}
}

func TestRoute53HostedZoneLookupAndHealth(t *testing.T) {
	ctx := context.Background()
	p, _, f := testPlugin(t, ProviderRoute53, nil)
	if err := p.Health(ctx); err != nil {
		t.Fatal(err)
	}
	if id := p.backend.(*route53Backend).zoneID; id != "Z123" {
		t.Fatalf("zone id %q", id)
	}
	f.(*fakeRoute53).zone = "example.org."
	p.backend.(*route53Backend).zoneID = ""
	if err := p.Health(ctx); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not found, got %v", err)
	}
}

// A concurrent writer between the ownership check and the batch makes the
// atomic Route 53 batch fail instead of overwriting.
func TestRoute53CreateIsAtomic(t *testing.T) {
	ctx := context.Background()
	p, _, f := testPlugin(t, ProviderRoute53, nil)
	r := &racingRoute53{fakeRoute53: f.(*fakeRoute53)}
	p.backend.(*route53Backend).api = r
	if err := p.Provision(ctx, tenantA); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected batch failure, got %v", err)
	}
	expect(t, f, "acme.example.com", TypeCNAME, "racer.example.net")
	expect(t, f, "_tenarium.acme.example.com", TypeTXT)
}

type racingRoute53 struct{ *fakeRoute53 }

func (r *racingRoute53) ChangeResourceRecordSets(ctx context.Context, in *route53.ChangeResourceRecordSetsInput, o ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error) {
	r.seed("acme.example.com", TypeCNAME, "racer.example.net")
	return r.fakeRoute53.ChangeResourceRecordSets(ctx, in, o...)
}

func TestServeTenant(t *testing.T) {
	p, reg, _ := testPlugin(t, ProviderCloudflare, nil)
	host := reg.HostImpl
	ten := host.AddTenant(sdk.Tenant{Slug: "acme"})
	other := host.AddTenant(sdk.Tenant{Slug: "other"})
	_ = p
	call := func(principal *sdk.Principal, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if principal != nil {
			req = req.WithContext(sdk.WithPrincipal(req.Context(), principal))
		}
		rec := httptest.NewRecorder()
		reg.Mux.ServeHTTP(rec, req)
		return rec
	}
	rec := call(&sdk.Principal{Subject: "admin"}, "/tenants/acme")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var info TenantInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	if info.Provider != "cloudflare" || info.Zone != "example.com" || len(info.Records) != 3 ||
		info.Records[0].Name != "acme.example.com" || info.Records[0].Type != "CNAME" ||
		info.Records[1].TTL != 120 || info.Records[2].Values[0] != "tenant="+ten.ID {
		t.Fatalf("info %+v", info)
	}
	if strings.Contains(rec.Body.String(), "tok") {
		t.Fatal("token leaked")
	}
	// Same-tenant principal is allowed; another tenant's gets 404.
	if rec := call(&sdk.Principal{Subject: "u", TenantID: ten.ID}, "/tenants/"+ten.ID); rec.Code != http.StatusOK {
		t.Fatalf("own tenant status %d", rec.Code)
	}
	if rec := call(&sdk.Principal{Subject: "u", TenantID: other.ID}, "/tenants/acme"); rec.Code != http.StatusNotFound {
		t.Fatalf("foreign tenant status %d", rec.Code)
	}
	if rec := call(nil, "/tenants/acme"); rec.Code != http.StatusNotFound {
		t.Fatalf("anonymous status %d", rec.Code)
	}
	if rec := call(&sdk.Principal{Subject: "admin"}, "/tenants/missing"); rec.Code != http.StatusNotFound {
		t.Fatalf("missing status %d", rec.Code)
	}
}
