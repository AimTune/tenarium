package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

func TestSanitize(t *testing.T) {
	for in, want := range map[string]string{
		"tenant-acme":        "tenant-acme",
		"Tenant_Acme Corp.":  "tenant_acme-corp",
		"--x--":              "x",
		"_x_":                "x",
		`a"; path "*" {`:     "a-path",
		"ümlaut":             "mlaut",
		"":                   "",
		"tenants/acme":       "tenants-acme",
		"00000000-0000-0000": "00000000-0000-0000",
	} {
		if got := SanitizeName(in); got != want {
			t.Errorf("SanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"tenants/acme":        "tenants/acme",
		"/Tenants//Acme Co/":  "tenants/acme-co",
		"tenants/../x":        "tenants/x",
		"a/./b":               "a/b",
		"a/*/b+":              "a/b",
		"t/.hidden.":          "t/hidden",
		`x"; path "secret/*"`: "x-path-secret",
		"v1.2/x_y":            "v1.2/x_y",
	} {
		if got := SanitizePath(in); got != want {
			t.Errorf("SanitizePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRenderLimits(t *testing.T) {
	long := strings.Repeat("very-long-slug-", 20)
	a := sdk.Tenant{ID: "11111111-1111-1111-1111-111111111111", Slug: long}
	b := sdk.Tenant{ID: "22222222-2222-2222-2222-222222222222", Slug: long}

	name, err := parseTemplate("n", DefaultPolicyTemplate, renderName)
	if err != nil {
		t.Fatal(err)
	}
	na, _ := renderName(name, a)
	nb, _ := renderName(name, b)
	if na == nb || len(na) > maxNameLen || !strings.HasSuffix(na, hashSuffix(a.ID)) {
		t.Fatalf("names %q %q", na, nb)
	}
	if again, _ := renderName(name, a); again != na {
		t.Fatal("name not stable")
	}

	path, err := parseTemplate("p", "tenants/{{.Slug}}/{{.Slug}}", renderPath)
	if err != nil {
		t.Fatal(err)
	}
	pa, _ := renderPath(path, a)
	pb, _ := renderPath(path, b)
	if pa == pb || len(pa) > maxPathLen || !strings.HasPrefix(pa, "tenants/very-long") || !strings.HasSuffix(pa, hashSuffix(a.ID)) {
		t.Fatalf("paths %q %q", pa, pb)
	}
}

func baseCfg(c Config) Config {
	if c.Address == "" {
		c.Address = "http://127.0.0.1:9"
	}
	if c.Auth.Token == "" && c.Auth.AppRole == nil {
		c.Auth.Token = "root"
	}
	return c
}

func TestConfigValidation(t *testing.T) {
	for _, tc := range []struct {
		cfg     Config
		wantErr string
	}{
		{baseCfg(Config{}), ""},
		{baseCfg(Config{Address: "https://vault.example.com:8200/"}), ""},
		{baseCfg(Config{AppRole: &AppRoleConfig{TokenTTL: "1h", TokenMaxTTL: "7200", SecretIDTTL: "24h"}, Transit: &TransitConfig{}}), ""},
		{baseCfg(Config{Auth: AuthConfig{AppRole: &AuthAppRoleConfig{RoleID: "r", SecretID: "s"}}}), ""},
		{Config{Auth: AuthConfig{Token: "x"}}, "address is required"},
		{baseCfg(Config{Address: "vault:8200"}), "http(s) URL"},
		{baseCfg(Config{Address: "ftp://vault"}), "http(s) URL"},
		{baseCfg(Config{Address: "https://vault/v1"}), "must not have a path"},
		{Config{Address: "http://v"}, "one of token and approle is required"},
		{Config{Address: "http://v", Auth: AuthConfig{Token: "t", AppRole: &AuthAppRoleConfig{RoleID: "r", SecretID: "s"}}}, "exactly one"},
		{Config{Address: "http://v", Auth: AuthConfig{AppRole: &AuthAppRoleConfig{RoleID: "r"}}}, "role_id and secret_id"},
		{baseCfg(Config{Timeout: "soon"}), "timeout"},
		{baseCfg(Config{Timeout: "-1s"}), "timeout"},
		{baseCfg(Config{OnDeprovision: "archive"}), "on_deprovision"},
		{baseCfg(Config{KV: KVConfig{Mount: "bad mount"}}), "kv.mount"},
		{baseCfg(Config{KV: KVConfig{Mount: "a/../b"}}), "kv.mount"},
		{baseCfg(Config{KV: KVConfig{PathTemplate: "tenants/static"}}), "must depend on the tenant"},
		{baseCfg(Config{KV: KVConfig{PathTemplate: "{{.Nope}}"}}), "kv.path_template"},
		{baseCfg(Config{KV: KVConfig{PathTemplate: "{{if false}}x{{end}}"}}), "empty path"},
		{baseCfg(Config{Policy: PolicyConfig{NameTemplate: "tenants"}}), "policy.name_template must depend"},
		{baseCfg(Config{Policy: PolicyConfig{Capabilities: []string{"read", "sudo"}}}), "policy.capabilities"},
		{baseCfg(Config{Policy: PolicyConfig{ExtraRules: "{{.Nope}}"}}), "policy.extra_rules"},
		{baseCfg(Config{Policy: PolicyConfig{ExtraRules: "{{.Tenant"}}), "policy.extra_rules"},
		{baseCfg(Config{Policy: PolicyConfig{ExtraRules: `path "shared/{{.Prefix}}/*" { capabilities = ["read"] }`}}), ""},
		{baseCfg(Config{AppRole: &AppRoleConfig{RoleTemplate: "role"}}), "approle.role_template"},
		{baseCfg(Config{AppRole: &AppRoleConfig{TokenTTL: "1 hour"}}), "approle.token_ttl"},
		{baseCfg(Config{AppRole: &AppRoleConfig{TokenPolicies: []string{`a"b`}}}), "token_policies"},
		{baseCfg(Config{Transit: &TransitConfig{Type: "ed25519"}}), "transit.type"},
		{baseCfg(Config{Transit: &TransitConfig{KeyTemplate: "k"}}), "transit.key_template"},
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

	p := &Plugin{cfg: baseCfg(Config{
		Address: "https://vault:8200/", Namespace: "/team/",
		AppRole: &AppRoleConfig{}, Transit: &TransitConfig{},
		Auth: AuthConfig{AppRole: &AuthAppRoleConfig{RoleID: "r", SecretID: "s"}},
	})}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	c := p.cfg
	if c.Address != "https://vault:8200" || c.Namespace != "team" || c.KV.Mount != DefaultKVMount ||
		c.OnDeprovision != DeprovisionDelete || c.Auth.AppRole.Mount != DefaultAppRoleMount ||
		c.AppRole.Mount != DefaultAppRoleMount || c.Transit.Mount != DefaultTransitMount ||
		c.Transit.Type != DefaultTransitKeyType || len(c.Policy.Capabilities) != 5 {
		t.Fatalf("defaults not applied: %+v", c)
	}
	tg, err := p.target(sdk.Tenant{ID: "id", Slug: "acme-corp"})
	if err != nil || tg != (target{Prefix: "tenants/acme-corp", Policy: "tenant-acme-corp", Role: "tenant-acme-corp", Key: "tenant-acme-corp"}) {
		t.Fatalf("target = %+v, %v", tg, err)
	}

	// A slug that renders a built-in policy name is refused.
	p = &Plugin{cfg: baseCfg(Config{Policy: PolicyConfig{NameTemplate: "{{.Slug}}"}})}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.target(sdk.Tenant{ID: "x", Slug: "default"}); err == nil || !strings.Contains(err.Error(), "built-in") {
		t.Fatalf("err = %v", err)
	}
}

func TestConfigSchemaCompiles(t *testing.T) {
	m := (&Plugin{}).Manifest()
	if m.ID != "vault-tenant" || m.Version != "0.1.0" {
		t.Fatalf("manifest %+v", m)
	}
	s, err := schema.Compile(m.ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	ok := map[string]any{
		"address": "https://vault:8200", "namespace": "ns",
		"auth":           map[string]any{"approle": map[string]any{"role_id": "r", "secret_id": "s"}},
		"tls":            map[string]any{"insecure_skip_verify": true},
		"kv":             map[string]any{"mount": "kv", "path_template": "t/{{.Slug}}"},
		"policy":         map[string]any{"capabilities": []any{"read", "list"}},
		"approle":        map[string]any{"token_ttl": "1h", "token_policies": []any{"base"}},
		"transit":        map[string]any{"type": "aes128-gcm96"},
		"on_deprovision": "retain",
	}
	if err := s.Validate(ok); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []map[string]any{
		{"address": "x"},
		{"address": "x", "auth": map[string]any{}},
		{"address": "x", "auth": map[string]any{"token": "t", "approle": map[string]any{"role_id": "r", "secret_id": "s"}}},
		{"address": "x", "auth": map[string]any{"token": "t"}, "on_deprovision": "archive"},
		{"address": "x", "auth": map[string]any{"token": "t"}, "kv": map[string]any{"nope": 1}},
		{"address": "x", "auth": map[string]any{"token": "t"}, "transit": map[string]any{"type": "ed25519"}},
		{"address": "x", "auth": map[string]any{"token": "t"}, "policy": map[string]any{"capabilities": []any{"sudo"}}},
		{"address": "x", "auth": map[string]any{"token": "t"}, "extra": true},
	} {
		if err := s.Validate(bad); err == nil {
			t.Errorf("expected schema error for %v", bad)
		}
	}
}

func TestInitRegisters(t *testing.T) {
	reg := sdktest.NewRegistrar(map[string]any{"address": "http://127.0.0.1:9", "auth": map[string]any{"token": "t"}})
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if len(reg.Provisioners) != 1 || reg.Provisioners[0].Name() != "vault" {
		t.Fatalf("provisioners %v", reg.Provisioners)
	}
	if len(reg.Routes) != 1 || reg.Routes[0] != "GET /tenants/{tenant}" {
		t.Fatalf("routes %v", reg.Routes)
	}
	var _ sdk.HealthChecker = p
	var _ sdk.Stopper = p

	reg = sdktest.NewRegistrar(map[string]any{"address": "http://127.0.0.1:9", "auth": map[string]any{"token": "t"}, "approle": map[string]any{}})
	if err := (&Plugin{}).Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if len(reg.Routes) != 2 || reg.Routes[1] != "POST /tenants/{tenant}/secret-id" {
		t.Fatalf("routes %v", reg.Routes)
	}

	reg = sdktest.NewRegistrar(map[string]any{"address": "http://127.0.0.1:9", "auth": map[string]any{"token": "t"}, "tls": map[string]any{"ca_file": "does-not-exist.pem"}})
	if err := (&Plugin{}).Init(context.Background(), reg); err == nil || !strings.Contains(err.Error(), "tls.ca_file") {
		t.Fatalf("err = %v", err)
	}
	reg = sdktest.NewRegistrar(map[string]any{"address": "http://127.0.0.1:9", "auth": map[string]any{"token": "t"}, "unknown": 1})
	if err := (&Plugin{}).Init(context.Background(), reg); err == nil {
		t.Fatal("unknown key accepted")
	}
}

// setup initializes the plugin against a fake Vault with cfg merged over a
// token-authenticated base configuration.
func setup(t *testing.T, cfg map[string]any) (*Plugin, *sdktest.Registrar, *fakeVault) {
	t.Helper()
	f := newFakeVault(t)
	full := map[string]any{"address": f.srv.URL, "auth": map[string]any{"token": "root"}}
	for k, v := range cfg {
		full[k] = v
	}
	reg := sdktest.NewRegistrar(full)
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	return p, reg, f
}

var fullCfg = map[string]any{
	"approle": map[string]any{"token_ttl": "1h", "token_policies": []any{"shared-read"}},
	"transit": map[string]any{},
}

func TestRenderPolicy(t *testing.T) {
	p, _, _ := setup(t, map[string]any{
		"approle": map[string]any{}, "transit": map[string]any{},
		"policy": map[string]any{"extra_rules": `path "shared/data/{{.Tenant.Slug}}" { capabilities = ["read"] }`},
	})
	tn := sdk.Tenant{ID: "tid-1", Slug: "acme"}
	tg, _ := p.target(tn)
	hcl, err := p.renderPolicy(tn, tg)
	if err != nil {
		t.Fatal(err)
	}
	if policyOwner(hcl) != "tid-1" || !strings.HasPrefix(hcl, "# tenarium-tenant-id: tid-1\n") {
		t.Fatalf("header missing:\n%s", hcl)
	}
	for _, want := range []string{
		`path "secret/data/tenants/acme/*" {` + "\n" + `  capabilities = ["create", "read", "update", "delete", "list"]`,
		`path "secret/metadata/tenants/acme/*" {`,
		`path "secret/metadata/tenants/acme" {` + "\n" + `  capabilities = ["list"]`,
		`path "secret/destroy/tenants/acme/*" {` + "\n" + `  capabilities = ["update"]`,
		`path "secret/undelete/tenants/acme/*"`,
		`path "secret/data/tenants/acme/.tenarium-owner" {` + "\n" + `  capabilities = ["deny"]`,
		`path "secret/metadata/tenants/acme/.tenarium-owner"`,
		`path "transit/encrypt/tenant-acme"`,
		`path "transit/decrypt/tenant-acme"`,
		`path "transit/rewrap/tenant-acme"`,
		`path "transit/datakey/+/tenant-acme"`,
		`path "shared/data/acme" { capabilities = ["read"] }`,
	} {
		if !strings.Contains(hcl, want) {
			t.Errorf("policy lacks %q:\n%s", want, hcl)
		}
	}
	if policyOwner("path \"x\" {}") != "" || policyOwner("  # tenarium-tenant-id:  abc \npath") != "abc" {
		t.Fatal("policyOwner parsing")
	}

	// Without delete there are no delete/undelete/destroy grants.
	p, _, _ = setup(t, map[string]any{"policy": map[string]any{"capabilities": []any{"read", "list"}}})
	tg, _ = p.target(tn)
	hcl, _ = p.renderPolicy(tn, tg)
	if strings.Contains(hcl, "secret/destroy/tenants/acme/*") || strings.Contains(hcl, "transit/") {
		t.Fatalf("unexpected grants:\n%s", hcl)
	}
}

func TestProvisionIdempotent(t *testing.T) {
	p, reg, f := setup(t, fullCfg)
	ctx := context.Background()
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	for range 2 {
		if err := p.Provision(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.count("PUT", "sys/policies/acl/tenant-acme"); n != 1 {
		t.Errorf("policy written %d times", n)
	}
	if policyOwner(f.policies["tenant-acme"]) != tn.ID {
		t.Fatalf("policy %q", f.policies["tenant-acme"])
	}
	role := f.roles["tenant-acme"]
	if fmt.Sprint(role["token_policies"]) != "[tenant-acme shared-read]" || role["token_ttl"] != "1h" {
		t.Fatalf("role %v", role)
	}
	if k := f.keys["tenant-acme"]; k == nil || k.typ != "aes256-gcm96" {
		t.Fatalf("key %+v", k)
	}
	m := f.kv["tenants/acme/.tenarium-owner"]
	if m == nil || m.custom[MetaTenantID] != tn.ID || m.custom[MetaAppRoleRole] != "approle/tenant-acme" ||
		m.custom[MetaTransitKey] != "transit/tenant-acme" || m.versions != 0 {
		t.Fatalf("marker %+v", m)
	}
	if n := f.count("POST", "transit/keys/tenant-acme"); n != 1 {
		t.Errorf("key created %d times", n)
	}

	// The tenant's own data does not get in the way of re-provisioning.
	f.kv["tenants/acme/app/db"] = &kvEntry{versions: 1}
	if err := p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}

	// A changed policy is converged.
	f.policies["tenant-acme"] = "# tenarium-tenant-id: " + tn.ID + "\npath \"x\" {}"
	if err := p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.policies["tenant-acme"], "secret/data/tenants/acme/*") {
		t.Fatal("policy not converged")
	}
}

func TestProvisionAfterPartialFailure(t *testing.T) {
	p, reg, f := setup(t, fullCfg)
	ctx := context.Background()
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	if err := p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	// Simulate a run interrupted after the marker was written.
	delete(f.roles, "tenant-acme")
	delete(f.keys, "tenant-acme")
	delete(f.policies, "tenant-acme")
	if err := p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if f.roles["tenant-acme"] == nil || f.keys["tenant-acme"] == nil || f.policies["tenant-acme"] == "" {
		t.Fatal("not converged")
	}

	// Enabling approle later records the new role; disabling removes it.
	p2, _, _ := setup(t, nil)
	p2.client = p.client
	if err := p2.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if f.roles["tenant-acme"] != nil || f.kv["tenants/acme/.tenarium-owner"].custom[MetaAppRoleRole] != "" {
		t.Fatal("role of disabled approle not removed")
	}
	if f.keys["tenant-acme"] == nil {
		t.Fatal("transit key must never be removed implicitly")
	}
	if err := p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if f.roles["tenant-acme"] == nil {
		t.Fatal("role not recreated")
	}
}

func TestOwnershipConflicts(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		prepare func(f *fakeVault, other string)
		wantErr string
	}{
		"marker of another tenant": {func(f *fakeVault, other string) {
			f.kv["tenants/acme/.tenarium-owner"] = &kvEntry{custom: map[string]string{MetaTenantID: other}}
		}, "already belongs to another tenant"},
		"retained data": {func(f *fakeVault, other string) {
			f.kv["tenants/acme/.tenarium-owner"] = &kvEntry{custom: map[string]string{MetaDeletedTenantID: other, MetaDeletedAt: "2026-01-01T00:00:00Z"}}
		}, "retained from deleted tenant"},
		"unmarked data": {func(f *fakeVault, _ string) {
			f.kv["tenants/acme/foo"] = &kvEntry{versions: 1}
		}, "not empty and is not managed"},
		"unmanaged policy": {func(f *fakeVault, _ string) {
			f.policies["tenant-acme"] = `path "secret/*" { capabilities = ["read"] }`
		}, "not managed by tenarium"},
		"policy of another tenant": {func(f *fakeVault, other string) {
			f.policies["tenant-acme"] = "# tenarium-tenant-id: " + other + "\n"
		}, "policy tenant-acme already belongs to another tenant"},
		"unmanaged role": {func(f *fakeVault, _ string) {
			f.roles["tenant-acme"] = map[string]any{"token_policies": []any{"admin"}}
		}, "approle role approle/tenant-acme already exists"},
		"unmanaged key": {func(f *fakeVault, _ string) {
			f.keys["tenant-acme"] = &transitKey{typ: "aes256-gcm96"}
		}, "transit key transit/tenant-acme already exists"},
	} {
		t.Run(name, func(t *testing.T) {
			p, reg, f := setup(t, fullCfg)
			tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
			tc.prepare(f, "other-tenant-id")
			before := fmt.Sprint(f.policies, len(f.roles), len(f.keys))
			err := p.Provision(ctx, tn)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			if after := fmt.Sprint(f.policies, len(f.roles), len(f.keys)); after != before {
				t.Fatalf("state changed: %s -> %s", before, after)
			}
			if m := f.kv["tenants/acme/.tenarium-owner"]; m != nil && m.custom[MetaTenantID] == tn.ID {
				t.Fatal("prefix claimed despite the conflict")
			}
		})
	}

	// A role or key that appears after the marker was written is not
	// adopted either.
	p, reg, f := setup(t, nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	if err := p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	f.roles["tenant-acme"] = map[string]any{}
	f.keys["tenant-acme"] = &transitKey{typ: "rsa-2048"}
	p2, _, _ := setup(t, fullCfg)
	p2.client = p.client
	if err := p2.Provision(ctx, tn); err == nil || !strings.Contains(err.Error(), "not managed by tenarium for this tenant") {
		t.Fatalf("err = %v", err)
	}
}

func TestTransitKeyTypeMismatch(t *testing.T) {
	p, reg, f := setup(t, fullCfg)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	if err := p.Provision(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
	f.keys["tenant-acme"].typ = "rsa-2048"
	if err := p.Provision(context.Background(), tn); err == nil || !strings.Contains(err.Error(), "cannot be changed") {
		t.Fatalf("err = %v", err)
	}
}

func TestDeprovisionDelete(t *testing.T) {
	p, reg, f := setup(t, fullCfg)
	ctx := context.Background()
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	other := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme-two"})
	for _, x := range []sdk.Tenant{tn, other} {
		if err := p.Provision(ctx, x); err != nil {
			t.Fatal(err)
		}
	}
	f.kv["tenants/acme/db"] = &kvEntry{versions: 2}
	f.kv["tenants/acme/app/a/b"] = &kvEntry{versions: 1}
	f.kv["tenants/acme-two/db"] = &kvEntry{versions: 1}
	f.kv["unrelated"] = &kvEntry{versions: 1}

	if err := p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	for k := range f.kv {
		if strings.HasPrefix(k, "tenants/acme/") {
			t.Errorf("left %s", k)
		}
	}
	if f.kv["tenants/acme-two/db"] == nil || f.kv["tenants/acme-two/.tenarium-owner"] == nil || f.kv["unrelated"] == nil {
		t.Fatal("deleted data of others")
	}
	if _, ok := f.policies["tenant-acme"]; ok || f.roles["tenant-acme"] != nil || f.keys["tenant-acme"] != nil {
		t.Fatal("resources left")
	}
	if f.policies["tenant-acme-two"] == "" || f.roles["tenant-acme-two"] == nil || f.keys["tenant-acme-two"] == nil {
		t.Fatal("other tenant's resources deleted")
	}
	// Again, and for a tenant never provisioned.
	if err := p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if err := p.Deprovision(ctx, sdk.Tenant{ID: "never", Slug: "never"}); err != nil {
		t.Fatal(err)
	}
}

func TestDeprovisionRetainAndKeep(t *testing.T) {
	ctx := context.Background()
	p, reg, f := setup(t, map[string]any{"approle": map[string]any{}, "transit": map[string]any{}, "on_deprovision": "retain"})
	p.now = func() time.Time { return time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) }
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	if err := p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	f.kv["tenants/acme/db"] = &kvEntry{versions: 1}
	if err := p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.policies["tenant-acme"]; ok || f.roles["tenant-acme"] != nil {
		t.Fatal("access not revoked")
	}
	if f.keys["tenant-acme"] == nil || f.kv["tenants/acme/db"] == nil {
		t.Fatal("data not retained")
	}
	m := f.kv["tenants/acme/.tenarium-owner"].custom
	if m[MetaTenantID] != "" || m[MetaDeletedTenantID] != tn.ID || m[MetaDeletedAt] != "2026-10-01T00:00:00Z" ||
		m[MetaTransitKey] != "transit/tenant-acme" || m[MetaAppRoleRole] != "" {
		t.Fatalf("marker %v", m)
	}
	if err := p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	next := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	if err := p.Provision(ctx, next); err == nil || !strings.Contains(err.Error(), "retained") {
		t.Fatalf("err = %v", err)
	}

	p, reg, f = setup(t, map[string]any{"approle": map[string]any{}, "transit": map[string]any{}, "on_deprovision": "keep"})
	tn = reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	if err := p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if err := p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if f.policies["tenant-acme"] == "" || f.roles["tenant-acme"] == nil || f.keys["tenant-acme"] == nil ||
		f.kv["tenants/acme/.tenarium-owner"].custom[MetaTenantID] != tn.ID {
		t.Fatal("keep touched resources")
	}
}

func TestDeprovisionForeign(t *testing.T) {
	ctx := context.Background()
	p, reg, f := setup(t, fullCfg)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	f.kv["tenants/acme/.tenarium-owner"] = &kvEntry{custom: map[string]string{MetaTenantID: "other", MetaAppRoleRole: "approle/tenant-acme", MetaTransitKey: "transit/tenant-acme"}}
	f.kv["tenants/acme/db"] = &kvEntry{versions: 1}
	f.policies["tenant-acme"] = "# tenarium-tenant-id: other\n"
	f.roles["tenant-acme"] = map[string]any{}
	f.keys["tenant-acme"] = &transitKey{typ: "aes256-gcm96"}
	if err := p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if f.kv["tenants/acme/db"] == nil || f.policies["tenant-acme"] == "" || f.roles["tenant-acme"] == nil || f.keys["tenant-acme"] == nil {
		t.Fatal("foreign resources deleted")
	}
	// An unmanaged policy is not deleted even without a marker.
	delete(f.kv, "tenants/acme/.tenarium-owner")
	f.policies["tenant-acme"] = "path \"x\" {}"
	if err := p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if f.policies["tenant-acme"] == "" {
		t.Fatal("unmanaged policy deleted")
	}
}

func do(reg *sdktest.Registrar, method, path string, pr *sdk.Principal) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if pr != nil {
		req = req.WithContext(sdk.WithPrincipal(req.Context(), pr))
	}
	rec := httptest.NewRecorder()
	reg.Mux.ServeHTTP(rec, req)
	return rec
}

func TestRoutes(t *testing.T) {
	p, reg, f := setup(t, fullCfg)
	ctx := context.Background()
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	platform := &sdk.Principal{Subject: "admin", Kind: "user", Authenticator: "oidc"}
	own := &sdk.Principal{Subject: "u", Kind: "user", TenantID: tn.ID}
	stranger := &sdk.Principal{Subject: "s", Kind: "user", TenantID: "other"}

	// Before provisioning.
	rec := do(reg, "GET", "/tenants/acme", platform)
	var info TenantInfo
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &info) != nil || info.Provisioned || info.AppRole.RoleID != "" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec := do(reg, "POST", "/tenants/acme/secret-id", platform); rec.Code != http.StatusConflict {
		t.Fatalf("secret-id before provisioning: %d", rec.Code)
	}

	if err := p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	rec = do(reg, "GET", "/tenants/acme", own)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	info = TenantInfo{}
	_ = json.Unmarshal(rec.Body.Bytes(), &info)
	want := TenantInfo{
		Address: f.srv.URL, KVMount: "secret", KVPath: "tenants/acme", Policy: "tenant-acme", Provisioned: true,
		AppRole: &AppRoleInfo{Mount: "approle", Role: "tenant-acme", RoleID: f.roleIDs["tenant-acme"]},
		Transit: &TransitInfo{Mount: "transit", Key: "tenant-acme"},
	}
	if !reflect.DeepEqual(info, want) || want.AppRole.RoleID == "" {
		t.Fatalf("info %s", rec.Body)
	}
	if strings.Contains(rec.Body.String(), "secret_id") {
		t.Fatal("info leaks secret")
	}

	for _, tc := range []struct {
		method, path string
		pr           *sdk.Principal
		want         int
	}{
		{"GET", "/tenants/acme", stranger, 404},
		{"GET", "/tenants/nope", platform, 404},
		{"GET", "/tenants/acme", nil, 404},
		{"POST", "/tenants/acme/secret-id", stranger, 404},
		{"POST", "/tenants/nope/secret-id", platform, 404},
	} {
		if rec := do(reg, tc.method, tc.path, tc.pr); rec.Code != tc.want {
			t.Errorf("%s %s as %v: %d, want %d", tc.method, tc.path, tc.pr, rec.Code, tc.want)
		}
	}

	rec = do(reg, "POST", "/tenants/acme/secret-id", platform)
	if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	var sid SecretIDResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &sid)
	if sid.SecretID == "" || sid.SecretIDAccessor == "" || sid.SecretIDTTL != 600 || sid.RoleID != f.roleIDs["tenant-acme"] {
		t.Fatalf("secret-id %+v", sid)
	}
	if meta := f.secretIDs["tenant-acme"][0]; meta["tenarium_tenant_id"] != tn.ID || meta["tenarium_issued_by"] != "oidc:admin" {
		t.Fatalf("secret-id metadata %v", meta)
	}

	// Readers that may not update get 403.
	reg.HostImpl.AuthorizeFunc = func(_ context.Context, _ *sdk.Principal, a sdk.Action, _ sdk.Resource) error {
		if a == sdk.ActionTenantsUpdate {
			return sdk.ErrForbidden
		}
		return nil
	}
	if rec := do(reg, "POST", "/tenants/acme/secret-id", own); rec.Code != http.StatusForbidden {
		t.Fatalf("got %d", rec.Code)
	}
	reg.HostImpl.AuthorizeFunc = nil

	// A same-named role not recorded for the tenant never gets secret IDs.
	f.kv["tenants/acme/.tenarium-owner"].custom[MetaAppRoleRole] = ""
	if rec := do(reg, "POST", "/tenants/acme/secret-id", platform); rec.Code != http.StatusConflict {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestAppRoleLogin(t *testing.T) {
	f := newFakeVault(t)
	f.loginRoleID, f.loginSecretID, f.loginTTL = "plugin-role", "plugin-secret", 100
	reg := sdktest.NewRegistrar(map[string]any{
		"address": f.srv.URL, "namespace": "team-a",
		"auth": map[string]any{"approle": map[string]any{"role_id": "plugin-role", "secret_id": "plugin-secret"}},
	})
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return now }
	ctx := context.Background()
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})

	if err := p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if err := p.Health(ctx); err != nil {
		t.Fatal(err)
	}
	if f.logins != 1 {
		t.Fatalf("logins = %d, want cached token", f.logins)
	}
	if !f.namespaces["team-a"] {
		t.Fatal("namespace header not sent")
	}

	// Revoked token: one 403, re-login, retry.
	f.mu.Lock()
	for tok := range f.tokens {
		if tok != "root" {
			delete(f.tokens, tok)
		}
	}
	f.mu.Unlock()
	if err := p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if f.logins != 2 {
		t.Fatalf("logins = %d after revocation", f.logins)
	}

	// Near expiry (80% of the 100s lease): log in again proactively.
	now = now.Add(81 * time.Second)
	if err := p.Health(ctx); err != nil {
		t.Fatal(err)
	}
	if f.logins != 3 {
		t.Fatalf("logins = %d after expiry", f.logins)
	}

	// Bad credentials surface as errors.
	f.loginSecretID = "rotated"
	now = now.Add(time.Hour)
	if err := p.Health(ctx); err == nil || !strings.Contains(err.Error(), "approle login") {
		t.Fatalf("err = %v", err)
	}
}

func TestHealth(t *testing.T) {
	p, _, f := setup(t, nil)
	ctx := context.Background()
	for status, ok := range map[int]bool{200: true, 429: true, 473: true, 472: false, 501: false, 503: false, 500: false} {
		f.health = status
		if err := p.Health(ctx); (err == nil) != ok {
			t.Errorf("status %d: err = %v", status, err)
		}
	}
	f.health = 200
	p.client.token = "bad"
	if err := p.Health(ctx); err == nil || !strings.Contains(err.Error(), "token lookup") {
		t.Fatalf("err = %v", err)
	}
	if err := p.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}
