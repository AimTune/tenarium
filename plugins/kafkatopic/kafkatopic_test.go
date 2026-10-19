package kafkatopic

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
	"github.com/twmb/franz-go/pkg/kmsg"
)

const testSecret = "0123456789abcdef-secret"

// newTestPlugin initializes the plugin with cfg (brokers defaulted) and
// swaps in an in-memory admin.
func newTestPlugin(t *testing.T, cfg map[string]any) (*Plugin, *sdktest.Registrar, *fakeAdmin) {
	t.Helper()
	if _, ok := cfg["brokers"]; !ok {
		cfg["brokers"] = []string{"localhost:9"}
	}
	reg := sdktest.NewRegistrar(cfg)
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	p.adm.Close()
	f := newFakeAdmin()
	p.adm = f
	return p, reg, f
}

func TestSanitizeName(t *testing.T) {
	for in, want := range map[string]string{
		"tenant-acme":       "tenant-acme",
		"Tenant.Acme Corp":  "tenant-acme-corp",
		"a..b--c__d":        "a-b-c__d",
		"--x--":             "x",
		"ümlaut":            "mlaut",
		"":                  "",
		`x"; rm -rf /; y`:   "x-rm-rf-y",
		"prod.tenant.acme.": "prod-tenant-acme",
	} {
		if got := SanitizeName(in); got != want {
			t.Errorf("SanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	gp := "grp."
	for _, tc := range []struct {
		cfg     Config
		wantErr string
	}{
		{Config{Brokers: []string{"k:9092"}}, ""},
		{Config{}, "brokers is required"},
		{Config{Brokers: []string{"kafka://k:9092"}}, "host:port"},
		{Config{Brokers: []string{"k:9092"}, SASL: &SASLConfig{Mechanism: "GSSAPI", Username: "u"}}, "unsupported"},
		{Config{Brokers: []string{"k:9092"}, SASL: &SASLConfig{Mechanism: "PLAIN"}}, "sasl.username"},
		{Config{Brokers: []string{"k:9092"}, TopicPrefix: "bad prefix"}, "topic_prefix"},
		{Config{Brokers: []string{"k:9092"}, GroupPrefix: &gp}, ""},
		{Config{Brokers: []string{"k:9092"}, OnDeprovision: "archive"}, "on_deprovision"},
		{Config{Brokers: []string{"k:9092"}, Topics: []TopicConfig{{Name: "a b"}}}, "topics[0].name"},
		{Config{Brokers: []string{"k:9092"}, Topics: []TopicConfig{{Name: "a"}, {Name: "a"}}}, "duplicated"},
		{Config{Brokers: []string{"k:9092"}, Topics: []TopicConfig{{Name: "a", Partitions: -2}}}, "partitions"},
		{Config{Brokers: []string{"k:9092"}, Topics: []TopicConfig{{Name: "a", ReplicationFactor: -3}}}, "replication_factor"},
		{Config{Brokers: []string{"k:9092"}, Topics: []TopicConfig{{Name: "a", Configs: map[string]string{" ": "x"}}}}, "empty key"},
		{Config{Brokers: []string{"k:9092"}, MaxPartitions: -1}, "max_partitions"},
		{Config{Brokers: []string{"k:9092"}, ACL: ACLConfig{TopicOperations: []string{"all"}}}, "acl.topic_operations"},
		{Config{Brokers: []string{"k:9092"}, ACL: ACLConfig{GroupOperations: []string{"write"}}}, "acl.group_operations"},
		{Config{Brokers: []string{"k:9092"}, SCRAM: &SCRAMConfig{}}, "password_secret"},
		{Config{Brokers: []string{"k:9092"}, SCRAM: &SCRAMConfig{PasswordSecret: testSecret, Mechanism: "MD5"}}, "scram.mechanism"},
		{Config{Brokers: []string{"k:9092"}, SCRAM: &SCRAMConfig{PasswordSecret: testSecret, Iterations: 100}}, "iterations"},
		{Config{Brokers: []string{"k:9092"}, ClientQuotas: map[string]string{"bytes": "x"}}, "unknown quota"},
		{Config{Brokers: []string{"k:9092"}, ClientQuotas: map[string]string{"producer_byte_rate": ""}}, "empty"},
		{Config{Brokers: []string{"k:9092"}, NameTemplate: "t-{{.Slug"}, "name_template"},
		{Config{Brokers: []string{"k:9092"}, NameTemplate: "t-{{.Nope}}"}, "name_template"},
		{Config{Brokers: []string{"k:9092"}, NameTemplate: "{{if false}}x{{end}}"}, "empty name"},
		{Config{Brokers: []string{"k:9092"}, NameTemplate: "static"}, "name_template must depend"},
		{Config{Brokers: []string{"k:9092"}, UserTemplate: "svc"}, "user_template must depend"},
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
}

func TestTargetAndDefaults(t *testing.T) {
	p := &Plugin{cfg: Config{Brokers: []string{"k:9092"}, TopicPrefix: "prod.", Topics: []TopicConfig{{Name: "events"}, {Name: "audit.log"}}}}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	if p.cfg.OnDeprovision != DeprovisionDelete || p.cfg.ACL.Host != "*" || *p.cfg.GroupPrefix != "prod." ||
		p.cfg.Topics[0].Partitions != -1 || p.cfg.Topics[0].ReplicationFactor != -1 {
		t.Fatalf("defaults not applied: %+v", p.cfg)
	}
	tg, err := p.target(sdk.Tenant{ID: "id-1", Slug: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	want := target{
		Name: "tenant-acme", User: "tenant-acme", Principal: "User:tenant-acme",
		TopicPrefix: "prod.tenant-acme.", GroupPrefix: "prod.tenant-acme.",
		Topics: []string{"prod.tenant-acme.events", "prod.tenant-acme.audit.log"},
	}
	if tg.Name != want.Name || tg.User != want.User || tg.Principal != want.Principal ||
		tg.TopicPrefix != want.TopicPrefix || tg.GroupPrefix != want.GroupPrefix || !slices.Equal(tg.Topics, want.Topics) {
		t.Fatalf("target = %+v, want %+v", tg, want)
	}

	// Prefixes of different tenants never nest, even when slugs do.
	a, _ := p.target(sdk.Tenant{ID: "1", Slug: "acme"})
	b, _ := p.target(sdk.Tenant{ID: "2", Slug: "acme-corp"})
	if strings.HasPrefix(b.TopicPrefix, a.TopicPrefix) || strings.HasPrefix(b.GroupPrefix, a.GroupPrefix) {
		t.Fatalf("prefix %q nests in %q", a.TopicPrefix, b.TopicPrefix)
	}
	// Dots in slugs cannot create nesting either.
	c, _ := p.target(sdk.Tenant{ID: "3", Slug: "acme.x"})
	if strings.HasPrefix(c.TopicPrefix, a.TopicPrefix) {
		t.Fatalf("prefix %q nests in %q", a.TopicPrefix, c.TopicPrefix)
	}

	// Long names are shortened with a tenant hash and stay distinct.
	long := strings.Repeat("very-long-slug-", 20)
	l1, err := p.target(sdk.Tenant{ID: "1", Slug: long})
	if err != nil {
		t.Fatal(err)
	}
	l2, _ := p.target(sdk.Tenant{ID: "2", Slug: long})
	if l1.Name == l2.Name || len(l1.Topics[1]) > maxTopicLen {
		t.Fatalf("long names: %q %q (%d)", l1.Name, l2.Name, len(l1.Topics[1]))
	}

	// A separate user template.
	p = &Plugin{cfg: Config{Brokers: []string{"k:9092"}, UserTemplate: "svc-{{.Slug}}"}}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	tg, _ = p.target(sdk.Tenant{ID: "1", Slug: "acme"})
	if tg.User != "svc-acme" || tg.Principal != "User:svc-acme" {
		t.Fatalf("user %+v", tg)
	}
}

func TestConfigSchemaCompiles(t *testing.T) {
	m := (&Plugin{}).Manifest()
	if m.ID != "kafka-tenant" {
		t.Fatalf("id %q", m.ID)
	}
	s, err := schema.Compile(m.ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	valid := map[string]any{
		"brokers": []any{"k:9092"},
		"sasl":    map[string]any{"mechanism": "SCRAM-SHA-512", "username": "admin", "password": "x"},
		"tls":     map[string]any{"enabled": true},
		"topics": []any{map[string]any{
			"name": "events", "partitions": 3, "replication_factor": 3,
			"configs": map[string]any{"retention.ms": "86400000"},
		}},
		"partitions_from_limit": "kafka_partitions",
		"acl":                   map[string]any{"topic_operations": []any{"read", "write"}, "transactional_ids": true},
		"scram":                 map[string]any{"password_secret": testSecret},
		"client_quotas":         map[string]any{"producer_byte_rate": "kafka_produce_bps"},
		"on_deprovision":        "retain",
	}
	if err := s.Validate(valid); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []map[string]any{
		{},
		{"brokers": []any{"k:9092"}, "unknown": 1},
		{"brokers": []any{"k:9092"}, "on_deprovision": "drop"},
		{"brokers": []any{"k:9092"}, "client_quotas": map[string]any{"bytes": "x"}},
		{"brokers": []any{"k:9092"}, "topics": []any{map[string]any{"name": "a", "extra": 1}}},
		{"brokers": []any{"k:9092"}, "acl": map[string]any{"topic_operations": []any{"all"}}},
	} {
		if err := s.Validate(bad); err == nil {
			t.Errorf("expected schema error for %v", bad)
		}
	}
}

func TestInitRegisters(t *testing.T) {
	p, reg, _ := newTestPlugin(t, map[string]any{})
	if len(reg.Provisioners) != 1 || reg.Provisioners[0].Name() != "kafka-topics" {
		t.Fatalf("provisioners %v", reg.Provisioners)
	}
	if !slices.Equal(reg.Routes, []string{"GET /tenants/{tenant}"}) {
		t.Fatalf("routes %v", reg.Routes)
	}
	var _ sdk.HealthChecker = p
	var _ sdk.Stopper = p
	_, reg, _ = newTestPlugin(t, map[string]any{"scram": map[string]any{"password_secret": testSecret}})
	if !slices.Contains(reg.Routes, "GET /tenants/{tenant}/credentials") {
		t.Fatalf("routes %v", reg.Routes)
	}
}

func fullConfig() map[string]any {
	return map[string]any{
		"topics": []any{
			map[string]any{"name": "events", "partitions": 3, "configs": map[string]any{"retention.ms": "1000"}},
			map[string]any{"name": "audit"},
		},
		"partitions_from_limit": "kafka_partitions",
		"max_partitions":        12,
		"acl":                   map[string]any{"transactional_ids": true},
		"scram":                 map[string]any{"password_secret": testSecret},
		"client_quotas":         map[string]any{"producer_byte_rate": "kafka_produce_bps", "consumer_byte_rate": "kafka_consume_bps"},
	}
}

func TestProvisionAndIdempotency(t *testing.T) {
	ctx := context.Background()
	p, reg, f := newTestPlugin(t, fullConfig())
	reg.HostImpl.AddPlan(sdk.Plan{ID: "pro", Limits: map[string]int64{"kafka_produce_bps": 1048576}})
	tenant := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})

	for range 2 {
		if err := p.Provision(ctx, tenant); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.topics) != 2 || f.topics["tenant-acme.events"].Partitions != 3 ||
		f.topics["tenant-acme.events"].Configs["retention.ms"] != "1000" || f.topics["tenant-acme.audit"].Partitions != 1 {
		t.Fatalf("topics %+v", f.topics)
	}
	if n := strings.Count(strings.Join(f.calls, "\n"), "create-topic"); n != 2 {
		t.Fatalf("topics created %d times, want 2 (idempotent)", n)
	}
	acls := f.aclsOf("User:tenant-acme")
	// 3 topic ops + 2 group ops + 2 transactional ID ops.
	if len(acls) != 7 {
		t.Fatalf("acls %v", acls)
	}
	for _, a := range acls {
		if a.Pattern != kmsg.ACLResourcePatternTypePrefixed || a.Perm != kmsg.ACLPermissionTypeAllow || a.Host != "*" {
			t.Fatalf("bad acl %v", a)
		}
	}
	marker := f.aclsOf(OwnerPrincipalPrefix + tenant.ID)
	if len(marker) != 1 || marker[0].Perm != kmsg.ACLPermissionTypeDeny || marker[0].Name != "tenant-acme." {
		t.Fatalf("marker %v", marker)
	}
	if f.scram["tenant-acme"] != TenantPassword(testSecret, tenant.ID) {
		t.Fatalf("scram %v", f.scram)
	}
	if q := f.quotas["tenant-acme"]; len(q) != 1 || q["producer_byte_rate"] != 1048576 {
		t.Fatalf("quotas %v", f.quotas)
	}

	// A plan upgrade raises partitions (capped) and quotas; removing an
	// operation from the config revokes its ACL.
	reg.HostImpl.AddPlan(sdk.Plan{ID: "pro", Limits: map[string]int64{"kafka_partitions": 50, "kafka_consume_bps": 10}})
	p.groupOps = p.groupOps[:1] // read only
	if err := p.Provision(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if f.topics["tenant-acme.events"].Partitions != 12 || f.topics["tenant-acme.audit"].Partitions != 12 {
		t.Fatalf("partitions not raised: %+v %+v", f.topics["tenant-acme.events"], f.topics["tenant-acme.audit"])
	}
	if q := f.quotas["tenant-acme"]; len(q) != 1 || q["consumer_byte_rate"] != 10 {
		t.Fatalf("quotas %v", f.quotas)
	}
	if acls := f.aclsOf("User:tenant-acme"); len(acls) != 6 {
		t.Fatalf("stale ACL not removed: %v", acls)
	}
	// A downgrade never shrinks partitions.
	reg.HostImpl.AddPlan(sdk.Plan{ID: "pro", Limits: map[string]int64{"kafka_partitions": 2}})
	if err := p.Provision(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if f.topics["tenant-acme.events"].Partitions != 12 {
		t.Fatal("partitions shrunk")
	}
}

func TestOwnershipConflicts(t *testing.T) {
	ctx := context.Background()
	p, reg, f := newTestPlugin(t, fullConfig())
	a := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	if err := p.Provision(ctx, a); err != nil {
		t.Fatal(err)
	}
	// Another tenant whose slug renders the same prefix (e.g. after keep).
	b := reg.HostImpl.AddTenant(sdk.Tenant{ID: "other-tenant", Slug: "acme"})
	if err := p.Provision(ctx, b); err == nil || !strings.Contains(err.Error(), "belongs to tenant") {
		t.Fatalf("expected ownership conflict, got %v", err)
	}
	// Deprovisioning the other tenant leaves acme's resources alone.
	if err := p.Deprovision(ctx, b); err != nil {
		t.Fatal(err)
	}
	if len(f.topics) != 2 || len(f.aclsOf("User:tenant-acme")) == 0 || f.scram["tenant-acme"] == "" {
		t.Fatal("foreign deprovision touched acme")
	}

	// Unmarked topics under a prefix are not adopted.
	f.topics["tenant-beta.legacy"] = &fakeTopic{Partitions: 1}
	beta := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "beta"})
	if err := p.Provision(ctx, beta); err == nil || !strings.Contains(err.Error(), "without a tenarium ownership marker") {
		t.Fatalf("expected adoption refusal, got %v", err)
	}
	// A pre-existing SCRAM user is not taken over.
	f.scram["tenant-gamma"] = "theirs"
	gamma := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "gamma"})
	if err := p.Provision(ctx, gamma); err == nil || !strings.Contains(err.Error(), "SCRAM user") {
		t.Fatalf("expected SCRAM refusal, got %v", err)
	}
	if f.scram["tenant-gamma"] != "theirs" {
		t.Fatal("SCRAM password overwritten")
	}
	// Never-provisioned tenants deprovision cleanly.
	if err := p.Deprovision(ctx, sdk.Tenant{ID: "ghost", Slug: "ghost"}); err != nil {
		t.Fatal(err)
	}
}

func TestDeprovisionModes(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{DeprovisionDelete, DeprovisionKeep, DeprovisionRetain} {
		t.Run(mode, func(t *testing.T) {
			cfg := fullConfig()
			cfg["on_deprovision"] = mode
			p, reg, f := newTestPlugin(t, cfg)
			reg.HostImpl.AddPlan(sdk.Plan{ID: "pro", Limits: map[string]int64{"kafka_produce_bps": 5}})
			tenant := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})
			if err := p.Provision(ctx, tenant); err != nil {
				t.Fatal(err)
			}
			// A topic and a group the tenant created itself.
			f.topics["tenant-acme.own"] = &fakeTopic{Partitions: 1}
			f.groups = []string{"tenant-acme.workers", "tenant-acme-corp.workers", "other"}
			for range 2 { // idempotent
				if err := p.Deprovision(ctx, tenant); err != nil {
					t.Fatal(err)
				}
			}
			// Access is revoked in every mode.
			if len(f.aclsOf("User:tenant-acme")) != 0 || len(f.scram) != 0 || len(f.quotas) != 0 {
				t.Fatalf("access not revoked: acls=%v scram=%v quotas=%v", f.aclsOf("User:tenant-acme"), f.scram, f.quotas)
			}
			owner := f.aclsOf(OwnerPrincipalPrefix + tenant.ID)
			retained := f.aclsOf(RetainedPrincipalPrefix + tenant.ID)
			switch mode {
			case DeprovisionDelete:
				if len(f.topics) != 0 || len(owner) != 0 || len(retained) != 0 {
					t.Fatalf("delete left topics=%v owner=%v retained=%v", f.topics, owner, retained)
				}
				if !slices.Equal(f.groups, []string{"tenant-acme-corp.workers", "other"}) {
					t.Fatalf("groups %v", f.groups)
				}
			case DeprovisionKeep:
				if len(f.topics) != 3 || len(owner) != 1 || len(retained) != 0 {
					t.Fatalf("keep: topics=%v owner=%v retained=%v", f.topics, owner, retained)
				}
				// The kept prefix cannot be claimed by a new tenant.
				if err := p.Provision(ctx, reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})); err == nil {
					t.Fatal("kept prefix was adopted")
				}
			case DeprovisionRetain:
				if len(f.topics) != 3 || len(owner) != 0 || len(retained) != 1 {
					t.Fatalf("retain: topics=%v owner=%v retained=%v", f.topics, owner, retained)
				}
				if err := p.Provision(ctx, reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})); err == nil ||
					!strings.Contains(err.Error(), "retained data") {
					t.Fatalf("retained prefix: %v", err)
				}
			}
		})
	}
}

func TestRoutes(t *testing.T) {
	p, reg, _ := newTestPlugin(t, fullConfig())
	acme := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	other := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "other"})
	_ = p

	do := func(path string, principal *sdk.Principal) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if principal != nil {
			req = req.WithContext(sdk.WithPrincipal(req.Context(), principal))
		}
		rec := httptest.NewRecorder()
		reg.Mux.ServeHTTP(rec, req)
		return rec
	}
	platform := &sdk.Principal{Subject: "admin", Kind: "user"}
	scoped := &sdk.Principal{Subject: "u", Kind: "user", TenantID: other.ID}

	rec := do("/tenants/acme", platform)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var info TenantInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	if info.Principal != "User:tenant-acme" || info.TopicPrefix != "tenant-acme." || info.TransactionalIDPrefix != "tenant-acme." ||
		len(info.Topics) != 2 || info.SASLMechanism != "SCRAM-SHA-512" || strings.Contains(rec.Body.String(), "password") {
		t.Fatalf("info %s", rec.Body)
	}
	if rec := do("/tenants/acme", scoped); rec.Code != http.StatusNotFound {
		t.Fatalf("foreign tenant: status %d", rec.Code)
	}
	if rec := do("/tenants/missing", platform); rec.Code != http.StatusNotFound {
		t.Fatalf("missing tenant: status %d", rec.Code)
	}

	rec = do("/tenants/"+acme.ID+"/credentials", platform)
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("credentials: %d %v", rec.Code, rec.Header())
	}
	var cred Credentials
	_ = json.Unmarshal(rec.Body.Bytes(), &cred)
	if cred.User != "tenant-acme" || cred.Password != TenantPassword(testSecret, acme.ID) {
		t.Fatalf("credentials %+v", cred)
	}
	if rec := do("/tenants/acme/credentials", scoped); rec.Code != http.StatusNotFound {
		t.Fatalf("foreign credentials: status %d", rec.Code)
	}
	// Readers without tenants:update get 403.
	reg.HostImpl.AuthorizeFunc = func(_ context.Context, _ *sdk.Principal, a sdk.Action, _ sdk.Resource) error {
		if a == sdk.ActionTenantsRead {
			return nil
		}
		return sdk.ErrForbidden
	}
	if rec := do("/tenants/acme/credentials", platform); rec.Code != http.StatusForbidden {
		t.Fatalf("reader credentials: status %d", rec.Code)
	}
}

func TestTenantPassword(t *testing.T) {
	a := TenantPassword("secret", "t1")
	if len(a) != 64 || a != TenantPassword("secret", "t1") || a == TenantPassword("secret", "t2") || a == TenantPassword("other", "t1") {
		t.Fatalf("password %q", a)
	}
}
