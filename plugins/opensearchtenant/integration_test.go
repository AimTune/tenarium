package opensearchtenant

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

// Integration tests run against a real cluster named by
// TENARIUM_TEST_OPENSEARCH_URL, e.g.
//
//	docker run -d -p 9200:9200 -e discovery.type=single-node \
//	  -e DISABLE_SECURITY_PLUGIN=true opensearchproject/opensearch:2
//
// Optional: TENARIUM_TEST_OPENSEARCH_USER / _PASSWORD (basic auth),
// TENARIUM_TEST_OPENSEARCH_INSECURE=1 (skip TLS verification),
// TENARIUM_TEST_OPENSEARCH_FLAVOR (opensearch or elasticsearch) and
// TENARIUM_TEST_OPENSEARCH_SECURITY=1 to also test roles and users (needs
// the OpenSearch Security plugin or Elasticsearch security and an admin
// user).

func integrationConfig(t *testing.T, cfg map[string]any) map[string]any {
	t.Helper()
	u := os.Getenv("TENARIUM_TEST_OPENSEARCH_URL")
	if u == "" {
		t.Skip("TENARIUM_TEST_OPENSEARCH_URL not set")
	}
	full := map[string]any{"url": u}
	if v := os.Getenv("TENARIUM_TEST_OPENSEARCH_USER"); v != "" {
		full["username"] = v
		full["password"] = os.Getenv("TENARIUM_TEST_OPENSEARCH_PASSWORD")
	}
	if os.Getenv("TENARIUM_TEST_OPENSEARCH_INSECURE") == "1" {
		full["tls"] = map[string]any{"insecure_skip_verify": true}
	}
	if v := os.Getenv("TENARIUM_TEST_OPENSEARCH_FLAVOR"); v != "" {
		full["flavor"] = v
	}
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

func randSlug(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "it-" + hex.EncodeToString(b)
}

// cleanup force-removes everything of prefix at the end of the test.
func cleanup(t *testing.T, p *Plugin, n names) {
	t.Cleanup(func() {
		ctx := context.Background()
		_ = p.deleteIndices(ctx, n.Pattern)
		for k, name := range map[objectKind]string{kindTemplate: n.Template, kindRole: n.Prefix, kindUser: n.Prefix, kindMapping: n.Prefix} {
			if k != kindTemplate && (!p.cfg.Security.Enabled || k == kindMapping && p.cfg.Flavor == FlavorElasticsearch) {
				continue
			}
			_ = p.deleteObject(ctx, object{Kind: k, Name: name, Path: p.objectPath(k, name)})
		}
	})
}

func exists(t *testing.T, p *Plugin, path string) bool {
	t.Helper()
	err := p.client.do(context.Background(), http.MethodGet, path, nil, nil, nil)
	if isNotFound(err) {
		return false
	} else if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return true
}

func TestIntegrationIndexPrefix(t *testing.T) {
	ctx := context.Background()
	p, reg := newIntegrationPlugin(t, map[string]any{
		"index_template": map[string]any{
			"shards": 1, "replicas": 0,
			"mappings": map[string]any{"properties": map[string]any{"title": map[string]any{"type": "keyword"}}},
		},
		"create_initial_index": "000001",
		"initial_alias":        "write",
		"quota_from_limit":     "search_indices",
	})
	slug := randSlug(t)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug, Name: slug, Limits: map[string]int64{"search_indices": 7}})
	n, err := p.names(tn)
	if err != nil {
		t.Fatal(err)
	}
	cleanup(t, p, n)

	// Wildcard deletes are refused, as on hardened clusters.
	setting := func(v any) {
		err := p.client.do(ctx, http.MethodPut, "/_cluster/settings", nil,
			map[string]any{"transient": map[string]any{"action.destructive_requires_name": v}}, nil)
		if err != nil {
			t.Fatalf("cluster settings: %v", err)
		}
	}
	setting(true)
	t.Cleanup(func() { setting(nil) })

	for range 2 {
		if err := p.Provision(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	tmpl, err := p.getObject(ctx, kindTemplate, n.Template)
	if err != nil || tmpl.TenantID != tn.ID {
		t.Fatalf("template %+v, %v", tmpl, err)
	}
	if !exists(t, p, "/"+n.Index) || !exists(t, p, "/_alias/"+n.Alias) {
		t.Fatal("initial index or alias missing")
	}
	// Write through the alias, and create another index that picks up the
	// template's mapping.
	if err := p.client.do(ctx, http.MethodPost, "/"+n.Alias+"/_doc", map[string][]string{"refresh": {"true"}},
		map[string]any{"title": "hello"}, nil); err != nil {
		t.Fatal(err)
	}
	other := n.Prefix + "-logs"
	if err := p.client.do(ctx, http.MethodPut, "/"+other, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	var mapping map[string]struct {
		Mappings struct {
			Properties map[string]map[string]any `json:"properties"`
		} `json:"mappings"`
	}
	if err := p.client.do(ctx, http.MethodGet, "/"+other+"/_mapping", nil, nil, &mapping); err != nil {
		t.Fatal(err)
	}
	if mapping[other].Mappings.Properties["title"]["type"] != "keyword" {
		t.Fatalf("template not applied: %+v", mapping)
	}
	var tresp struct {
		IndexTemplates []struct {
			IndexTemplate struct {
				Meta map[string]any `json:"_meta"`
			} `json:"index_template"`
		} `json:"index_templates"`
	}
	if err := p.client.do(ctx, http.MethodGet, "/_index_template/"+n.Template, nil, nil, &tresp); err != nil {
		t.Fatal(err)
	}
	if m := tresp.IndexTemplates[0].IndexTemplate.Meta; m[MetaQuota] != float64(7) || m[MetaQuotaLimit] != "search_indices" {
		t.Fatalf("quota meta %v", m)
	}

	// Another tenant rendering the same prefix is refused and cannot
	// deprovision the first tenant's data.
	intruder := reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug, Name: "intruder"})
	if err := p.Provision(ctx, intruder); err == nil || !strings.Contains(err.Error(), "belongs to another tenant") {
		t.Fatalf("intruder provision: %v", err)
	}
	if err := p.Deprovision(ctx, intruder); err != nil {
		t.Fatal(err)
	}
	if idx, _ := p.listIndices(ctx, n.Pattern); len(idx) != 2 {
		t.Fatalf("indices after intruder deprovision: %v", idx)
	}

	for range 2 {
		if err := p.Deprovision(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	if idx, _ := p.listIndices(ctx, n.Pattern); len(idx) != 0 {
		t.Fatalf("indices left: %v", idx)
	}
	if exists(t, p, "/_index_template/"+n.Template) {
		t.Fatal("template left")
	}
}

func TestIntegrationUnmanagedAndRetain(t *testing.T) {
	ctx := context.Background()
	p, reg := newIntegrationPlugin(t, map[string]any{
		"index_template":       map[string]any{"replicas": 0},
		"create_initial_index": "000001",
		"on_deprovision":       "retain",
	})
	slug := randSlug(t)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug, Name: slug})
	n, _ := p.names(tn)
	cleanup(t, p, n)

	// An index created outside tenarium blocks the prefix.
	stray := n.Prefix + "-stray"
	if err := p.client.do(ctx, http.MethodPut, "/"+stray, nil,
		map[string]any{"settings": map[string]any{"number_of_replicas": 0}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := p.Provision(ctx, tn); err == nil || !strings.Contains(err.Error(), stray) {
		t.Fatalf("provision over stray index: %v", err)
	}
	if err := p.client.do(ctx, http.MethodDelete, "/"+stray, nil, nil, nil); err != nil {
		t.Fatal(err)
	}

	if err := p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if err := p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if !exists(t, p, "/"+n.Index) {
		t.Fatal("retained index deleted")
	}
	tmpl, err := p.getObject(ctx, kindTemplate, n.Template)
	if err != nil || tmpl.TenantID != "" || tmpl.DeletedTenantID != tn.ID {
		t.Fatalf("retained template %+v, %v", tmpl, err)
	}
	next := reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug, Name: "next"})
	if err := p.Provision(ctx, next); err == nil || !strings.Contains(err.Error(), "retained") {
		t.Fatalf("provision over retained data: %v", err)
	}
}

func TestIntegrationSecurity(t *testing.T) {
	if os.Getenv("TENARIUM_TEST_OPENSEARCH_SECURITY") != "1" {
		t.Skip("TENARIUM_TEST_OPENSEARCH_SECURITY not set")
	}
	ctx := context.Background()
	sec := map[string]any{"enabled": true, "create_user": true, "password_secret": "integration-secret"}
	if os.Getenv("TENARIUM_TEST_OPENSEARCH_FLAVOR") != FlavorElasticsearch {
		sec["backend_roles"] = []any{"tenarium-it-backend"}
	}
	p, reg := newIntegrationPlugin(t, map[string]any{
		"index_template":       map[string]any{"replicas": 0},
		"create_initial_index": "000001",
		"security":             sec,
	})
	slug := randSlug(t)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug, Name: slug})
	n, _ := p.names(tn)
	cleanup(t, p, n)
	for range 2 {
		if err := p.Provision(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	for _, k := range []objectKind{kindRole, kindUser} {
		o, err := p.getObject(ctx, k, n.Prefix)
		if err != nil || o.TenantID != tn.ID {
			t.Fatalf("%s: %+v, %v", k, o, err)
		}
	}

	// Act as the tenant user.
	cfg := p.cfg
	cfg.Username, cfg.Password, cfg.APIKey = n.User, TenantPassword("integration-secret", tn.ID), ""
	as, err := newClient(&cfg, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := as.do(ctx, http.MethodPost, "/"+n.Prefix+"-docs/_doc", nil, map[string]any{"x": 1}, nil); err != nil {
		t.Fatalf("tenant write to own prefix: %v", err)
	}
	err = as.do(ctx, http.MethodPost, "/someone_else-docs/_doc", nil, map[string]any{"x": 1}, nil)
	if statusOf(err) != http.StatusForbidden {
		t.Fatalf("tenant write outside prefix: %v", err)
	}

	// A user that is not managed by tenarium blocks provisioning.
	other := reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug + "-x", Name: "x"})
	on, _ := p.names(other)
	cleanup(t, p, on)
	if err := p.put(ctx, kindUser, on.User, map[string]any{"password": "Zr8!plmQ-uv41-Kt"}); err != nil {
		t.Fatal(err)
	}
	if err := p.Provision(ctx, other); err == nil || !strings.Contains(err.Error(), "not managed by tenarium") {
		t.Fatalf("provision over unmanaged user: %v", err)
	}

	if err := p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	for _, k := range []objectKind{kindRole, kindUser} {
		if o, err := p.getObject(ctx, k, n.Prefix); err != nil || o.Exists {
			t.Fatalf("%s left: %+v, %v", k, o, err)
		}
	}
	if idx, _ := p.listIndices(ctx, n.Pattern); len(idx) != 0 {
		t.Fatalf("indices left: %v", idx)
	}
	if err := as.do(ctx, http.MethodGet, "/_cluster/health", nil, nil, nil); statusOf(err) != http.StatusUnauthorized {
		t.Fatalf("deleted user still authenticates: %v", err)
	}
}
