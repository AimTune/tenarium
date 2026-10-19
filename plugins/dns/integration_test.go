package dns

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
)

// Integration tests:
//
//   - Route 53: TENARIUM_TEST_ROUTE53_ENDPOINT points at a Route 53
//     compatible API such as LocalStack (http://localhost:4566). A hosted
//     zone is created per test and removed afterwards. Credentials default
//     to "test"/"test" (TENARIUM_TEST_ROUTE53_ACCESS_KEY_ID /
//     TENARIUM_TEST_ROUTE53_SECRET_ACCESS_KEY override them).
//   - Cloudflare: TENARIUM_TEST_CLOUDFLARE_API_TOKEN and
//     TENARIUM_TEST_CLOUDFLARE_ZONE_ID name a real zone; records are created
//     under a random label and removed. TENARIUM_TEST_CLOUDFLARE_BASE_URL
//     overrides the API URL.

func randHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func integrationRecords() []any {
	return []any{
		map[string]any{"name_template": "{{.Slug}}", "type": "CNAME", "values": []any{"ingress.example.net"}},
		map[string]any{"name_template": "api.{{.Slug}}", "type": "A", "values": []any{"192.0.2.10", "192.0.2.11"}, "ttl": 120},
		map[string]any{"name_template": "api.{{.Slug}}", "type": "TXT", "values": []any{"tenant={{.ID}}"}},
	}
}

// route53Zone creates a hosted zone on the test endpoint and returns its
// name and ID.
func route53Zone(t *testing.T) (zone, id string, cfg map[string]any) {
	t.Helper()
	endpoint := os.Getenv("TENARIUM_TEST_ROUTE53_ENDPOINT")
	if endpoint == "" {
		t.Skip("TENARIUM_TEST_ROUTE53_ENDPOINT not set")
	}
	r53 := &Route53Config{
		Endpoint:        endpoint,
		AccessKeyID:     envOr("TENARIUM_TEST_ROUTE53_ACCESS_KEY_ID", "test"),
		SecretAccessKey: envOr("TENARIUM_TEST_ROUTE53_SECRET_ACCESS_KEY", "test"),
	}
	if err := r53.validate(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	zone = "tenarium-" + randHex(t) + ".test"
	b, err := newRoute53(ctx, zone, r53)
	if err != nil {
		t.Fatal(err)
	}
	client := b.api.(*route53.Client)
	out, err := client.CreateHostedZone(ctx, &route53.CreateHostedZoneInput{
		Name: aws.String(zone), CallerReference: aws.String(randHex(t)),
	})
	if err != nil {
		t.Fatalf("create hosted zone: %v", err)
	}
	id = strings.TrimPrefix(aws.ToString(out.HostedZone.Id), "/hostedzone/")
	t.Cleanup(func() {
		// Remove whatever a failed test left behind, then the zone.
		list, err := client.ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{HostedZoneId: aws.String(id)})
		if err == nil {
			var changes []types.Change
			for _, rs := range list.ResourceRecordSets {
				if rs.Type != types.RRTypeSoa && rs.Type != types.RRTypeNs {
					changes = append(changes, types.Change{Action: types.ChangeActionDelete, ResourceRecordSet: &rs})
				}
			}
			if len(changes) > 0 {
				_, _ = client.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
					HostedZoneId: aws.String(id), ChangeBatch: &types.ChangeBatch{Changes: changes},
				})
			}
		}
		if _, err := client.DeleteHostedZone(ctx, &route53.DeleteHostedZoneInput{Id: aws.String(id)}); err != nil {
			t.Logf("delete hosted zone %s: %v", id, err)
		}
	})
	cfg = map[string]any{
		"endpoint": endpoint, "access_key_id": r53.AccessKeyID, "secret_access_key": r53.SecretAccessKey,
	}
	return zone, id, cfg
}

func initIntegration(t *testing.T, cfg map[string]any) (*Plugin, *sdktest.Registrar) {
	t.Helper()
	reg := sdktest.NewRegistrar(cfg)
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	return p, reg
}

// liveValues reads a set through the plugin's backend.
func liveValues(t *testing.T, p *Plugin, name, typ string) []string {
	t.Helper()
	sets, err := p.backend.lookup(context.Background(), name)
	if err != nil {
		t.Fatalf("lookup %s: %v", name, err)
	}
	s := sets[typ]
	if s == nil {
		return nil
	}
	v := slices.Clone(s.Values)
	slices.Sort(v)
	return v
}

func expectLive(t *testing.T, p *Plugin, name, typ string, want ...string) {
	t.Helper()
	slices.Sort(want)
	if got := liveValues(t, p, name, typ); !slices.Equal(got, want) {
		t.Fatalf("%s %s = %q, want %q", typ, name, got, want)
	}
}

// runLifecycle exercises provision, idempotency, ownership and deprovision
// against a live provider.
func runLifecycle(t *testing.T, p *Plugin, reg *sdktest.Registrar, zone string) {
	t.Helper()
	ctx := context.Background()
	if err := p.Health(ctx); err != nil {
		t.Fatalf("health: %v", err)
	}
	slug := "t" + randHex(t)
	a := reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug})
	b := sdk.Tenant{ID: "bbbbbbbb-0000-0000-0000-000000000002", Slug: slug}
	name := slug + "." + zone
	api := "api." + name

	if err := p.Provision(ctx, a); err != nil {
		t.Fatal(err)
	}
	expectLive(t, p, name, TypeCNAME, "ingress.example.net")
	expectLive(t, p, api, TypeA, "192.0.2.10", "192.0.2.11")
	expectLive(t, p, api, TypeTXT, "tenant="+a.ID)
	expectLive(t, p, "_tenarium."+name, TypeTXT, OwnerValuePrefix+a.ID)
	expectLive(t, p, "_tenarium."+api, TypeTXT, OwnerValuePrefix+a.ID)

	// Idempotent.
	if err := p.Provision(ctx, a); err != nil {
		t.Fatal(err)
	}
	expectLive(t, p, api, TypeA, "192.0.2.10", "192.0.2.11")

	// Another tenant with the same names is refused and cannot delete.
	if err := p.Provision(ctx, b); err == nil || !strings.Contains(err.Error(), "owned by tenant "+a.ID) {
		t.Fatalf("expected ownership error, got %v", err)
	}
	if err := p.Deprovision(ctx, b); err != nil {
		t.Fatal(err)
	}
	expectLive(t, p, name, TypeCNAME, "ingress.example.net")

	// Route.
	req := sdk.WithPrincipal(ctx, &sdk.Principal{Subject: "admin"})
	rec := httptest.NewRecorder()
	r, _ := http.NewRequestWithContext(req, http.MethodGet, "/tenants/"+slug, nil)
	reg.Mux.ServeHTTP(rec, r)
	var info TenantInfo
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &info) != nil || len(info.Records) != 3 || info.Records[0].Name != name {
		t.Fatalf("route: %d %s", rec.Code, rec.Body.String())
	}

	if err := p.Deprovision(ctx, a); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{name, api, "_tenarium." + name, "_tenarium." + api} {
		for _, typ := range []string{TypeA, TypeCNAME, TypeTXT} {
			expectLive(t, p, n, typ)
		}
	}
	if err := p.Deprovision(ctx, a); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationRoute53(t *testing.T) {
	zone, _, r53 := route53Zone(t)
	// Hosted zone looked up by name; wait for INSYNC.
	r53["wait"] = true
	r53["wait_timeout"] = "1m"
	p, reg := initIntegration(t, map[string]any{
		"provider": "route53", "zone": zone, "route53": r53, "records": integrationRecords(),
	})
	runLifecycle(t, p, reg, zone)
}

func TestIntegrationRoute53UnmarkedRecord(t *testing.T) {
	zone, id, r53 := route53Zone(t)
	r53["hosted_zone_id"] = id
	p, _ := initIntegration(t, map[string]any{
		"provider": "route53", "zone": zone, "route53": r53, "records": integrationRecords(),
	})
	ctx := context.Background()
	ten := sdk.Tenant{ID: "aaaaaaaa-0000-0000-0000-000000000001", Slug: "taken"}
	b := p.backend.(*route53Backend)
	if err := b.submit(ctx, []types.Change{{Action: types.ChangeActionCreate, ResourceRecordSet: toR53(
		rrset{Name: "taken." + zone, Type: TypeCNAME, TTL: 60, Values: []string{"someone.example.org"}})}}, "seed"); err != nil {
		t.Fatal(err)
	}
	if err := p.Provision(ctx, ten); err == nil || !strings.Contains(err.Error(), "without a tenarium ownership marker") {
		t.Fatalf("expected takeover refusal, got %v", err)
	}
	expectLive(t, p, "taken."+zone, TypeCNAME, "someone.example.org")
	expectLive(t, p, "_tenarium.taken."+zone, TypeTXT)
	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	expectLive(t, p, "taken."+zone, TypeCNAME, "someone.example.org")
}

func TestIntegrationRoute53Wildcard(t *testing.T) {
	zone, id, r53 := route53Zone(t)
	r53["hosted_zone_id"] = id
	p, _ := initIntegration(t, map[string]any{
		"provider": "route53", "zone": zone, "route53": r53,
		"records": []any{map[string]any{"name_template": "*.{{.Slug}}", "type": "A", "values": []any{"192.0.2.5"}}},
	})
	ctx := context.Background()
	ten := sdk.Tenant{ID: "aaaaaaaa-0000-0000-0000-000000000001", Slug: "wild"}
	if err := p.Provision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	expectLive(t, p, "*.wild."+zone, TypeA, "192.0.2.5")
	if err := p.Provision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	expectLive(t, p, "*.wild."+zone, TypeA)
}

func TestIntegrationCloudflare(t *testing.T) {
	token := os.Getenv("TENARIUM_TEST_CLOUDFLARE_API_TOKEN")
	zoneID := os.Getenv("TENARIUM_TEST_CLOUDFLARE_ZONE_ID")
	if token == "" || zoneID == "" {
		t.Skip("TENARIUM_TEST_CLOUDFLARE_API_TOKEN / TENARIUM_TEST_CLOUDFLARE_ZONE_ID not set")
	}
	base := envOr("TENARIUM_TEST_CLOUDFLARE_BASE_URL", DefaultCloudflareBaseURL)
	// Discover the zone name.
	probe := &cloudflareBackend{baseURL: base, token: token, zoneID: zoneID, client: http.DefaultClient}
	var z struct {
		Name string `json:"name"`
	}
	if _, err := probe.do(context.Background(), http.MethodGet, "/zones/"+zoneID, nil, nil, &z); err != nil {
		t.Fatal(err)
	}
	zone := "tenarium-" + randHex(t) + "." + z.Name
	p, reg := initIntegration(t, map[string]any{
		"provider": "cloudflare", "zone": z.Name,
		"cloudflare": map[string]any{"api_token": token, "zone_id": zoneID, "base_url": base},
		"records": []any{
			map[string]any{"name_template": "{{.Slug}}." + zone, "type": "CNAME", "values": []any{"ingress.example.net"}},
			map[string]any{"name_template": "api.{{.Slug}}." + zone, "type": "A", "values": []any{"192.0.2.10", "192.0.2.11"}, "ttl": 120},
			map[string]any{"name_template": "api.{{.Slug}}." + zone, "type": "TXT", "values": []any{"tenant={{.ID}}"}},
		},
	})
	runLifecycle(t, p, reg, zone)
}
