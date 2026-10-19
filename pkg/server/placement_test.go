package server_test

import (
	"testing"
)

func TestPlacementAPI(t *testing.T) {
	cfg := baseConfig()
	cfg.Tenants.Regions = []string{"eu", "us"}
	cfg.Tenants.DefaultRegion = "eu"
	c := client{t: t, base: startServer(t, cfg)}
	c.do("POST", "/v1/plans", map[string]any{"id": "pro", "name": "Pro", "limits": map[string]any{"seats": 10}})
	c.do("POST", "/v1/plans", map[string]any{"id": "seats-10", "name": "10 seats", "limits": map[string]any{"seats": 10}})
	code, tn := c.do("POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme", "plan": "pro", "add_ons": []string{"seats-10"}})
	if code != 201 || tn["region"] != "eu" {
		t.Fatalf("create: %d %v", code, tn)
	}
	_, ak := c.do("POST", "/v1/tenants/acme/api-keys", map[string]any{"name": "owner", "roles": []string{"owner"}})
	owner := as(c, ak["key"].(string))

	// Grandfather existing tenants, then check revisions and pinning.
	if code, _ := c.do("PATCH", "/v1/plans/pro", map[string]any{"limits": map[string]any{"seats": 3}, "grandfather": true}); code != 200 {
		t.Fatalf("update plan: %d", code)
	}
	_, e := c.do("GET", "/v1/tenants/acme/entitlements", nil)
	if e["limits"].(map[string]any)["seats"].(float64) != 20 || e["plan_revision"].(float64) != 1 {
		t.Fatalf("entitlements: %v", e)
	}
	if _, revs := c.do("GET", "/v1/plans/pro/revisions", nil); len(revs["items"].([]any)) != 2 {
		t.Fatalf("revisions: %v", revs)
	}
	if code, _ := owner("PUT", "/v1/tenants/acme/plan-revision", map[string]any{"revision": 0}); code != 403 {
		t.Fatalf("tenant unpinned itself: %d", code)
	}
	if code, _ := c.do("PUT", "/v1/tenants/acme/plan-revision", map[string]any{"revision": 0}); code != 200 {
		t.Fatalf("unpin: %d", code)
	}
	if _, e := c.do("GET", "/v1/tenants/acme/entitlements", nil); e["limits"].(map[string]any)["seats"].(float64) != 13 {
		t.Fatalf("after unpin: %v", e)
	}
	// Tenants cannot buy themselves add-ons.
	if code, _ := owner("PATCH", "/v1/tenants/acme", map[string]any{"add_ons": []string{}}); code != 403 {
		t.Fatalf("tenant changed add-ons: %d", code)
	}

	// Rollouts are platform-only.
	if code, _ := owner("GET", "/v1/rollouts", nil); code != 403 {
		t.Fatalf("tenant read rollouts: %d", code)
	}
	code, ro := c.do("PUT", "/v1/rollouts/beta", map[string]any{"percentage": 100, "enabled": true, "regions": []string{"eu"}})
	if code != 200 || ro["feature"] != "beta" {
		t.Fatalf("put rollout: %d %v", code, ro)
	}
	if _, e := c.do("GET", "/v1/tenants/acme/entitlements", nil); e["features"].(map[string]any)["beta"] != true {
		t.Fatalf("rollout not applied: %v", e)
	}

	// Moving regions is platform-only and takes the tenant out of the
	// region-filtered rollout.
	if code, _ := owner("POST", "/v1/tenants/acme/move", map[string]any{"region": "us"}); code != 403 {
		t.Fatalf("tenant moved itself: %d", code)
	}
	if code, _ := c.do("POST", "/v1/tenants/acme/move", map[string]any{"region": "ap"}); code != 400 {
		t.Fatalf("unknown region: %d", code)
	}
	if code, m := c.do("POST", "/v1/tenants/acme/move", map[string]any{"region": "us"}); code != 200 || m["region"] != "us" {
		t.Fatalf("move: %d %v", code, m)
	}
	if _, e := c.do("GET", "/v1/tenants/acme/entitlements", nil); e["features"].(map[string]any)["beta"] == true {
		t.Fatalf("rollout still applied after move: %v", e)
	}
	if _, rs := c.do("GET", "/v1/regions", nil); len(rs["items"].([]any)) != 2 {
		t.Fatalf("regions: %v", rs)
	}
	if code, _ := c.do("DELETE", "/v1/rollouts/beta", nil); code != 204 {
		t.Fatalf("delete rollout: %d", code)
	}
}
