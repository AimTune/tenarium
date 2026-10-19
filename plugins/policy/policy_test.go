package policy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

func TestReconfigure(t *testing.T) {
	reg := sdktest.NewRegistrar(map[string]any{"reserved_slugs": []string{"www"}, "default_plan": "free"})
	p := &Plugin{}
	ctx := context.Background()
	if err := p.Init(ctx, reg); err != nil {
		t.Fatal(err)
	}
	create := func(slug string) (*sdk.Tenant, error) {
		req := &sdk.HookRequest{Point: sdk.HookBeforeTenantCreate, Tenant: &sdk.Tenant{Slug: slug}}
		if err := p.applyDefaults(ctx, req); err != nil {
			return nil, err
		}
		return req.Tenant, p.validate(ctx, req)
	}
	if _, err := create("www"); err == nil {
		t.Fatal("reserved slug accepted")
	}

	// New rules apply to the registered hooks and route.
	err := p.Reconfigure(ctx, sdktest.NewRegistrar(map[string]any{"reserved_slugs": []string{"admin"}, "default_plan": "pro"}).Config)
	if err != nil {
		t.Fatal(err)
	}
	if tn, err := create("www"); err != nil || tn.Plan != "pro" {
		t.Fatalf("www after reconfigure: %+v %v", tn, err)
	}
	if _, err := create("admin"); err == nil {
		t.Fatal("new reserved slug accepted")
	}
	rec := httptest.NewRecorder()
	reg.Mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/rules", nil))
	if !strings.Contains(rec.Body.String(), `"admin"`) {
		t.Fatalf("rules: %s", rec.Body)
	}

	// An invalid config is rejected and the current rules stay.
	if err := p.Reconfigure(ctx, sdktest.NewRegistrar(map[string]any{"reserved_slug": []string{"x"}}).Config); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := create("admin"); err == nil {
		t.Fatal("rules lost after rejected reconfigure")
	}
}
