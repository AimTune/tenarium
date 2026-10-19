package client_test

import (
	"context"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/client"
)

func TestAllowanceSpendsLocally(t *testing.T) {
	ctx := context.Background()
	c := newClient(t, startServer(t, baseConfig()), client.WithAPIKey(apiKey))
	must(c.Tenants.Create(ctx, client.CreateTenantRequest{Slug: "far", Name: "Far", Limits: map[string]int64{"calls": 25}}))
	value := func() int64 {
		for _, it := range must(c.Usage.Get(ctx, "far")) {
			if it.Metric == "calls" {
				return it.Value
			}
		}
		return -1
	}

	eu := c.Usage.NewAllowance("far", "calls", 10, time.Minute, "eu")
	for range 7 {
		if err := eu.Use(ctx, 1); err != nil {
			t.Fatal(err)
		}
	}
	if v := value(); v != 10 {
		t.Fatalf("one chunk reserved: %d", v)
	}
	us := c.Usage.NewAllowance("far", "calls", 10, time.Minute, "us")
	if err := us.Use(ctx, 10); err != nil {
		t.Fatal(err)
	}
	// 20 reserved: eu's next chunk only fits 5, so it falls back to n.
	for range 3 {
		if err := eu.Use(ctx, 1); err != nil {
			t.Fatal(err)
		}
	}
	if err := eu.Use(ctx, 1); err != nil {
		t.Fatalf("near the limit: %v", err)
	}
	if err := eu.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := us.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if v := value(); v != 21 {
		t.Fatalf("after release: %d, want 21 (11 eu + 10 us)", v)
	}
	big := c.Usage.NewAllowance("far", "calls", 10, time.Minute, "eu")
	if err := big.Use(ctx, 5); !client.IsQuotaExceeded(err) {
		t.Fatalf("over the limit: %v", err)
	}
}
