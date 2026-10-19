package plugin

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func TestScopedHandlerSeesTenantsLeavingTheScope(t *testing.T) {
	m := NewManager(slog.New(slog.DiscardHandler), nil, nil)
	var got []string
	h := m.scopedHandler(&Scope{Regions: []string{"eu"}}, func(_ context.Context, e sdk.Event) error {
		got = append(got, e.ID)
		return nil
	})
	event := func(id string, region string, prev *string) sdk.Event {
		d := sdk.TenantEventData{Tenant: sdk.Tenant{ID: "t1", Region: region}}
		if prev != nil {
			d.Previous = &sdk.Tenant{ID: "t1", Region: *prev}
		}
		b, _ := json.Marshal(d)
		return sdk.Event{ID: id, TenantID: "t1", Type: sdk.EventTenantRegionChanged, Data: b}
	}
	eu, us := "eu", "us"
	for _, e := range []sdk.Event{
		event("in-scope", "eu", nil),
		event("out-of-scope", "us", nil),
		event("left", "us", &eu),
		event("joined", "eu", &us),
		event("elsewhere", "ap", &us),
	} {
		if err := h(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"in-scope", "left", "joined"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("delivered %v, want %v", got, want)
	}
}
