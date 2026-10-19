package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/store"
)

func testWebhooks(t *testing.T, s store.Store) {
	ctx := context.Background()
	tn := tenant("hooks")
	mustTx(t, s, func(tx store.Tx) error { return tx.CreateTenant(ctx, tn) })
	now := time.Now().UTC().Truncate(time.Microsecond)
	w := store.Webhook{ID: newID(), TenantID: tn.ID, URL: "https://x.example/h", Secret: "whsec_x",
		Types: []string{"tenant.*"}, Enabled: true, CreatedAt: now, UpdatedAt: now}
	mustTx(t, s, func(tx store.Tx) error { return tx.CreateWebhook(ctx, w) })
	if err := s.InTx(ctx, func(tx store.Tx) error { return tx.CreateWebhook(ctx, w) }); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("duplicate: %v", err)
	}
	got, err := s.GetWebhook(ctx, w.ID)
	if err != nil || got.Secret != "whsec_x" || len(got.Types) != 1 || !got.Enabled {
		t.Fatalf("get: %+v %v", got, err)
	}
	w.Types, w.Description = nil, "all events"
	mustTx(t, s, func(tx store.Tx) error { return tx.UpdateWebhook(ctx, w) })
	if l, _ := s.ListWebhooks(ctx, tn.ID); len(l) != 1 || l[0].Types != nil || l[0].Description != "all events" {
		t.Fatalf("list: %+v", l)
	}

	// Failures disable the webhook at the threshold; success resets.
	for i := 1; i <= 2; i++ {
		if d, _ := s.RecordWebhookResult(ctx, w.ID, false, 3); d {
			t.Fatalf("disabled after %d failures", i)
		}
	}
	if _, err := s.RecordWebhookResult(ctx, w.ID, true, 3); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetWebhook(ctx, w.ID); got.Failures != 0 {
		t.Fatalf("success did not reset: %d", got.Failures)
	}
	for i := 1; i <= 3; i++ {
		d, _ := s.RecordWebhookResult(ctx, w.ID, false, 3)
		if d != (i == 3) {
			t.Fatalf("failure %d: disabled=%v", i, d)
		}
	}
	if d, _ := s.RecordWebhookResult(ctx, w.ID, false, 3); d {
		t.Fatal("disabled twice")
	}
	if got, _ := s.GetWebhook(ctx, w.ID); got.Enabled || got.Failures != 4 {
		t.Fatalf("after disable: %+v", got)
	}
	if _, err := s.RecordWebhookResult(ctx, newID(), true, 3); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown webhook: %v", err)
	}

	var ids []string
	for i := range 3 {
		d := store.WebhookDelivery{ID: newID(), WebhookID: w.ID, TenantID: tn.ID, EventID: "e", EventType: "tenant.updated",
			Payload: []byte(`{"a":1}`), Attempts: 1, StatusCode: 200 + i, Success: true, CreatedAt: now.Add(time.Duration(i) * time.Hour)}
		if err := s.AddWebhookDelivery(ctx, d); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, d.ID)
	}
	if err := s.AddWebhookDelivery(ctx, store.WebhookDelivery{ID: newID(), WebhookID: newID(), TenantID: tn.ID, CreatedAt: now}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delivery for unknown webhook: %v", err)
	}
	d, err := s.GetWebhookDelivery(ctx, ids[1])
	if err != nil || d.StatusCode != 201 || string(d.Payload) != `{"a": 1}` && string(d.Payload) != `{"a":1}` {
		t.Fatalf("get delivery: %+v %v", d, err)
	}
	page, _ := s.ListWebhookDeliveries(ctx, w.ID, "", 2)
	if len(page) != 2 || page[0].ID != ids[2] || page[1].ID != ids[1] {
		t.Fatalf("page: %+v", page)
	}
	if rest, _ := s.ListWebhookDeliveries(ctx, w.ID, page[1].ID, 2); len(rest) != 1 || rest[0].ID != ids[0] {
		t.Fatalf("next page: %+v", rest)
	}
	if n, _ := s.PruneWebhookDeliveries(ctx, now.Add(90*time.Minute)); n != 2 {
		t.Fatalf("pruned %d", n)
	}

	mustTx(t, s, func(tx store.Tx) error { return tx.DeleteWebhook(ctx, w.ID) })
	if _, err := s.GetWebhookDelivery(ctx, ids[2]); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delivery survived webhook deletion: %v", err)
	}
	if err := s.InTx(ctx, func(tx store.Tx) error { return tx.DeleteWebhook(ctx, w.ID) }); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
}
