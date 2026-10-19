package webhooks

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/netguard"
	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/internal/store/memory"
	"github.com/AimTune/tenarium/pkg/sdk"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

type recorder struct {
	mu    sync.Mutex
	types []string
}

func (r *recorder) RecordEvent(_ context.Context, typ, _, _ string, _ any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.types = append(r.types, typ)
	return nil
}

type receiver struct {
	srv    *httptest.Server
	status atomic.Int32
	mu     sync.Mutex
	got    []*http.Request
	bodies [][]byte
}

func newReceiver(t *testing.T) *receiver {
	r := &receiver{}
	r.status.Store(200)
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.got, r.bodies = append(r.got, req), append(r.bodies, b)
		r.mu.Unlock()
		w.WriteHeader(int(r.status.Load()))
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *receiver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.got)
}

func setup(t *testing.T, cfg Config) (*Service, store.Store, *recorder, string) {
	t.Helper()
	s := memory.New()
	ctx := context.Background()
	tn := sdk.Tenant{ID: "0190d4a2-0000-7000-8000-000000000001", Slug: "acme", Name: "Acme", Status: sdk.StatusActive, Version: 1}
	if err := s.InTx(ctx, func(tx store.Tx) error { return tx.CreateTenant(ctx, tn) }); err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	svc := New(s, rec, cfg, discard)
	svc.backoff = time.Millisecond
	return svc, s, rec, tn.ID
}

func ptr[T any](v T) *T { return &v }

func TestDeliverySignedAndFiltered(t *testing.T) {
	ctx := context.Background()
	svc, s, _, tid := setup(t, Config{AllowHTTP: true, AllowPrivateNetworks: true})
	r := newReceiver(t)
	w, secret, err := svc.Create(ctx, tid, Input{URL: ptr(r.srv.URL), Types: &[]string{"tenant.*"}})
	if err != nil {
		t.Fatal(err)
	}
	evt := sdk.Event{ID: "evt-1", Type: "tenant.updated", Source: "tenarium", TenantID: tid, Time: time.Now()}
	for _, e := range []sdk.Event{evt, {ID: "evt-2", Type: "member.added", TenantID: tid}, {ID: "evt-3", Type: "tenant.updated", TenantID: "other"}} {
		if err := svc.handle(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if r.count() != 1 {
		t.Fatalf("deliveries: %d", r.count())
	}
	req, body := r.got[0], r.bodies[0]
	want := "v1," + Sign(secret, "evt-1", req.Header.Get("webhook-timestamp"), body)
	if req.Header.Get("webhook-id") != "evt-1" || req.Header.Get("webhook-signature") != want {
		t.Fatalf("headers: %v", req.Header)
	}
	var ce map[string]any
	if json.Unmarshal(body, &ce) != nil || ce["type"] != "tenant.updated" {
		t.Fatalf("body: %s", body)
	}
	log, _ := svc.Deliveries(ctx, tid, w.ID, "", 10)
	if len(log) != 1 || !log[0].Success || log[0].StatusCode != 200 || log[0].Attempts != 1 {
		t.Fatalf("log: %+v", log)
	}
	if _, err := svc.Deliveries(ctx, "other", w.ID, "", 10); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant log: %v", err)
	}
	_ = s
}

func TestRetriesFailuresAndAutoDisable(t *testing.T) {
	ctx := context.Background()
	svc, s, rec, tid := setup(t, Config{AllowHTTP: true, AllowPrivateNetworks: true, Attempts: 2, MaxFailures: 2})
	r := newReceiver(t)
	r.status.Store(500)
	w, _, _ := svc.Create(ctx, tid, Input{URL: ptr(r.srv.URL)})

	_ = svc.handle(ctx, sdk.Event{ID: "e1", Type: "x", TenantID: tid})
	if r.count() != 2 {
		t.Fatalf("attempts: %d", r.count())
	}
	log, _ := svc.Deliveries(ctx, tid, w.ID, "", 10)
	if len(log) != 1 || log[0].Success || log[0].Attempts != 2 || log[0].StatusCode != 500 || log[0].Error == "" {
		t.Fatalf("failed delivery: %+v", log)
	}
	_ = svc.handle(ctx, sdk.Event{ID: "e2", Type: "x", TenantID: tid})
	got, _ := s.GetWebhook(ctx, w.ID)
	if got.Enabled || got.Failures != 2 {
		t.Fatalf("not disabled: %+v", got)
	}
	if rec.types[len(rec.types)-1] != EventDisabled {
		t.Fatalf("events: %v", rec.types)
	}
	_ = svc.handle(ctx, sdk.Event{ID: "e3", Type: "x", TenantID: tid})
	if r.count() != 4 {
		t.Fatalf("delivered to disabled webhook: %d", r.count())
	}

	// Redelivery after the endpoint is fixed; re-enabling resets failures.
	r.status.Store(204)
	d, err := svc.Redeliver(ctx, tid, w.ID, log[0].ID)
	if err != nil || !d.Success || r.got[len(r.got)-1].Header.Get("webhook-id") != "e1" {
		t.Fatalf("redeliver: %+v %v", d, err)
	}
	w, err = svc.Update(ctx, tid, w.ID, Input{Enabled: ptr(true)})
	if err != nil || !w.Enabled || w.Failures != 0 {
		t.Fatalf("re-enable: %+v %v", w, err)
	}
	if d, err := svc.Test(ctx, tid, w.ID); err != nil || !d.Success || d.EventType != EventTest {
		t.Fatalf("test: %+v %v", d, err)
	}
}

func TestValidationAndSSRF(t *testing.T) {
	ctx := context.Background()
	svc, _, _, tid := setup(t, Config{MaxPerTenant: 1})
	bad := []string{"http://example.com/h", "https://user:pw@example.com/", "ftp://example.com", "https://127.0.0.1/h",
		"https://169.254.169.254/latest", "https://localhost/x", "https://[::1]/", "https://10.1.2.3/", "not a url"}
	for _, u := range bad {
		var ve *ValidationError
		if _, _, err := svc.Create(ctx, tid, Input{URL: ptr(u)}); !errors.As(err, &ve) {
			t.Errorf("%s accepted: %v", u, err)
		}
	}
	if _, _, err := svc.Create(ctx, tid, Input{URL: ptr("https://example.com/h"), Types: &[]string{"[bad"}}); err == nil {
		t.Error("bad pattern accepted")
	}
	if _, _, err := svc.Create(ctx, tid, Input{URL: ptr("https://example.com/h")}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Create(ctx, tid, Input{URL: ptr("https://example.com/2")}); err == nil {
		t.Error("per-tenant limit ignored")
	}

	// A name that resolves to an internal address is refused at dial time.
	r := newReceiver(t)
	strict := newSender(Config{Timeout: time.Second})
	code, msg := strict.post(ctx, r.srv.URL, nil, []byte("{}"))
	if code != 0 || msg == "" || r.count() != 0 {
		t.Fatalf("internal address reached: %d %q", code, msg)
	}
	for _, a := range []string{"100.64.1.1", "0.0.0.0", "::ffff:127.0.0.1", "fe80::1"} {
		if netguard.CheckAddr(netip.MustParseAddr(a)) == nil {
			t.Errorf("%s allowed", a)
		}
	}
	if netguard.CheckAddr(netip.MustParseAddr("93.184.216.34")) != nil {
		t.Error("public address refused")
	}
}

func TestNoRedirects(t *testing.T) {
	target := newReceiver(t)
	redir := httptest.NewServer(http.RedirectHandler(target.srv.URL, http.StatusTemporaryRedirect))
	t.Cleanup(redir.Close)
	s := newSender(Config{Timeout: time.Second, AllowPrivateNetworks: true})
	code, msg := s.post(context.Background(), redir.URL, nil, []byte("{}"))
	if code != http.StatusTemporaryRedirect || msg == "" || target.count() != 0 {
		t.Fatalf("redirect followed: %d %q", code, msg)
	}
}
