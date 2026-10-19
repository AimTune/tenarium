package tenant

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"testing"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/internal/store/memory"
	"github.com/AimTune/tenarium/pkg/sdk"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

type hookFunc func(ctx context.Context, req *sdk.HookRequest) error

func (f hookFunc) RunHooks(ctx context.Context, req *sdk.HookRequest) error { return f(ctx, req) }

func eventTypes(t *testing.T, s store.Store) []string {
	t.Helper()
	evts, err := s.ReadEvents(context.Background(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range evts {
		out = append(out, e.Type)
	}
	return out
}

func TestLifecycleWithoutProvisioners(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	svc := NewService(s, Options{})

	tn, err := svc.Create(ctx, CreateInput{Slug: "acme", Name: "Acme"})
	if err != nil {
		t.Fatal(err)
	}
	if tn.Status != sdk.StatusActive || tn.Version != 1 {
		t.Fatalf("unexpected tenant %+v", tn)
	}
	if _, err := svc.Create(ctx, CreateInput{Slug: "acme", Name: "Dup"}); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("want ErrAlreadyExists, got %v", err)
	}

	name := "Acme Inc"
	tn, err = svc.Update(ctx, "acme", UpdateInput{Name: &name, Settings: map[string]any{"theme": map[string]any{"color": "blue"}}}, nil)
	if err != nil || tn.Name != name || tn.Version != 2 {
		t.Fatalf("update: %+v %v", tn, err)
	}
	stale := int64(1)
	if _, err := svc.Update(ctx, tn.ID, UpdateInput{Name: &name}, &stale); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}

	if _, err := svc.Resume(ctx, tn.ID); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("resume active: want ErrInvalidTransition, got %v", err)
	}
	if tn, err = svc.Suspend(ctx, tn.ID, "unpaid"); err != nil || tn.Status != sdk.StatusSuspended || tn.StatusReason != "unpaid" {
		t.Fatalf("suspend: %+v %v", tn, err)
	}
	if tn, err = svc.Resume(ctx, tn.ID); err != nil || tn.Status != sdk.StatusActive {
		t.Fatalf("resume: %+v %v", tn, err)
	}
	if tn, err = svc.Delete(ctx, tn.ID); err != nil || tn.Status != sdk.StatusDeleted || tn.DeletedAt == nil {
		t.Fatalf("delete: %+v %v", tn, err)
	}
	// Slug is free again after deletion.
	if _, err := svc.Create(ctx, CreateInput{Slug: "acme", Name: "Acme 2"}); err != nil {
		t.Fatalf("recreate: %v", err)
	}

	want := []string{"tenant.created", "tenant.updated", "tenant.suspended", "tenant.resumed", "tenant.deleted", "tenant.created"}
	if got := eventTypes(t, s); !slices.Equal(got, want) {
		t.Fatalf("events\n got %v\nwant %v", got, want)
	}
}

func TestValidation(t *testing.T) {
	svc := NewService(memory.New(), Options{})
	var ve *ValidationError
	for _, in := range []CreateInput{
		{Slug: "Bad_Slug", Name: "x"},
		{Slug: "-x", Name: "x"},
		{Slug: "ok", Name: ""},
		{Slug: "ok", Name: "x", Labels: map[string]string{"bad key!": "v"}},
	} {
		if _, err := svc.Create(context.Background(), in); !errors.As(err, &ve) {
			t.Errorf("%+v: want ValidationError, got %v", in, err)
		}
	}
}

func TestHooksMutateButCannotTouchProtectedFields(t *testing.T) {
	svc := NewService(memory.New(), Options{Hooks: hookFunc(func(_ context.Context, req *sdk.HookRequest) error {
		if req.Point != sdk.HookBeforeTenantCreate {
			return nil
		}
		req.Tenant.Plan = "free"
		req.Tenant.Status = sdk.StatusSuspended // must be ignored
		req.Tenant.ID = "hijack"                // must be ignored
		return nil
	})})
	tn, err := svc.Create(context.Background(), CreateInput{Slug: "a", Name: "A"})
	if err != nil {
		t.Fatal(err)
	}
	if tn.Plan != "free" || tn.Status != sdk.StatusActive || tn.ID == "hijack" {
		t.Fatalf("unexpected %+v", tn)
	}
}

func TestHookRejectionPersistsNothing(t *testing.T) {
	s := memory.New()
	svc := NewService(s, Options{Hooks: hookFunc(func(context.Context, *sdk.HookRequest) error {
		return sdk.Reject("nope")
	})})
	_, err := svc.Create(context.Background(), CreateInput{Slug: "a", Name: "A"})
	if _, ok := sdk.IsReject(err); !ok {
		t.Fatalf("want reject, got %v", err)
	}
	if n, _ := s.LastEventSeq(context.Background()); n != 0 {
		t.Fatalf("events written despite rejection: %d", n)
	}
}

type fakeProv struct {
	fail          bool
	provisioned   []string
	deprovisioned []string
}

func (p *fakeProv) Name() string { return "fake" }
func (p *fakeProv) Provision(_ context.Context, t sdk.Tenant) error {
	if p.fail {
		return errors.New("quota exceeded")
	}
	p.provisioned = append(p.provisioned, t.Slug)
	return nil
}
func (p *fakeProv) Deprovision(_ context.Context, t sdk.Tenant) error {
	p.deprovisioned = append(p.deprovisioned, t.Slug)
	return nil
}

// drive feeds every logged event through the runner, like the dispatcher.
func drive(t *testing.T, s store.Store, r *Runner, after *int64) {
	t.Helper()
	ctx := context.Background()
	for {
		evts, _ := s.ReadEvents(ctx, *after, 0)
		if len(evts) == 0 {
			return
		}
		for _, e := range evts {
			if r.Subscription().Filter.Match(e) {
				if err := r.handle(ctx, e); err != nil {
					t.Fatal(err)
				}
			}
			*after = e.Seq
		}
	}
}

func TestProvisioningFlow(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	svc := NewService(s, Options{HasProvisioners: true})
	prov := &fakeProv{fail: true}
	r := NewRunner(svc, []ProvisionerRef{{Plugin: "test", Provisioner: prov}}, discard, nil)
	r.stepBackoff = 0
	var cursor int64

	tn, err := svc.Create(ctx, CreateInput{Slug: "acme", Name: "Acme"})
	if err != nil || tn.Status != sdk.StatusProvisioning {
		t.Fatalf("%+v %v", tn, err)
	}
	drive(t, s, r, &cursor)
	if tn, _ = svc.Get(ctx, tn.ID); tn.Status != sdk.StatusFailed || tn.StatusReason == "" {
		t.Fatalf("want failed, got %+v", tn)
	}

	prov.fail = false
	if _, err := svc.RetryProvisioning(ctx, tn.ID); err != nil {
		t.Fatal(err)
	}
	drive(t, s, r, &cursor)
	if tn, _ = svc.Get(ctx, tn.ID); tn.Status != sdk.StatusActive {
		t.Fatalf("want active, got %+v", tn)
	}

	if tn, err = svc.Delete(ctx, tn.ID); err != nil || tn.Status != sdk.StatusDeleting {
		t.Fatalf("%+v %v", tn, err)
	}
	drive(t, s, r, &cursor)
	if tn, _ = svc.Get(ctx, tn.ID); tn.Status != sdk.StatusDeleted {
		t.Fatalf("want deleted, got %+v", tn)
	}
	if !slices.Equal(prov.provisioned, []string{"acme"}) || !slices.Equal(prov.deprovisioned, []string{"acme"}) {
		t.Fatalf("prov calls: %v / %v", prov.provisioned, prov.deprovisioned)
	}
	want := []string{
		"tenant.created", "tenant.provisioning_failed", "tenant.provisioning",
		"tenant.provisioned", "tenant.deleting", "tenant.deleted",
	}
	if got := eventTypes(t, s); !slices.Equal(got, want) {
		t.Fatalf("events\n got %v\nwant %v", got, want)
	}
}

func TestMergePatch(t *testing.T) {
	got := mergePatch(
		map[string]any{"a": 1, "b": map[string]any{"c": 1, "d": 2}, "e": 3},
		map[string]any{"a": nil, "b": map[string]any{"c": nil, "x": 9}, "f": "new"},
	)
	b := got["b"].(map[string]any)
	if _, ok := got["a"]; ok || b["d"] != 2 || b["x"] != 9 || b["c"] != nil || got["e"] != 3 || got["f"] != "new" {
		t.Fatalf("unexpected %v", got)
	}
}
