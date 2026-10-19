package tenant

import (
	"context"
	"testing"

	"github.com/AimTune/tenarium/internal/store/memory"
	"go.opentelemetry.io/otel/trace"
)

func TestEventsCarryTraceContext(t *testing.T) {
	s := memory.New()
	svc := NewService(s, Options{})
	tid, _ := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
	sid, _ := trace.SpanIDFromHex("00f067aa0ba902b7")
	ctx := trace.ContextWithSpanContext(context.Background(),
		trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid, TraceFlags: trace.FlagsSampled}))
	if _, err := svc.Create(ctx, CreateInput{Slug: "a", Name: "A"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(context.Background(), CreateInput{Slug: "b", Name: "B"}); err != nil {
		t.Fatal(err)
	}
	evs, _ := s.ReadEvents(ctx, 0, 10)
	if len(evs) != 2 || evs[0].TraceParent != "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01" {
		t.Fatalf("traceparent: %+v", evs)
	}
	if evs[1].TraceParent != "" {
		t.Fatalf("untraced request got a traceparent: %q", evs[1].TraceParent)
	}
}

func TestEventsNameTheirSchema(t *testing.T) {
	s := memory.New()
	svc := NewService(s, Options{Users: &UserOptions{PublicURL: "https://tenarium.example.com"}})
	if _, err := svc.Create(context.Background(), CreateInput{Slug: "a", Name: "A"}); err != nil {
		t.Fatal(err)
	}
	evs, _ := s.ReadEvents(context.Background(), 0, 10)
	if len(evs) != 1 || evs[0].DataSchema != "https://tenarium.example.com/v1/event-schemas/tenant.created/1" ||
		evs[0].CloudEvent().DataSchema != evs[0].DataSchema {
		t.Fatalf("dataschema: %+v", evs)
	}
}
