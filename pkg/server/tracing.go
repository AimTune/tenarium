package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// TracingConfig exports OpenTelemetry traces over OTLP/HTTP. The standard
// OTEL_EXPORTER_OTLP_* environment variables apply when fields are empty.
type TracingConfig struct {
	Enabled bool `yaml:"enabled"`
	// Endpoint is host:port of the collector (default localhost:4318).
	Endpoint string `yaml:"endpoint"`
	// Insecure uses plain HTTP to the collector.
	Insecure bool              `yaml:"insecure"`
	Headers  map[string]string `yaml:"headers"`
	// ServiceName defaults to "tenarium".
	ServiceName string `yaml:"service_name"`
	// SampleRatio of new traces to record (default 1); incoming sampled
	// traces are always followed.
	SampleRatio *float64 `yaml:"sample_ratio"`
}

// setupTracing installs the global tracer provider and propagator. The
// returned function flushes and stops it.
func setupTracing(ctx context.Context, cfg TracingConfig) (func(context.Context) error, error) {
	if !cfg.Enabled {
		return func(context.Context) error { return nil }, nil
	}
	var opts []otlptracehttp.Option
	if cfg.Endpoint != "" {
		opts = append(opts, otlptracehttp.WithEndpoint(cfg.Endpoint))
	}
	if cfg.Insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	if len(cfg.Headers) > 0 {
		opts = append(opts, otlptracehttp.WithHeaders(cfg.Headers))
	}
	exp, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("tracing exporter: %w", err)
	}
	ratio := 1.0
	if cfg.SampleRatio != nil {
		ratio = *cfg.SampleRatio
	}
	name := cfg.ServiceName
	if name == "" {
		name = "tenarium"
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(resource.NewSchemaless(
			attribute.String("service.name", name),
			attribute.String("service.version", Version),
		)),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	return tp.Shutdown, nil
}

// traceHandler creates a server span per request (continuing incoming
// W3C trace context).
func traceHandler(h http.Handler) http.Handler {
	return otelhttp.NewHandler(h, "http",
		// Renamed to the route pattern once routed (see internal/api).
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string { return "HTTP " + r.Method }),
		otelhttp.WithFilter(func(r *http.Request) bool {
			// Probes and scrapes would drown the useful traces.
			return !strings.HasPrefix(r.URL.Path, "/healthz") && !strings.HasPrefix(r.URL.Path, "/readyz") &&
				r.URL.Path != "/metrics"
		}),
	)
}
