// Package metrics defines Tenarium's Prometheus metrics.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Metrics groups all collectors. Each App gets its own registry so tests and
// embedded servers don't collide on the global one.
type Metrics struct {
	Registry *prometheus.Registry

	Deliveries       *prometheus.CounterVec
	DeliveryFailures *prometheus.CounterVec
	DeadLetters      *prometheus.CounterVec
	DeliveryDuration *prometheus.HistogramVec
	SubscriptionLag  *prometheus.GaugeVec
	LeaseHeld        *prometheus.GaugeVec
	HTTPRequests     *prometheus.CounterVec
	HTTPDuration     *prometheus.HistogramVec
	HookRejections   *prometheus.CounterVec
	ProvisioningRuns *prometheus.CounterVec
}

func New() *Metrics {
	m := &Metrics{
		Registry: prometheus.NewRegistry(),
		Deliveries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tenarium_event_deliveries_total", Help: "Events successfully delivered to a subscription.",
		}, []string{"subscription"}),
		DeliveryFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tenarium_event_delivery_failures_total", Help: "Failed delivery attempts.",
		}, []string{"subscription"}),
		DeadLetters: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tenarium_dead_letters_total", Help: "Events moved to the dead-letter queue.",
		}, []string{"subscription"}),
		DeliveryDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "tenarium_event_delivery_duration_seconds", Help: "Duration of one delivery attempt.",
			Buckets: prometheus.DefBuckets,
		}, []string{"subscription"}),
		SubscriptionLag: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tenarium_subscription_lag_events", Help: "Events in the log not yet processed by a subscription.",
		}, []string{"subscription"}),
		LeaseHeld: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tenarium_subscription_lease_held", Help: "1 if this instance processes the subscription.",
		}, []string{"subscription"}),
		HTTPRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tenarium_http_requests_total", Help: "HTTP requests by route and status.",
		}, []string{"method", "route", "status"}),
		HTTPDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "tenarium_http_request_duration_seconds", Help: "HTTP request duration by route.",
			Buckets: prometheus.DefBuckets,
		}, []string{"method", "route"}),
		HookRejections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tenarium_hook_rejections_total", Help: "Operations rejected by plugin hooks.",
		}, []string{"point", "plugin"}),
		ProvisioningRuns: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tenarium_provisioning_runs_total", Help: "Provisioning and deprovisioning outcomes.",
		}, []string{"operation", "result"}),
	}
	m.Registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.Deliveries, m.DeliveryFailures, m.DeadLetters, m.DeliveryDuration, m.SubscriptionLag,
		m.LeaseHeld, m.HTTPRequests, m.HTTPDuration, m.HookRejections, m.ProvisioningRuns,
	)
	return m
}
