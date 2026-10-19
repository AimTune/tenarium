package gateway

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics are the gateway's Prometheus metrics:
//
//   - tenarium_gateway_decisions_total{mode,decision,code}: checks by
//     protocol mode, decision (allow or deny) and code ("ok",
//     "tenant_not_found", "rate_limited", ...);
//   - tenarium_gateway_check_duration_seconds{mode,decision}: check latency;
//   - tenarium_gateway_rate_limited_total: requests refused by the limiter;
//   - tenarium_gateway_limiter_errors_total: limiter failures (e.g. Redis).
//
// Tenants are deliberately not a label, to keep cardinality bounded.
type Metrics struct {
	decisions     *prometheus.CounterVec
	duration      *prometheus.HistogramVec
	limited       prometheus.Counter
	limiterErrors prometheus.Counter
}

// NewMetrics creates the metrics and registers them with reg (when not nil).
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tenarium_gateway_decisions_total",
			Help: "Forward-auth decisions by protocol mode, decision and code.",
		}, []string{"mode", "decision", "code"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "tenarium_gateway_check_duration_seconds",
			Help:    "Latency of forward-auth checks.",
			Buckets: []float64{.0001, .00025, .0005, .001, .0025, .005, .01, .025, .05, .1, .25, .5, 1},
		}, []string{"mode", "decision"}),
		limited: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tenarium_gateway_rate_limited_total",
			Help: "Requests refused by the per-tenant rate limit.",
		}),
		limiterErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tenarium_gateway_limiter_errors_total",
			Help: "Rate limiter failures.",
		}),
	}
	if reg != nil {
		reg.MustRegister(m.decisions, m.duration, m.limited, m.limiterErrors)
	}
	return m
}

func (m *Metrics) observe(mode Mode, res Result, d time.Duration) {
	if m == nil {
		return
	}
	decision := "deny"
	if res.Allowed {
		decision = "allow"
	}
	m.decisions.WithLabelValues(string(mode), decision, res.Code).Inc()
	m.duration.WithLabelValues(string(mode), decision).Observe(d.Seconds())
}

func (m *Metrics) rateLimited() {
	if m != nil {
		m.limited.Inc()
	}
}

func (m *Metrics) limiterError() {
	if m != nil {
		m.limiterErrors.Inc()
	}
}
