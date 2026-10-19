// Package events delivers events from the store's event log to subscribers.
//
// Every subscription runs in its own goroutine with its own durable cursor,
// so delivery is at-least-once, ordered per subscription, and isolated: a
// subscriber that is down (e.g. Kafka unreachable) retries with exponential
// backoff and eventually dead-letters, without delaying anyone else.
//
// When several Tenarium instances share a database, each subscription is
// guarded by a lease: exactly one instance processes it at a time, and
// another takes over if that instance dies.
package events

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"runtime/debug"
	"slices"
	"sync"
	"time"

	"github.com/AimTune/tenarium/internal/metrics"
	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// Subscription is a named, durable consumer of the event log.
type Subscription struct {
	// Name is globally unique and stable across restarts; it keys the
	// cursor. Plugin subscriptions are named "{plugin-instance}/{name}".
	Name    string
	Filter  sdk.EventFilter
	Handler sdk.EventHandler
	Options sdk.SubscribeOptions
	// Regions, if set, are where the subscription should preferably run
	// (see Config.Region).
	Regions []string
}

type Config struct {
	// PollInterval bounds latency when no Notify arrives.
	PollInterval time.Duration
	BatchSize    int
	// HandlerTimeout bounds a single delivery attempt unless the
	// subscription sets its own.
	HandlerTimeout time.Duration
	// InstanceID identifies this process as a lease owner. Defaults to a
	// random ID.
	InstanceID string
	// LeaseTTL is how long a lease survives without renewal; an instance
	// that dies loses its subscriptions after at most this long.
	LeaseTTL time.Duration
	// Region is where this instance runs. Subscriptions preferring a region
	// (plugin scope regions) run on instances there when any is up: such
	// an instance takes the lease over from one elsewhere.
	Region string
}

type Dispatcher struct {
	store   store.Store
	log     *slog.Logger
	cfg     Config
	metrics *metrics.Metrics

	mu      sync.Mutex
	workers []*worker
	started bool
}

func NewDispatcher(s store.Store, log *slog.Logger, m *metrics.Metrics, cfg Config) *Dispatcher {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.HandlerTimeout <= 0 {
		cfg.HandlerTimeout = 30 * time.Second
	}
	if cfg.InstanceID == "" {
		cfg.InstanceID = uuid.NewString()
	}
	if cfg.LeaseTTL <= 0 {
		cfg.LeaseTTL = 15 * time.Second
	}
	if m == nil {
		m = metrics.New()
	}
	return &Dispatcher{store: s, log: log, cfg: cfg, metrics: m}
}

// Add registers a subscription. It must be called before Run.
func (d *Dispatcher) Add(sub Subscription) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.started {
		return errors.New("events: Add after Run")
	}
	if sub.Name == "" || sub.Handler == nil {
		return errors.New("events: subscription needs a name and handler")
	}
	if d.worker(sub.Name) != nil {
		return fmt.Errorf("events: duplicate subscription %q", sub.Name)
	}
	if sub.Options.MaxAttempts <= 0 {
		sub.Options.MaxAttempts = 1
	}
	d.workers = append(d.workers, &worker{d: d, sub: sub, wake: make(chan struct{}, 1)})
	return nil
}

func (d *Dispatcher) worker(name string) *worker {
	for _, w := range d.workers {
		if w.sub.Name == name {
			return w
		}
	}
	return nil
}

// Subscriptions returns the names of registered subscriptions.
func (d *Dispatcher) Subscriptions() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	names := make([]string, len(d.workers))
	for i, w := range d.workers {
		names[i] = w.sub.Name
	}
	return names
}

// Notify wakes all workers; call it after committing new events. It never
// blocks.
func (d *Dispatcher) Notify() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, w := range d.workers {
		select {
		case w.wake <- struct{}{}:
		default:
		}
	}
}

// Run delivers events until ctx is cancelled, then waits for in-flight
// deliveries to stop and releases its leases.
func (d *Dispatcher) Run(ctx context.Context) error {
	d.mu.Lock()
	d.started = true
	workers := d.workers
	d.mu.Unlock()

	var wg sync.WaitGroup
	if n, ok := d.store.(store.Notifier); ok {
		wg.Go(func() { d.listen(ctx, n) })
	}
	for _, w := range workers {
		wg.Go(func() { w.run(ctx) })
	}
	wg.Wait()
	return nil
}

// listen forwards cross-instance notifications, reconnecting on failure.
func (d *Dispatcher) listen(ctx context.Context, n store.Notifier) {
	for ctx.Err() == nil {
		if err := n.Listen(ctx, d.Notify); err != nil {
			d.log.Warn("event notification listener failed; relying on polling", "err", err)
		}
		sleep(ctx, d.cfg.PollInterval)
	}
}

// ErrUnknownSubscription is returned by Replay for subscriptions that are not
// registered on this instance.
var ErrUnknownSubscription = errors.New("unknown subscription")

// Replay redelivers a dead-lettered event to its subscription once. On
// success the dead letter is removed; on failure it is kept and the error is
// returned.
func (d *Dispatcher) Replay(ctx context.Context, deadLetterID string) error {
	dl, err := d.store.GetDeadLetter(ctx, deadLetterID)
	if err != nil {
		return err
	}
	d.mu.Lock()
	w := d.worker(dl.Subscription)
	d.mu.Unlock()
	if w == nil {
		return fmt.Errorf("%w %q", ErrUnknownSubscription, dl.Subscription)
	}
	if err := w.call(ctx, dl.Event); err != nil {
		return fmt.Errorf("replay failed: %w", err)
	}
	w.d.metrics.Deliveries.WithLabelValues(w.sub.Name).Inc()
	return d.store.DeleteDeadLetter(ctx, dl.ID)
}

type worker struct {
	d    *Dispatcher
	sub  Subscription
	wake chan struct{}
}

func (w *worker) logger() *slog.Logger {
	return w.d.log.With("subscription", w.sub.Name)
}

// run alternates between waiting for the lease and consuming while it is
// held.
func (w *worker) run(ctx context.Context) {
	log := w.logger()
	ttl := w.d.cfg.LeaseTTL
	held := w.d.metrics.LeaseHeld.WithLabelValues(w.sub.Name)
	for ctx.Err() == nil {
		ok, err := w.d.store.AcquireLease(ctx, w.sub.Name, w.d.cfg.InstanceID, ttl, w.preferred())
		if err != nil && ctx.Err() == nil {
			log.Error("acquire lease", "err", err)
		}
		if !ok {
			held.Set(0)
			sleep(ctx, min(ttl/3, w.d.cfg.PollInterval*5))
			continue
		}
		held.Set(1)
		leaseCtx, cancel := context.WithCancel(ctx)
		go w.renew(leaseCtx, cancel)
		w.consume(leaseCtx)
		cancel()
		held.Set(0)
	}
	_ = w.d.store.ReleaseLease(context.WithoutCancel(ctx), w.sub.Name, w.d.cfg.InstanceID)
}

// renew keeps the lease alive and cancels consumption if it is lost.
func (w *worker) renew(ctx context.Context, lost context.CancelFunc) {
	t := time.NewTicker(w.d.cfg.LeaseTTL / 3)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// Bound the renewal so a stalled store cannot keep us working past
			// the lease's expiry.
			renewCtx, cancel := context.WithTimeout(ctx, w.d.cfg.LeaseTTL/3)
			ok, err := w.d.store.AcquireLease(renewCtx, w.sub.Name, w.d.cfg.InstanceID, w.d.cfg.LeaseTTL, w.preferred())
			cancel()
			if ctx.Err() != nil {
				return
			}
			if err != nil || !ok {
				w.logger().Warn("lost subscription lease", "err", err)
				lost()
				return
			}
		}
	}
}

func (w *worker) consume(ctx context.Context) {
	log := w.logger()
	cursor, err := w.initCursor(ctx)
	for err != nil {
		log.Error("init cursor", "err", err)
		if !sleep(ctx, w.d.cfg.PollInterval) {
			return
		}
		cursor, err = w.initCursor(ctx)
	}

	ticker := time.NewTicker(w.d.cfg.PollInterval)
	defer ticker.Stop()
	for {
		n, next, err := w.processBatch(ctx, cursor)
		cursor = next
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Error("process batch", "err", err)
		}
		w.updateLag(ctx, cursor)
		if n == w.d.cfg.BatchSize && err == nil {
			continue // more is likely waiting
		}
		select {
		case <-ctx.Done():
			return
		case <-w.wake:
		case <-ticker.C:
		}
	}
}

func (w *worker) updateLag(ctx context.Context, cursor int64) {
	if last, err := w.d.store.LastEventSeq(ctx); err == nil {
		w.d.metrics.SubscriptionLag.WithLabelValues(w.sub.Name).Set(float64(max(last-cursor, 0)))
	}
}

func (w *worker) initCursor(ctx context.Context) (int64, error) {
	seq, found, err := w.d.store.GetCursor(ctx, w.sub.Name)
	if err != nil || found {
		return seq, err
	}
	if w.sub.Options.StartAtEnd {
		if seq, err = w.d.store.LastEventSeq(ctx); err != nil {
			return 0, err
		}
	}
	return seq, w.d.store.SetCursor(ctx, w.sub.Name, seq)
}

// processBatch delivers one batch and returns the number of events read and
// the new cursor.
func (w *worker) processBatch(ctx context.Context, cursor int64) (int, int64, error) {
	events, err := w.d.store.ReadEvents(ctx, cursor, w.d.cfg.BatchSize)
	if err != nil || len(events) == 0 {
		return 0, cursor, err
	}
	for _, e := range events {
		if w.sub.Filter.Match(e) {
			if err := w.deliver(ctx, e); err != nil {
				// Cancellation (shutdown or lost lease) or a failed
				// dead-letter write: keep the cursor so the event is
				// redelivered.
				return len(events), cursor, err
			}
		}
		cursor = e.Seq
		if err := w.d.store.SetCursor(ctx, w.sub.Name, cursor); err != nil {
			return len(events), cursor, fmt.Errorf("set cursor: %w", err)
		}
	}
	return len(events), cursor, nil
}

// deliver retries until success, dead-lettering after MaxAttempts. It returns
// an error only if ctx is cancelled or the dead letter cannot be stored.
func (w *worker) deliver(ctx context.Context, e sdk.Event) error {
	opts := w.sub.Options
	m := w.d.metrics
	log := w.logger().With("event_id", e.ID, "event_type", e.Type, "seq", e.Seq)
	var lastErr error
	for attempt := 1; attempt <= opts.MaxAttempts; attempt++ {
		start := time.Now()
		lastErr = w.call(ctx, e)
		m.DeliveryDuration.WithLabelValues(w.sub.Name).Observe(time.Since(start).Seconds())
		if lastErr == nil {
			m.Deliveries.WithLabelValues(w.sub.Name).Inc()
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		m.DeliveryFailures.WithLabelValues(w.sub.Name).Inc()
		log.Warn("delivery failed", "attempt", attempt, "err", lastErr)
		if attempt < opts.MaxAttempts && !sleep(ctx, backoff(opts, attempt)) {
			return ctx.Err()
		}
	}
	log.Error("dead-lettering event", "attempts", opts.MaxAttempts, "err", lastErr)
	m.DeadLetters.WithLabelValues(w.sub.Name).Inc()
	return w.d.store.AddDeadLetter(context.WithoutCancel(ctx), store.DeadLetter{
		ID:           uuid.Must(uuid.NewV7()).String(),
		Subscription: w.sub.Name,
		Event:        e,
		Error:        lastErr.Error(),
		Attempts:     opts.MaxAttempts,
		FailedAt:     time.Now().UTC(),
	})
}

func (w *worker) call(ctx context.Context, e sdk.Event) (err error) {
	timeout := w.sub.Options.Timeout
	if timeout <= 0 {
		timeout = w.d.cfg.HandlerTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	ctx, span := tracer.Start(ctx, "deliver "+w.sub.Name, trace.WithSpanKind(trace.SpanKindConsumer),
		trace.WithLinks(producerLink(e)...),
		trace.WithAttributes(
			attribute.String("tenarium.subscription", w.sub.Name),
			attribute.String("tenarium.event.type", e.Type),
			attribute.String("tenarium.event.id", e.ID),
			attribute.Int64("tenarium.event.seq", e.Seq),
			attribute.String("tenarium.tenant.id", e.TenantID),
		))
	defer func() {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()
	defer cancel()
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("handler panic: %v\n%s", r, debug.Stack())
		}
	}()
	return w.sub.Handler(ctx, e)
}

// backoff is exponential with full jitter.
func backoff(o sdk.SubscribeOptions, attempt int) time.Duration {
	d := o.BaseBackoff << min(attempt-1, 30)
	if d <= 0 || d > o.MaxBackoff {
		d = o.MaxBackoff
	}
	if d <= 0 {
		return 0
	}
	return d/2 + rand.N(d/2+1) //nolint:gosec // jitter needs no cryptographic randomness
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// tracer uses the global provider, a no-op unless tracing is configured.
var tracer = otel.Tracer("github.com/AimTune/tenarium/internal/events")

// producerLink links a delivery to the span that produced the event. A
// link, not a parent: delivery is asynchronous and may happen much later,
// possibly several times.
func producerLink(e sdk.Event) []trace.Link {
	if e.TraceParent == "" {
		return nil
	}
	c := propagation.MapCarrier{"traceparent": e.TraceParent, "tracestate": e.TraceState}
	sc := trace.SpanContextFromContext(propagation.TraceContext{}.Extract(context.Background(), c))
	if !sc.IsValid() {
		return nil
	}
	return []trace.Link{{SpanContext: sc}}
}

// preferred reports whether this instance is in a region the subscription
// prefers. Without a configured region, or for subscriptions without a
// preference, no instance is preferred, so leases behave as before.
func (w *worker) preferred() bool {
	return w.d.cfg.Region != "" && slices.Contains(w.sub.Regions, w.d.cfg.Region)
}
