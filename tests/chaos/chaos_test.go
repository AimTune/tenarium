//go:build chaos

// Package chaos runs failover tests against several Tenarium replicas
// sharing one PostgreSQL database. They are excluded from the default test
// run; see README.md.
//
//	TENARIUM_TEST_POSTGRES_DSN=postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable \
//	  go test -tags chaos -v -count=1 ./tests/chaos
package chaos

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/store/postgres/pgtest"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/server"
	"github.com/jackc/pgx/v5"
)

const (
	apiKey       = "chaos-key"
	leaseTTL     = 3 * time.Second
	pollInterval = 50 * time.Millisecond
	// subscription is the full name of the sink's subscription.
	subscription = "sink/all"
)

// --- delivery recorder ----------------------------------------------------------

type delivery struct {
	replica string
	seq     int64
	at      time.Time
}

// recorder collects every delivery made to the sink plugin by any replica.
type recorder struct {
	mu   sync.Mutex
	list []delivery
}

func (r *recorder) add(d delivery) {
	r.mu.Lock()
	r.list = append(r.list, d)
	r.mu.Unlock()
}

func (r *recorder) snapshot() []delivery {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.list)
}

// current is the recorder of the running test (tests in this package run
// sequentially).
var current atomic.Pointer[recorder]

// sinkPlugin subscribes to every event and records it with the replica
// name from its configuration.
type sinkPlugin struct{ replica string }

func (*sinkPlugin) Manifest() sdk.Manifest {
	return sdk.Manifest{ID: "chaos-sink", Name: "Chaos sink", Version: "0"}
}

func (p *sinkPlugin) Init(_ context.Context, r sdk.Registrar) error {
	var cfg struct {
		Replica string `json:"replica"`
	}
	if err := r.Config(&cfg); err != nil {
		return err
	}
	p.replica = cfg.Replica
	r.Subscribe("all", sdk.EventFilter{}, func(ctx context.Context, e sdk.Event) error {
		if rec := current.Load(); rec != nil {
			rec.add(delivery{replica: p.replica, seq: e.Seq, at: time.Now()})
		}
		return nil
	}, sdk.WithMaxAttempts(5))
	return nil
}

func init() { sdk.Register("chaos-sink", func() sdk.Plugin { return &sinkPlugin{} }) }

// --- TCP proxy between a replica and PostgreSQL -----------------------------------

// proxy forwards TCP connections to PostgreSQL. Cutting it closes every
// open connection and refuses new ones, which looks to the replica like a
// crashed or partitioned database.
type proxy struct {
	ln       net.Listener
	upstream string

	mu    sync.Mutex
	conns map[net.Conn]struct{}
	down  bool
}

func newProxy(t *testing.T, upstream string) *proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &proxy{ln: ln, upstream: upstream, conns: map[net.Conn]struct{}{}}
	go p.serve()
	t.Cleanup(func() { ln.Close(); p.setDown(true) })
	return p
}

func (p *proxy) addr() string { return p.ln.Addr().String() }

func (p *proxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handle(c)
	}
}

func (p *proxy) track(cs ...net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.down {
		return false
	}
	for _, c := range cs {
		p.conns[c] = struct{}{}
	}
	return true
}

func (p *proxy) handle(c net.Conn) {
	up, err := net.DialTimeout("tcp", p.upstream, 5*time.Second)
	if err != nil {
		c.Close()
		return
	}
	if !p.track(c, up) {
		c.Close()
		up.Close()
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
	c.Close()
	up.Close()
	p.mu.Lock()
	delete(p.conns, c)
	delete(p.conns, up)
	p.mu.Unlock()
}

// setDown cuts (true) or restores (false) the link.
func (p *proxy) setDown(down bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.down = down
	if down {
		for c := range p.conns {
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetLinger(0) // reset, like a dead peer
			}
			c.Close()
		}
		clear(p.conns)
	}
}

// --- replicas -----------------------------------------------------------------------

type replica struct {
	name   string
	base   string
	proxy  *proxy
	cancel context.CancelFunc
	done   chan error
	alive  atomic.Bool
}

func dsnVia(t *testing.T, dsn, addr string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.Host = addr
	return u.String()
}

func startReplica(t *testing.T, name, dsn string) *replica {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	px := newProxy(t, u.Host)

	cfg := server.DefaultConfig()
	cfg.Server.APIKeys = []string{apiKey}
	cfg.Server.ShutdownTimeout = 2 * time.Second
	cfg.Store = server.StoreConfig{Driver: "postgres", DSN: dsnVia(t, dsn, px.addr())}
	cfg.Events.PollInterval = pollInterval
	cfg.Events.LeaseTTL = leaseTTL
	cfg.Events.InstanceID = name
	cfg.Events.HandlerTimeout = 5 * time.Second
	cfg.Scheduler.Interval = 0
	cfg.Webhooks.Enabled = false
	cfg.UI.Enabled = false
	cfg.Auth.Tokens.Enabled = false
	cfg.Auth.SSO.Enabled = false
	cfg.Auth.WebAuthn.Enabled = false
	cfg.Plugins = []server.PluginSpec{{Plugin: "chaos-sink", Name: "sink", Config: map[string]any{"replica": name}}}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	// Errors are expected during the chaos (refused connections, failed
	// writes); the replicas log only with CHAOS_VERBOSE set.
	var out io.Writer = io.Discard
	if os.Getenv("CHAOS_VERBOSE") != "" {
		out = os.Stderr
	}
	log := slog.New(slog.NewTextHandler(out, nil)).With("replica", name)
	app, err := server.New(ctx, cfg, log)
	if err != nil {
		cancel()
		t.Fatalf("replica %s: %v", name, err)
	}
	r := &replica{name: name, base: "http://" + ln.Addr().String(), proxy: px, cancel: cancel, done: make(chan error, 1)}
	r.alive.Store(true)
	go func() { r.done <- app.Serve(ctx, ln) }()
	t.Cleanup(func() { r.stop() })
	return r
}

// stop shuts the replica down (idempotent). Errors are expected after a
// crash (the store is unreachable) and ignored.
func (r *replica) stop() {
	if r.alive.Swap(false) {
		r.cancel()
	}
	select {
	case <-r.done:
	case <-time.After(15 * time.Second):
	}
}

// crash kills the replica the hard way: its database link is cut first,
// so it can neither release its lease nor write anything on the way down,
// then its context is cancelled.
func (r *replica) crash() {
	r.alive.Store(false)
	r.proxy.setDown(true)
	r.cancel()
}

// kill cancels the replica's context without cutting its database link
// (an abrupt process stop that still lets deferred cleanup run).
func (r *replica) kill() {
	r.alive.Store(false)
	r.cancel()
}

func call(base, method, path string, body any) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, base+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, nil
}

// --- cluster ----------------------------------------------------------------------

type cluster struct {
	t        *testing.T
	replicas []*replica
	rec      *recorder
	created  atomic.Int64
	failed   atomic.Int64
	dsn      string // direct, not proxied
}

func newCluster(t *testing.T, n int) *cluster {
	t.Helper()
	dsn := pgtest.FreshDB(t)
	rec := &recorder{}
	current.Store(rec)
	t.Cleanup(func() { current.Store(nil) })
	c := &cluster{t: t, rec: rec, dsn: dsn}
	// Replicas start one after another; migrations run under an advisory lock.
	for i := range n {
		c.replicas = append(c.replicas, startReplica(t, fmt.Sprintf("r%d", i+1), dsn))
	}
	for _, r := range c.replicas {
		waitFor(t, 10*time.Second, "replica "+r.name+" healthy", func() bool {
			code, _, err := call(r.base, "GET", "/readyz", nil)
			return err == nil && code == 200
		})
	}
	return c
}

func (c *cluster) live() []*replica {
	var out []*replica
	for _, r := range c.replicas {
		if r.alive.Load() {
			out = append(out, r)
		}
	}
	return out
}

// produce creates tenants (each one appends a tenant.created event)
// through the live replicas, round-robin, until ctx is done. Failed writes
// are counted, not fatal: during a database outage they are expected.
func (c *cluster) produce(ctx context.Context, every time.Duration) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(every)
		defer t.Stop()
		for i := 0; ; i++ {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			live := c.live()
			if len(live) == 0 {
				continue
			}
			r := live[i%len(live)]
			code, _, err := call(r.base, "POST", "/v1/tenants", map[string]any{
				"slug": fmt.Sprintf("chaos-%d-%d", time.Now().UnixNano(), i), "name": "Chaos",
			})
			if err == nil && code == http.StatusCreated {
				c.created.Add(1)
			} else {
				c.failed.Add(1)
			}
		}
	}()
	return done
}

// logSeqs reads every event sequence number from the log through a live
// replica.
func (c *cluster) logSeqs() []int64 {
	c.t.Helper()
	var seqs []int64
	after := int64(0)
	for {
		live := c.live()
		if len(live) == 0 {
			c.t.Fatal("no live replica to read the event log")
		}
		code, body, err := call(live[0].base, "GET", "/v1/events?limit=1000&after="+strconv.FormatInt(after, 10), nil)
		if err != nil || code != 200 {
			c.t.Fatalf("read events: %d %v %s", code, err, body)
		}
		var page struct {
			Items []struct {
				Seq int64 `json:"seq"`
			} `json:"items"`
			Next string `json:"next"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			c.t.Fatal(err)
		}
		for _, it := range page.Items {
			seqs = append(seqs, it.Seq)
		}
		if page.Next == "" {
			return seqs
		}
		after, _ = strconv.ParseInt(page.Next, 10, 64)
	}
}

// waitAllDelivered waits until every event in the log has been delivered
// at least once, then returns the deliveries.
func (c *cluster) waitAllDelivered(timeout time.Duration) []delivery {
	c.t.Helper()
	want := c.logSeqs()
	if len(want) == 0 {
		c.t.Fatal("event log is empty")
	}
	var missing []int64
	waitFor(c.t, timeout, "all events delivered", func() bool {
		got := map[int64]bool{}
		for _, d := range c.rec.snapshot() {
			got[d.seq] = true
		}
		missing = missing[:0]
		for _, s := range want {
			if !got[s] {
				missing = append(missing, s)
			}
		}
		return len(missing) == 0
	}, func() string {
		return fmt.Sprintf("%d of %d events never delivered, e.g. %v", len(missing), len(want), head(missing, 10))
	})
	return c.rec.snapshot()
}

// lease reads the subscription's lease row directly from PostgreSQL (not
// through any replica's proxy).
func (c *cluster) lease() (owner string, expiresIn time.Duration, ok bool) {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, c.dsn)
	if err != nil {
		c.t.Fatalf("lease: %v", err)
	}
	defer conn.Close(ctx)
	var ms float64
	err = conn.QueryRow(ctx, `SELECT owner, (EXTRACT(EPOCH FROM expires_at - now()) * 1000)::float8 FROM leases WHERE name = $1`,
		subscription).Scan(&owner, &ms)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", 0, false
	}
	if err != nil {
		c.t.Fatalf("lease: %v", err)
	}
	return owner, time.Duration(ms) * time.Millisecond, true
}

// holder returns the replica holding the subscription lease, per the
// leases table, and how long the lease has left.
func (c *cluster) holder() (*replica, time.Duration) {
	c.t.Helper()
	var (
		name string
		left time.Duration
	)
	waitFor(c.t, 10*time.Second, "a lease holder", func() bool {
		owner, l, ok := c.lease()
		name, left = owner, l
		return ok && l > 0
	})
	for _, r := range c.replicas {
		if r.name == name {
			return r, left
		}
	}
	c.t.Fatalf("lease held by unknown owner %q", name)
	return nil, 0
}

// checkNoSkips verifies the stream never skips ahead: whenever a delivery
// jumps forward in the log, every event in between was already delivered.
// A failover may rewind (redelivering, which at-least-once allows) but
// must never leave a hole.
func checkNoSkips(t *testing.T, logSeqs []int64, ds []delivery) {
	t.Helper()
	pos := map[int64]int{}
	for i, s := range logSeqs {
		pos[s] = i
	}
	seen := make([]bool, len(logSeqs))
	for _, d := range ds {
		i, ok := pos[d.seq]
		if !ok {
			t.Fatalf("delivered seq %d is not in the event log", d.seq)
		}
		for j := 0; j < i; j++ {
			if !seen[j] {
				t.Fatalf("seq %d delivered (by %s) before seq %d was ever delivered: event skipped", d.seq, d.replica, logSeqs[j])
			}
		}
		seen[i] = true
	}
}

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool, detail ...func() string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			msg := ""
			if len(detail) > 0 {
				msg = ": " + detail[0]()
			}
			t.Fatalf("timed out after %v waiting for %s%s", timeout, what, msg)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func head[T any](s []T, n int) []T { return s[:min(n, len(s))] }

func duplicates(ds []delivery) int {
	seen := map[int64]bool{}
	n := 0
	for _, d := range ds {
		if seen[d.seq] {
			n++
		}
		seen[d.seq] = true
	}
	return n
}

// describeRedeliveries summarises which replicas delivered the same events,
// e.g. "r1->r2: 35 events (seq 120-154)".
func describeRedeliveries(ds []delivery) string {
	first := map[int64]delivery{}
	type pair struct{ from, to string }
	ranges := map[pair][2]int64{}
	counts := map[pair]int{}
	for _, d := range ds {
		f, ok := first[d.seq]
		if !ok {
			first[d.seq] = d
			continue
		}
		p := pair{f.replica, d.replica}
		r, seen := ranges[p]
		if !seen {
			r = [2]int64{d.seq, d.seq}
		}
		r[0], r[1] = min(r[0], d.seq), max(r[1], d.seq)
		ranges[p], counts[p] = r, counts[p]+1
	}
	out := ""
	for p, n := range counts {
		out += fmt.Sprintf(" %s->%s: %d events (seq %d-%d);", p.from, p.to, n, ranges[p][0], ranges[p][1])
	}
	return out
}

// --- tests --------------------------------------------------------------------------

// TestLeaseHolderFailover kills the replica holding the subscription lease
// while events keep arriving, and checks that another replica takes over
// within the lease TTL, that every event is delivered at least once and
// that none is skipped.
func TestLeaseHolderFailover(t *testing.T) {
	for _, mode := range []string{"crash", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			c := newCluster(t, 3)
			ctx, stopProducing := context.WithCancel(context.Background())
			produced := c.produce(ctx, 20*time.Millisecond)
			defer func() { stopProducing(); <-produced }()

			time.Sleep(2 * time.Second) // mid-stream
			victim, leaseLeft := c.holder()
			killedAt := time.Now()
			if mode == "crash" {
				victim.crash()
			} else {
				victim.kill()
			}
			t.Logf("%s: killed lease holder %s (lease valid for another %v) with %d deliveries so far",
				mode, victim.name, leaseLeft.Round(time.Millisecond), len(c.rec.snapshot()))

			// Delivery must resume on another replica within the TTL (plus
			// one acquisition retry and some scheduling slack).
			bound := leaseTTL + leaseTTL/3 + time.Second
			var resumed time.Time
			waitFor(t, bound+5*time.Second, "delivery to resume on another replica", func() bool {
				for _, d := range c.rec.snapshot() {
					if d.replica != victim.name && d.at.After(killedAt) {
						resumed = d.at
						return true
					}
				}
				return false
			})
			gap := resumed.Sub(killedAt)
			t.Logf("%s: delivery resumed after %v (bound %v)", mode, gap.Round(time.Millisecond), bound)
			if gap > bound {
				t.Errorf("delivery resumed after %v, want <= %v", gap, bound)
			}
			// A crashed holder cannot release its lease, so nobody may take
			// over before it expires: two holders would mean split brain.
			if mode == "crash" && gap < leaseLeft-250*time.Millisecond {
				t.Errorf("another replica delivered %v after the crash, but the lease was valid for %v", gap, leaseLeft)
			}

			time.Sleep(leaseTTL) // keep producing after the failover
			stopProducing()
			<-produced

			ds := c.waitAllDelivered(30 * time.Second)
			seqs := c.logSeqs()
			checkNoSkips(t, seqs, ds)
			t.Logf("%s: %d events (%d writes ok, %d failed), %d deliveries, %d redeliveries%s", mode,
				len(seqs), c.created.Load(), c.failed.Load(), len(ds), duplicates(ds), describeRedeliveries(ds))
		})
	}
}

// TestDatabaseRestart cuts every replica's database connections (as a
// PostgreSQL restart or failover would), keeps the outage for a while,
// then restores it. The API must recover, the dispatcher must reconnect
// and resume, and no event may be lost or skipped.
func TestDatabaseRestart(t *testing.T) {
	c := newCluster(t, 2)
	ctx, stopProducing := context.WithCancel(context.Background())
	produced := c.produce(ctx, 25*time.Millisecond)
	defer func() { stopProducing(); <-produced }()

	time.Sleep(2 * time.Second)
	before := len(c.rec.snapshot())
	for _, r := range c.replicas {
		r.proxy.setDown(true)
	}
	outage := 3 * time.Second
	time.Sleep(outage)
	failedDuringOutage := c.failed.Load()
	for _, r := range c.replicas {
		r.proxy.setDown(false)
	}
	restoredAt := time.Now()

	// Writes succeed again soon (pgxpool drops the dead connections).
	okBefore := c.created.Load()
	waitFor(t, 10*time.Second, "writes to succeed after the restart", func() bool { return c.created.Load() > okBefore+5 })
	t.Logf("writes recovered %v after the database came back", time.Since(restoredAt).Round(time.Millisecond))

	// Delivery resumes (the lease may have to expire first).
	var resumed time.Time
	waitFor(t, leaseTTL+leaseTTL/3+10*time.Second, "delivery to resume", func() bool {
		for _, d := range c.rec.snapshot() {
			if d.at.After(restoredAt) {
				resumed = d.at
				return true
			}
		}
		return false
	})
	t.Logf("delivery resumed %v after the database came back", resumed.Sub(restoredAt).Round(time.Millisecond))

	time.Sleep(time.Second)
	stopProducing()
	<-produced
	ds := c.waitAllDelivered(30 * time.Second)
	seqs := c.logSeqs()
	checkNoSkips(t, seqs, ds)
	if failedDuringOutage == 0 {
		t.Log("note: no write failed during the outage")
	}
	t.Logf("%d events, %d deliveries before the outage, %d total, %d redeliveries, %d writes failed during the outage",
		len(seqs), before, len(ds), duplicates(ds), failedDuringOutage)
}
