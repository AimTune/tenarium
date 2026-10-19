package archive

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

var t0 = time.Date(2026, 10, 10, 8, 30, 0, 0, time.UTC)

// clock is a settable time source.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// flakyStore wraps a store and fails Put while failPut is set.
type flakyStore struct {
	objectStore
	mu      sync.Mutex
	failPut bool
	puts    int
}

func (f *flakyStore) Put(ctx context.Context, key string, body []byte, ct string) error {
	f.mu.Lock()
	fail := f.failPut
	f.puts++
	f.mu.Unlock()
	if fail {
		return errors.New("storage down")
	}
	return f.objectStore.Put(ctx, key, body, ct)
}

type fixture struct {
	p     *Plugin
	reg   *sdktest.Registrar
	store *flakyStore
	clock *clock
}

func setup(t *testing.T, cfg map[string]any) *fixture {
	t.Helper()
	full := map[string]any{"backend": "file", "file": map[string]any{"dir": t.TempDir()}}
	for k, v := range cfg {
		full[k] = v
	}
	fs, err := newFileStore(full["file"].(map[string]any)["dir"].(string))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{store: &flakyStore{objectStore: fs}, clock: &clock{now: t0}}
	f.p = &Plugin{store: f.store, now: f.clock.Now}
	f.reg = sdktest.NewRegistrar(full)
	if err := f.p.Init(context.Background(), f.reg); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return f
}

func event(seq int64, typ, tenant string, at time.Time) sdk.Event {
	return sdk.Event{
		Seq: seq, ID: "evt-" + strconv.FormatInt(seq, 10), Type: typ, Source: "tenarium",
		TenantID: tenant, Time: at, Data: json.RawMessage(`{"n":` + strconv.FormatInt(seq, 10) + `}`),
	}
}

func (f *fixture) deliver(t *testing.T, events ...sdk.Event) {
	t.Helper()
	for _, e := range events {
		if err := f.reg.Deliver(context.Background(), "archive", e); err != nil {
			t.Fatalf("deliver %d: %v", e.Seq, err)
		}
	}
}

func (f *fixture) keys(t *testing.T) []string {
	t.Helper()
	keys, err := f.store.List(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(keys)
	return keys
}

func key(hour string, first, last int64) string {
	return fmt.Sprintf("events/%s/%020d-%020d.ndjson.gz", hour, first, last)
}

func TestBatchingAndKeys(t *testing.T) {
	f := setup(t, map[string]any{"batch_size": 3})
	for i := int64(1); i <= 5; i++ {
		f.deliver(t, event(i, "tenant.updated", "t1", t0.Add(time.Duration(i)*time.Second)))
	}
	want := []string{key("2026/10/10/08", 1, 3), key("2026/10/10/08", 4, 5)}
	if got := f.keys(t); !slices.Equal(got, want) {
		t.Fatalf("keys = %v, want %v", got, want)
	}
	// A new hour starts a new object, even within batch_size.
	f.deliver(t, event(6, "tenant.updated", "t1", t0.Add(30*time.Minute)))
	want = append(want, key("2026/10/10/09", 6, 6))
	if got := f.keys(t); !slices.Equal(got, want) {
		t.Fatalf("keys = %v, want %v", got, want)
	}
	// flush_interval (default 1m) closes an old batch.
	f.clock.Add(2 * time.Minute)
	f.deliver(t, event(7, "tenant.updated", "t1", t0.Add(31*time.Minute)))
	want = append(want, key("2026/10/10/09", 7, 7))
	if got := f.keys(t); !slices.Equal(got, want) {
		t.Fatalf("keys = %v, want %v", got, want)
	}
}

func TestEventFilterAndCompressionNone(t *testing.T) {
	f := setup(t, map[string]any{"events": []any{"tenant.*"}, "compression": "none", "prefix": "/arch/tenarium/"})
	f.deliver(t, event(1, "tenant.created", "t1", t0), event(2, "plan.created", "", t0))
	keys := f.keys(t)
	if len(keys) != 1 || keys[0] != fmt.Sprintf("arch/tenarium/2026/10/10/08/%020d-%020d.ndjson", 1, 1) {
		t.Fatalf("keys = %v", keys)
	}
	raw, _ := f.store.Get(context.Background(), keys[0])
	var e sdk.Event
	if err := json.Unmarshal(raw, &e); err != nil || e.ID != "evt-1" || !strings.HasSuffix(string(raw), "}\n") {
		t.Fatalf("object = %q (%v)", raw, err)
	}
}

func TestAckOnlyWhenStored(t *testing.T) {
	f := setup(t, nil)
	f.deliver(t, event(1, "tenant.created", "t1", t0))
	f.store.failPut = true
	if err := f.reg.Deliver(context.Background(), "archive", event(2, "tenant.updated", "t1", t0)); err == nil {
		t.Fatal("event acknowledged although it was not stored")
	}
	// The open batch is unchanged: the retry writes 1-2 and removes 1-1.
	f.store.failPut = false
	f.deliver(t, event(2, "tenant.updated", "t1", t0))
	if got, want := f.keys(t), []string{key("2026/10/10/08", 1, 2)}; !slices.Equal(got, want) {
		t.Fatalf("keys = %v, want %v", got, want)
	}
	// Redelivering a stored event writes nothing.
	puts := f.store.puts
	f.deliver(t, event(2, "tenant.updated", "t1", t0))
	if f.store.puts != puts {
		t.Fatal("redelivered event rewritten")
	}
}

// get calls GET /events as a platform admin.
func get(t *testing.T, f *fixture, query string, pr *sdk.Principal) (*http.Response, []sdk.Event) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/events?"+query, nil)
	if pr != nil {
		req = req.WithContext(sdk.WithPrincipal(req.Context(), pr))
	}
	rec := httptest.NewRecorder()
	f.reg.Mux.ServeHTTP(rec, req)
	resp := rec.Result()
	var events []sdk.Event
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() && resp.StatusCode == http.StatusOK {
		var e sdk.Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("line %q: %v", sc.Text(), err)
		}
		events = append(events, e)
	}
	return resp, events
}

var admin = &sdk.Principal{Subject: "ops", Kind: "user", Authenticator: "oidc"}

func seqs(events []sdk.Event) []int64 {
	out := make([]int64, len(events))
	for i, e := range events {
		out[i] = e.Seq
	}
	return out
}

func rangeQuery(from, to time.Time, extra string) string {
	q := "from=" + url.QueryEscape(from.Format(time.RFC3339)) + "&to=" + url.QueryEscape(to.Format(time.RFC3339))
	if extra != "" {
		q += "&" + extra
	}
	return q
}

func TestReadBack(t *testing.T) {
	f := setup(t, map[string]any{"batch_size": 2})
	// Events over two days; times are not strictly ordered by Seq.
	day2 := t0.Add(24 * time.Hour)
	f.deliver(t,
		event(1, "tenant.created", "t1", t0),
		event(2, "tenant.created", "t2", t0.Add(time.Minute)),
		event(3, "plan.created", "", t0.Add(2*time.Minute)),
		event(4, "tenant.updated", "t1", t0.Add(40*time.Minute)), // 09:10
		event(5, "tenant.updated", "t2", t0.Add(35*time.Minute)), // 09:05
		event(6, "tenant.deleted", "t1", day2),
	)
	// Simulate leftovers: a superseded object that was not deleted and an
	// object written twice by two replicas.
	ctx := context.Background()
	dup, _ := encode([]sdk.Event{event(1, "tenant.created", "t1", t0)}, true)
	_ = f.store.Put(ctx, key("2026/10/10/08", 1, 1), dup, "")
	dup, _ = encode([]sdk.Event{event(5, "tenant.updated", "t2", t0.Add(35*time.Minute)), event(4, "tenant.updated", "t1", t0.Add(40*time.Minute))}, true)
	_ = f.store.Put(ctx, key("2026/10/10/09", 4, 5)+"x", dup, "") // ignored: not a valid key
	_ = f.store.Put(ctx, "events/2026/10/10/09/"+fmt.Sprintf("%020d-%020d.ndjson.gz", 4, 5), dup, "")

	resp, events := get(t, f, rangeQuery(t0.Add(-time.Hour), day2.Add(time.Hour), ""), admin)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got := seqs(events); !slices.Equal(got, []int64{1, 2, 3, 4, 5, 6}) {
		t.Fatalf("seqs = %v", got)
	}
	if string(events[0].Data) != `{"n":1}` || events[0].TenantID != "t1" {
		t.Fatalf("event 1 = %+v", events[0])
	}
	if resp.Trailer.Get(errorTrailer) != "" {
		t.Fatalf("error trailer: %s", resp.Trailer.Get(errorTrailer))
	}

	for _, tc := range []struct {
		query string
		want  []int64
	}{
		{rangeQuery(t0, t0.Add(time.Hour), ""), []int64{1, 2, 3, 4, 5}},
		{rangeQuery(t0.Add(time.Minute), t0.Add(36*time.Minute), ""), []int64{2, 3, 5}}, // to is exclusive
		{rangeQuery(t0, day2.Add(time.Second), "type=tenant.*"), []int64{1, 2, 4, 5, 6}},
		{rangeQuery(t0, day2.Add(time.Second), "type=plan.created,tenant.deleted"), []int64{3, 6}},
		{rangeQuery(t0, day2.Add(time.Second), "type=plan.created&type=tenant.deleted"), []int64{3, 6}},
		{rangeQuery(t0, day2.Add(time.Second), "tenant_id=t1"), []int64{1, 4, 6}},
		{rangeQuery(t0, day2.Add(time.Second), "tenant_id=t2&limit=1"), []int64{2}},
		{rangeQuery(day2.Add(time.Hour), day2.Add(2*time.Hour), ""), nil},
	} {
		resp, events := get(t, f, tc.query, admin)
		if resp.StatusCode != http.StatusOK || !slices.Equal(seqs(events), tc.want) {
			t.Errorf("%s: status %d, seqs %v, want %v", tc.query, resp.StatusCode, seqs(events), tc.want)
		}
	}
}

func TestReadBadRequests(t *testing.T) {
	f := setup(t, nil)
	for _, q := range []string{
		"",
		"from=yesterday",
		rangeQuery(t0, t0.Add(-time.Hour), ""),
		rangeQuery(t0, t0.Add(10*366*24*time.Hour), ""),
		rangeQuery(t0, t0.Add(time.Hour), "type=["),
		rangeQuery(t0, t0.Add(time.Hour), "limit=-1"),
	} {
		if resp, _ := get(t, f, q, admin); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%q: status %d", q, resp.StatusCode)
		}
	}
	// to defaults to now.
	if resp, _ := get(t, f, "from="+t0.Add(-time.Hour).Format(time.RFC3339), admin); resp.StatusCode != http.StatusOK {
		t.Errorf("to default: status %d", resp.StatusCode)
	}
}

func TestRoutesArePlatformOnly(t *testing.T) {
	f := setup(t, nil)
	q := rangeQuery(t0, t0.Add(time.Hour), "")
	if resp, _ := get(t, f, q, nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("anonymous: %d", resp.StatusCode)
	}
	if resp, _ := get(t, f, q, &sdk.Principal{Subject: "a", TenantID: "t1"}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("tenant-scoped: %d", resp.StatusCode)
	}
	var asked []sdk.Action
	f.reg.HostImpl.AuthorizeFunc = func(_ context.Context, _ *sdk.Principal, a sdk.Action, _ sdk.Resource) error {
		asked = append(asked, a)
		if a == sdk.ActionDeadLettersReplay {
			return sdk.ErrForbidden
		}
		return nil
	}
	if resp, _ := get(t, f, q, admin); resp.StatusCode != http.StatusOK {
		t.Errorf("admin read: %d", resp.StatusCode)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/replay", strings.NewReader(`{}`))
	f.reg.Mux.ServeHTTP(rec, req.WithContext(sdk.WithPrincipal(req.Context(), admin)))
	if rec.Code != http.StatusForbidden {
		t.Errorf("replay without deadletters:replay: %d", rec.Code)
	}
	if !slices.Contains(asked, sdk.ActionEventsRead) || !slices.Contains(asked, sdk.ActionDeadLettersReplay) {
		t.Errorf("actions checked: %v", asked)
	}
}

func TestParseKey(t *testing.T) {
	hour := time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC)
	for _, prefix := range []string{"", "events", "a/b"} {
		for _, gz := range []bool{true, false} {
			k := objectKey(prefix, hour, 7, 42, gz)
			s, ok := parseKey(prefix, k)
			if !ok || s.first != 7 || s.last != 42 || !s.hour.Equal(hour) || s.gz != gz || s.key != k {
				t.Errorf("parseKey(%q) = %+v, %v", k, s, ok)
			}
			if !strings.HasPrefix(k, dayPrefix(prefix, hour)) {
				t.Errorf("%s not below %s", k, dayPrefix(prefix, hour))
			}
		}
	}
	for _, k := range []string{
		"events/2026/01/02/03/7-42.ndjson.gz",
		"events/2026/01/02/03/00000000000000000042-00000000000000000007.ndjson.gz",
		"events/2026/13/02/03/00000000000000000007-00000000000000000042.ndjson.gz",
		"other/2026/01/02/03/00000000000000000007-00000000000000000042.ndjson.gz",
		"events/x/2026/01/02/03/00000000000000000007-00000000000000000042.ndjson.gz",
	} {
		if s, ok := parseKey("events", k); ok {
			t.Errorf("parseKey(%q) accepted: %+v", k, s)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	for _, cfg := range []map[string]any{
		{"backend": "ftp"},
		{"backend": "file"},
		{"backend": "file", "file": map[string]any{"dir": "x"}, "s3": map[string]any{}},
		{"backend": "file", "file": map[string]any{"dir": "x"}, "batch_size": 5000},
		{"backend": "file", "file": map[string]any{"dir": "x"}, "flush_interval": "soon"},
		{"backend": "file", "file": map[string]any{"dir": "x"}, "flush_interval": "-1s"},
		{"backend": "file", "file": map[string]any{"dir": "x"}, "compression": "zstd"},
		{"backend": "file", "file": map[string]any{"dir": "x"}, "prefix": "a/../b"},
		{"backend": "file", "file": map[string]any{"dir": "x"}, "events": []any{"["}},
		{"backend": "file", "file": map[string]any{"dir": "x"}, "replay": map[string]any{"timeout": "x"}},
		{"backend": "s3", "s3": map[string]any{"endpoint": "https://s3", "access_key": "a", "secret_key": "s", "bucket": "b"}},
		{"backend": "gcs", "gcs": map[string]any{"bucket": "b", "anonymous": true, "credentials_json": "{}"}},
		{"backend": "azure", "azure": map[string]any{"container": "c"}},
		{"backend": "file", "file": map[string]any{"dir": "x"}, "unknown": 1},
	} {
		if err := (&Plugin{}).Init(context.Background(), sdktest.NewRegistrar(cfg)); err == nil {
			t.Errorf("accepted %v", cfg)
		}
	}
	// Defaults.
	f := setup(t, nil)
	c := f.p.cfg
	if c.Prefix != "events" || c.BatchSize != 100 || c.Compression != "gzip" || c.MaxAttempts != 30 ||
		f.p.flushInterval != time.Minute || f.p.timeout != 30*time.Second || f.p.replay.cfg.MaxEvents != 100000 {
		t.Fatalf("defaults: %+v", c)
	}
	sub := f.reg.Subscriptions[0]
	if sub.Name != "archive" || sub.Options.MaxAttempts != 30 || sub.Options.MaxBackoff != 2*time.Minute {
		t.Fatalf("subscription: %+v", sub)
	}
	if !slices.Equal(f.reg.Routes, []string{"GET /events", "POST /replay"}) {
		t.Fatalf("routes: %v", f.reg.Routes)
	}
	if err := f.p.Health(context.Background()); err != nil {
		t.Fatalf("Health: %v", err)
	}
}

func TestConfigSchema(t *testing.T) {
	sch, err := schema.Compile((&Plugin{}).Manifest().ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	for _, good := range []map[string]any{
		{"backend": "file", "file": map[string]any{"dir": "/var/archive"}, "prefix": "tenarium/events", "events": []any{"tenant.*"},
			"batch_size": 500, "flush_interval": "5m", "compression": "none", "timeout": "10s", "max_attempts": 5,
			"replay": map[string]any{"timeout": "5s", "max_events": 10, "allow_http": true, "allow_private_networks": true}},
		{"backend": "s3", "s3": map[string]any{"endpoint": "s3.amazonaws.com", "region": "eu-west-1", "access_key": "a", "secret_key": "s", "secure": true, "bucket": "archive"}},
		{"backend": "gcs", "gcs": map[string]any{"bucket": "archive", "credentials_file": "/sa.json"}},
		{"backend": "azure", "azure": map[string]any{"connection_string": "UseDevelopmentStorage=true", "container": "archive"}},
		{"backend": "azure", "azure": map[string]any{"account_name": "acct", "account_key": "a2V5", "container": "event-archive"}},
	} {
		if err := sch.Validate(good); err != nil {
			t.Errorf("valid config rejected: %v: %v", good, err)
		}
	}
	for _, bad := range []map[string]any{
		{},
		{"backend": "s3"},
		{"backend": "file", "file": map[string]any{}},
		{"backend": "file", "file": map[string]any{"dir": "d"}, "batch_size": 0},
		{"backend": "file", "file": map[string]any{"dir": "d"}, "compression": "lz4"},
		{"backend": "file", "file": map[string]any{"dir": "d"}, "prefix": "a b"},
		{"backend": "s3", "s3": map[string]any{"endpoint": "e", "access_key": "a", "secret_key": "s"}},
		{"backend": "gcs", "gcs": map[string]any{"bucket": "b", "credentials_file": "f", "credentials_json": "{}"}},
		{"backend": "azure", "azure": map[string]any{"container": "c"}},
		{"backend": "azure", "azure": map[string]any{"connection_string": "x", "account_name": "acct", "container": "c"}},
		{"backend": "azure", "azure": map[string]any{"connection_string": "x", "container": "Bad_Name"}},
	} {
		if err := sch.Validate(bad); err == nil {
			t.Errorf("invalid config accepted: %v", bad)
		}
	}
}

// replayTarget records requests and answers with status.
type replayTarget struct {
	mu     sync.Mutex
	reqs   []*http.Request
	bodies [][]byte
	status func(n int) int
}

func (rt *replayTarget) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	rt.mu.Lock()
	rt.reqs = append(rt.reqs, r)
	rt.bodies = append(rt.bodies, b)
	n := len(rt.reqs)
	rt.mu.Unlock()
	w.WriteHeader(rt.status(n))
}

func postReplay(t *testing.T, f *fixture, body any) (int, ReplayResult) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/replay", strings.NewReader(string(raw)))
	req = req.WithContext(sdk.WithPrincipal(req.Context(), admin))
	rec := httptest.NewRecorder()
	f.reg.Mux.ServeHTTP(rec, req)
	var res ReplayResult
	if rec.Code == http.StatusOK || rec.Code == http.StatusBadGateway {
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("response %q: %v", rec.Body.String(), err)
		}
	}
	return rec.Code, res
}

func TestReplay(t *testing.T) {
	f := setup(t, map[string]any{"replay": map[string]any{"allow_http": true, "allow_private_networks": true}})
	f.p.replay.backoff = time.Millisecond
	f.deliver(t,
		event(1, "tenant.created", "t1", t0),
		event(2, "tenant.created", "t2", t0.Add(time.Second)),
		event(3, "tenant.updated", "t1", t0.Add(2*time.Second)),
	)
	target := &replayTarget{status: func(int) int { return http.StatusNoContent }}
	srv := httptest.NewServer(target)
	t.Cleanup(srv.Close)

	secret := "whsec_c2VjcmV0LWtleQ=="
	code, res := postReplay(t, f, map[string]any{
		"from": t0, "to": t0.Add(time.Hour), "type": "tenant.*", "tenant_id": "t1", "url": srv.URL + "/hook", "secret": secret,
	})
	if code != http.StatusOK || res.Matched != 2 || res.Sent != 2 || res.Failed != 0 || res.LastSeq != 3 || res.Truncated {
		t.Fatalf("replay = %d %+v", code, res)
	}
	r := target.reqs[0]
	var ce sdk.CloudEvent
	if err := json.Unmarshal(target.bodies[0], &ce); err != nil || ce.ID != "evt-1" || ce.Sequence != "1" || ce.SpecVersion != "1.0" {
		t.Fatalf("body %s (%v)", target.bodies[0], err)
	}
	ts := r.Header.Get("webhook-timestamp")
	if r.URL.Path != "/hook" || r.Header.Get("Content-Type") != "application/cloudevents+json" ||
		r.Header.Get("webhook-id") != "evt-1" || ts != strconv.FormatInt(t0.Unix(), 10) ||
		r.Header.Get("webhook-signature") != "v1,"+Sign(secret, "evt-1", ts, target.bodies[0]) {
		t.Fatalf("headers %v", r.Header)
	}
	// Known Standard Webhooks vector: secret "secret-key" base64-encoded.
	if Sign(secret, "id", "1", []byte("{}")) != Sign("secret-key", "id", "1", []byte("{}")) {
		t.Fatal("whsec_ secret not decoded")
	}

	// The limit stops the replay.
	code, res = postReplay(t, f, map[string]any{"from": t0, "to": t0.Add(time.Hour), "url": srv.URL, "secret": "s", "limit": 2})
	if code != http.StatusOK || res.Sent != 2 || !res.Truncated {
		t.Fatalf("limited replay = %d %+v", code, res)
	}

	// A failing endpoint stops the replay after retries.
	target.status = func(n int) int {
		if n > 5 {
			return http.StatusServiceUnavailable
		}
		return http.StatusOK
	}
	code, res = postReplay(t, f, map[string]any{"from": t0, "to": t0.Add(time.Hour), "url": srv.URL, "secret": "s"})
	if code != http.StatusBadGateway || res.Sent != 1 || res.Failed != 1 || res.Matched != 2 || res.LastSeq != 1 ||
		!strings.Contains(res.Error, "503") || len(target.reqs) != 4+1+replayAttempts {
		t.Fatalf("failed replay = %d %+v (%d requests)", code, res, len(target.reqs))
	}
}

func TestReplayRejectsTargets(t *testing.T) {
	f := setup(t, nil)
	f.deliver(t, event(1, "tenant.created", "t1", t0))
	base := map[string]any{"from": t0, "to": t0.Add(time.Hour), "secret": "s"}
	for _, u := range []string{
		"http://example.com/hook",        // https required
		"https://127.0.0.1/hook",         // loopback
		"https://10.0.0.8/hook",          // private
		"https://169.254.169.254/latest", // metadata
		"https://localhost/hook",
		"https://user:pw@example.com/hook",
		"/relative",
	} {
		body := map[string]any{"url": u}
		for k, v := range base {
			body[k] = v
		}
		if code, _ := postReplay(t, f, body); code != http.StatusBadRequest {
			t.Errorf("%s: status %d", u, code)
		}
	}
	if code, _ := postReplay(t, f, map[string]any{"from": t0, "url": "https://example.com"}); code != http.StatusBadRequest {
		t.Errorf("missing secret: %d", code)
	}
	if code, _ := postReplay(t, f, map[string]any{"from": t0, "url": "https://example.com", "secret": "s", "extra": 1}); code != http.StatusBadRequest {
		t.Errorf("unknown field: %d", code)
	}
}

// TestGuardedClient checks the dial-time address check, which also covers
// names that resolve to internal addresses (DNS rebinding).
func TestGuardedClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	t.Cleanup(srv.Close)
	resp, err := guardedClient(time.Second, false).Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("guarded client reached a loopback address")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("err = %v", err)
	}
	resp, err = guardedClient(time.Second, true).Get(srv.URL)
	if err != nil {
		t.Fatalf("allow_private_networks: %v", err)
	}
	resp.Body.Close()
}
