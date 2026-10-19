package archive

import (
	"bufio"
	"bytes"
	"cmp"
	"compress/gzip"
	"container/heap"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// Query selects archived events.
type Query struct {
	// From (inclusive) and To (exclusive) bound Event.Time.
	From, To time.Time
	// Types are glob patterns on Event.Type; empty means all.
	Types []string
	// TenantID, when set, keeps only that tenant's events.
	TenantID string
	// Limit stops after that many events (0: no limit).
	Limit int
}

func (q Query) match(e sdk.Event) bool {
	if e.Time.Before(q.From) || !e.Time.Before(q.To) {
		return false
	}
	if q.TenantID != "" && e.TenantID != q.TenantID {
		return false
	}
	return sdk.EventFilter{Types: q.Types}.Match(e)
}

// maxRange bounds a query so a typo cannot list decades of days.
const maxRange = 5 * 366 * 24 * time.Hour

func (q Query) validate() error {
	switch {
	case q.From.IsZero():
		return errors.New("from is required")
	case !q.To.After(q.From):
		return errors.New("to must be after from")
	case q.To.Sub(q.From) > maxRange:
		return errors.New("range must not exceed 5 years")
	case q.Limit < 0:
		return errors.New("limit must not be negative")
	}
	for _, p := range q.Types {
		if _, err := path.Match(p, ""); err != nil || p == "" {
			return fmt.Errorf("invalid type pattern %q", p)
		}
	}
	return nil
}

// segments lists the objects whose hour overlaps [q.From, q.To), sorted by
// first sequence number.
func (p *Plugin) segments(ctx context.Context, q Query) ([]segment, error) {
	var segs []segment
	from, to := q.From.UTC(), q.To.UTC()
	for day := from.Truncate(24 * time.Hour); day.Before(to); day = day.Add(24 * time.Hour) {
		keys, err := p.store.List(ctx, dayPrefix(p.cfg.Prefix, day))
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", dayPrefix(p.cfg.Prefix, day), err)
		}
		for _, k := range keys {
			s, ok := parseKey(p.cfg.Prefix, k)
			if ok && s.hour.Before(to) && s.hour.Add(time.Hour).After(from) {
				segs = append(segs, s)
			}
		}
	}
	slices.SortFunc(segs, func(a, b segment) int {
		return cmp.Or(cmp.Compare(a.first, b.first), cmp.Compare(a.last, b.last), strings.Compare(a.key, b.key))
	})
	return segs, nil
}

// load reads and decodes one object, sorted by sequence number.
func (p *Plugin) load(ctx context.Context, s segment) ([]sdk.Event, error) {
	raw, err := p.store.Get(ctx, s.key)
	if errors.Is(err, errNotFound) {
		return nil, nil // superseded and deleted since it was listed
	} else if err != nil {
		return nil, err
	}
	var r io.Reader = bytes.NewReader(raw)
	if s.gz {
		zr, err := gzip.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.key, err)
		}
		defer zr.Close()
		r = zr
	}
	var events []sdk.Event
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 64<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var e sdk.Event
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("%s: %w", s.key, err)
		}
		events = append(events, e)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", s.key, err)
	}
	slices.SortStableFunc(events, func(a, b sdk.Event) int { return cmp.Compare(a.Seq, b.Seq) })
	return events, nil
}

// run is the remaining events of one loaded object.
type run []sdk.Event

// runHeap orders runs by their next event's sequence number.
type runHeap []run

func (h runHeap) Len() int           { return len(h) }
func (h runHeap) Less(i, j int) bool { return h[i][0].Seq < h[j][0].Seq }
func (h runHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *runHeap) Push(x any)        { *h = append(*h, x.(run)) }
func (h *runHeap) Pop() any {
	old := *h
	r := old[len(old)-1]
	*h = old[:len(old)-1]
	return r
}

// scan calls fn for every archived event matching q, in sequence order and
// without duplicates. Objects are merged lazily: one is loaded only once
// every event before its first sequence number has been emitted, so memory
// holds just the objects that overlap. fn returning false stops the scan.
func (p *Plugin) scan(ctx context.Context, q Query, segs []segment, fn func(sdk.Event) (bool, error)) error {
	h := &runHeap{}
	next := 0
	var (
		curSeq int64 = -1
		seen         = map[string]bool{} // IDs emitted at curSeq
		n      int
	)
	for {
		for next < len(segs) && (h.Len() == 0 || segs[next].first <= (*h)[0][0].Seq) {
			if err := ctx.Err(); err != nil {
				return err
			}
			events, err := p.load(ctx, segs[next])
			if err != nil {
				return err
			}
			next++
			if len(events) > 0 {
				heap.Push(h, run(events))
			}
		}
		if h.Len() == 0 {
			return nil
		}
		r := (*h)[0]
		e := r[0]
		if len(r) == 1 {
			heap.Pop(h)
		} else {
			(*h)[0] = r[1:]
			heap.Fix(h, 0)
		}
		// Duplicates (retries, overlapping objects) share Seq and ID, so
		// they come out of the merge next to each other.
		if e.Seq != curSeq {
			curSeq = e.Seq
			clear(seen)
		}
		if seen[e.ID] {
			continue
		}
		seen[e.ID] = true
		if !q.match(e) {
			continue
		}
		cont, err := fn(e)
		if err != nil || !cont {
			return err
		}
		if n++; q.Limit > 0 && n >= q.Limit {
			return nil
		}
	}
}

// authorize allows platform-wide callers that may perform every action.
// Plugin routes are already guarded by plugins:route; archived events span
// all tenants, so tenant-scoped callers are always refused.
func (p *Plugin) authorize(r *http.Request, actions ...sdk.Action) bool {
	pr, ok := sdk.PrincipalFrom(r.Context())
	if !ok || pr.TenantID != "" {
		return false
	}
	for _, a := range actions {
		if p.host.Authorize(r.Context(), a, sdk.Resource{Type: "event"}) != nil {
			return false
		}
	}
	return true
}

// parseQuery reads from, to, type (repeatable or comma-separated),
// tenant_id and limit.
func parseQuery(v map[string][]string, now time.Time) (Query, error) {
	get := func(k string) string {
		if len(v[k]) > 0 {
			return v[k][0]
		}
		return ""
	}
	var q Query
	var err error
	if s := get("from"); s != "" {
		if q.From, err = time.Parse(time.RFC3339Nano, s); err != nil {
			return q, fmt.Errorf("from: must be RFC 3339, got %q", s)
		}
	}
	q.To = now
	if s := get("to"); s != "" {
		if q.To, err = time.Parse(time.RFC3339Nano, s); err != nil {
			return q, fmt.Errorf("to: must be RFC 3339, got %q", s)
		}
	}
	for _, t := range v["type"] {
		for p := range strings.SplitSeq(t, ",") {
			if p = strings.TrimSpace(p); p != "" {
				q.Types = append(q.Types, p)
			}
		}
	}
	q.TenantID = get("tenant_id")
	if s := get("limit"); s != "" {
		if q.Limit, err = strconv.Atoi(s); err != nil {
			return q, fmt.Errorf("limit: %w", err)
		}
	}
	return q, q.validate()
}

// errorTrailer reports an error that happened after streaming started.
const errorTrailer = "Tenarium-Archive-Error"

// serveEvents streams archived events as NDJSON (GET /events).
func (p *Plugin) serveEvents(w http.ResponseWriter, r *http.Request) {
	if !p.authorize(r, sdk.ActionEventsRead) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	q, err := parseQuery(r.URL.Query(), p.now())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	segs, err := p.segments(r.Context(), q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Trailer", errorTrailer)
	w.WriteHeader(http.StatusOK)
	bw := bufio.NewWriterSize(w, 32<<10)
	enc := json.NewEncoder(bw)
	enc.SetEscapeHTML(false)
	flusher, _ := w.(http.Flusher)
	n := 0
	err = p.scan(r.Context(), q, segs, func(e sdk.Event) (bool, error) {
		if err := enc.Encode(e); err != nil {
			return false, err
		}
		// Push output regularly so clients see progress on long ranges.
		if n++; n%500 == 0 && flusher != nil {
			if err := bw.Flush(); err != nil {
				return false, err
			}
			flusher.Flush()
		}
		return true, nil
	})
	if ferr := bw.Flush(); err == nil {
		err = ferr
	}
	if err != nil && r.Context().Err() == nil {
		p.log.Error("streaming archived events failed", "err", err)
		w.Header().Set(errorTrailer, err.Error())
	}
}
