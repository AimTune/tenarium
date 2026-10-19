package chatnotify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// maxResponse bounds response bodies.
const maxResponse = 1 << 20

type target struct {
	p        *Plugin
	cfg      TargetConfig
	events   []string
	template *template.Template
	limiter  *bucket
	seen     *seenSet
	drops    *dropCount // shared with the copies made by Reconfigure
}

// dropCount counts notifications suppressed by the rate limit.
type dropCount struct {
	mu sync.Mutex
	n  int
}

// notify renders and posts one event.
func (t *target) notify(ctx context.Context, e sdk.Event) error {
	if n := t.p.next.Load(); n != nil {
		return n.target(t.cfg.Name).notify(ctx, e)
	}
	if t.seen.has(e.ID) {
		return nil // already posted; redelivered after a lost ack
	}
	if !t.limiter.allow() {
		t.drops.mu.Lock()
		t.drops.n++
		n := t.drops.n
		t.drops.mu.Unlock()
		t.p.log.Warn("notification dropped by rate limit", "target", t.cfg.Name, "event", e.ID, "type", e.Type, "suppressed", n)
		return nil
	}
	d := newData(e)
	if d.Tenant == nil && e.TenantID != "" && t.p.host != nil {
		// Member and usage events carry only the tenant ID; look the tenant
		// up for a readable message. Best effort: it may be gone already.
		if tn, err := t.p.host.GetTenant(ctx, e.TenantID); err == nil {
			d.Tenant = &tn
		}
	}
	title := t.p.render(t.p.title, d)
	text := t.p.render(t.p.templateFor(t, e.Type), d)

	t.drops.mu.Lock()
	suppressed := t.drops.n
	t.drops.mu.Unlock()
	if suppressed > 0 {
		text += fmt.Sprintf("\n(%d earlier notification(s) suppressed by the rate limit)", suppressed)
	}

	var err error
	switch t.cfg.Type {
	case TypeSlackWebhook:
		err = t.post(ctx, t.cfg.URL, nil, slackPayload(title, text, ""))
	case TypeSlackBot:
		err = t.slackAPI(ctx, "chat.postMessage", slackPayload(title, text, t.cfg.Channel))
	case TypeTeamsWebhook, TypeTeamsWorkflow:
		err = t.post(ctx, t.cfg.URL, nil, teamsPayload(title, text, d))
	}
	if err != nil {
		t.limiter.refund()
		return fmt.Errorf("target %s: %w", t.cfg.Name, err)
	}
	t.drops.mu.Lock()
	t.drops.n -= suppressed
	t.drops.mu.Unlock()
	t.seen.add(e.ID)
	return nil
}

func slackPayload(title, text, channel string) map[string]any {
	m := map[string]any{"text": "*" + slackEscape(title) + "*\n" + slackEscape(text), "unfurl_links": false}
	if channel != "" {
		m["channel"] = channel
	}
	return m
}

// slackEscape escapes the control characters of Slack's mrkdwn.
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// teamsPayload builds a message with an Adaptive Card, the format accepted
// by Teams incoming webhooks and the Workflows "post to a channel when a
// webhook request is received" template.
func teamsPayload(title, text string, d Data) map[string]any {
	facts := []map[string]string{{"title": "Event", "value": d.Event.Type}}
	if l := d.TenantLabel(); l != "" {
		facts = append(facts, map[string]string{"title": "Tenant", "value": l})
	}
	if d.Event.Actor != "" {
		facts = append(facts, map[string]string{"title": "Actor", "value": d.Event.Actor})
	}
	if !d.Event.Time.IsZero() {
		facts = append(facts, map[string]string{"title": "Time", "value": d.Event.Time.UTC().Format(time.RFC3339)})
	}
	card := map[string]any{
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"type":    "AdaptiveCard",
		"version": "1.4",
		"body": []any{
			map[string]any{"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Medium", "wrap": true},
			map[string]any{"type": "TextBlock", "text": text, "wrap": true},
			map[string]any{"type": "FactSet", "facts": facts},
		},
	}
	return map[string]any{
		"type": "message",
		"attachments": []any{map[string]any{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"contentUrl":  nil,
			"content":     card,
		}},
	}
}

// post sends a JSON payload and checks the response.
func (t *target) post(ctx context.Context, u string, header http.Header, payload any) error {
	_, err := t.do(ctx, u, header, payload)
	return err
}

func (t *target) do(ctx context.Context, u string, header http.Header, payload any) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", "tenarium-chat-notify/"+version)
	resp, err := t.p.client.Do(req)
	if err != nil {
		// The URL contains the webhook secret; report the host only.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("post to %s: %w", req.URL.Host, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate limited by %s (Retry-After %q)", req.URL.Host, resp.Header.Get("Retry-After"))
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("%s responded %s: %s", req.URL.Host, resp.Status, excerpt(raw))
	}
	// Legacy Teams connectors answer 200 with an error text instead of "1".
	if t.cfg.Type == TypeTeamsWebhook && resp.StatusCode == http.StatusOK {
		if s := strings.TrimSpace(string(raw)); s != "" && s != "1" && !strings.HasPrefix(s, "{") {
			return nil, fmt.Errorf("teams rejected the message: %s", excerpt(raw))
		}
	}
	return raw, nil
}

// slackAPI calls a Slack Web API method with the bot token. Slack reports
// errors as {"ok": false, "error": "..."} with status 200.
func (t *target) slackAPI(ctx context.Context, method string, payload any) error {
	if payload == nil {
		payload = map[string]any{}
	}
	raw, err := t.do(ctx, t.cfg.APIBase+"/"+method, http.Header{"Authorization": {"Bearer " + t.cfg.Token}}, payload)
	if err != nil {
		return err
	}
	var res struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return fmt.Errorf("slack %s: decode response: %w", method, err)
	}
	if !res.OK {
		return fmt.Errorf("slack %s: %s", method, res.Error)
	}
	return nil
}

func excerpt(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

// bucket is a token bucket refilled at perMinute tokens per minute.
type bucket struct {
	mu     sync.Mutex
	now    func() time.Time
	rate   float64 // tokens per second
	burst  float64
	tokens float64
	last   time.Time
}

func newBucket(perMinute, burst int, now func() time.Time) *bucket {
	return &bucket{now: now, rate: float64(perMinute) / 60, burst: float64(burst), tokens: float64(burst), last: now()}
}

func (b *bucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens = min(b.burst, b.tokens+el*b.rate)
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// refund returns a token taken for a message that could not be sent, so
// retries are not counted twice.
func (b *bucket) refund() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens = min(b.burst, b.tokens+1)
}

// seenSet remembers the last n posted event IDs.
type seenSet struct {
	mu   sync.Mutex
	ids  map[string]struct{}
	ring []string
	next int
}

func newSeenSet(n int) *seenSet {
	return &seenSet{ids: make(map[string]struct{}, n), ring: make([]string, n)}
}

func (s *seenSet) has(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.ids[id]
	return ok
}

func (s *seenSet) add(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.ids[id]; ok {
		return
	}
	if old := s.ring[s.next]; old != "" {
		delete(s.ids, old)
	}
	s.ring[s.next] = id
	s.ids[id] = struct{}{}
	s.next = (s.next + 1) % len(s.ring)
}
