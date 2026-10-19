package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// cloudflareBackend talks to the Cloudflare API v4 with an API token.
type cloudflareBackend struct {
	baseURL string
	token   string
	zone    string
	client  *http.Client

	mu     sync.Mutex
	zoneID string
}

func newCloudflare(zone string, c *CloudflareConfig) *cloudflareBackend {
	return &cloudflareBackend{
		baseURL: c.BaseURL, token: c.APIToken, zone: zone, zoneID: c.ZoneID,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// cfRecord is a Cloudflare DNS record.
type cfRecord struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type,omitempty"`
	Name    string `json:"name,omitempty"`
	Content string `json:"content,omitempty"`
	TTL     int64  `json:"ttl,omitempty"`
	Proxied *bool  `json:"proxied,omitempty"`
	Comment string `json:"comment,omitempty"`
}

type cfEnvelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo *struct {
		Page       int `json:"page"`
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

// cfError is a failed Cloudflare API call.
type cfError struct {
	Method, Path string
	Status       int
	Messages     []string
}

func (e *cfError) Error() string {
	return fmt.Sprintf("cloudflare %s %s: HTTP %d: %s", e.Method, e.Path, e.Status, strings.Join(e.Messages, "; "))
}

// do calls the API and decodes the envelope's result into out (if not nil).
func (b *cloudflareBackend) do(ctx context.Context, method, path string, query url.Values, body, out any) (*cfEnvelope, error) {
	u := b.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+b.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloudflare %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, fmt.Errorf("cloudflare %s %s: %w", method, path, err)
	}
	var env cfEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, &cfError{Method: method, Path: path, Status: resp.StatusCode, Messages: []string{"invalid response: " + truncateText(string(raw), 200)}}
	}
	if resp.StatusCode >= 300 || !env.Success {
		e := &cfError{Method: method, Path: path, Status: resp.StatusCode}
		for _, m := range env.Errors {
			e.Messages = append(e.Messages, fmt.Sprintf("%d %s", m.Code, m.Message))
		}
		return nil, e
	}
	if out != nil {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return nil, fmt.Errorf("cloudflare %s %s: decode result: %w", method, path, err)
		}
	}
	return &env, nil
}

func truncateText(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// cloudflareZoneID returns the configured zone ID or looks it up by name
// (once).
func (b *cloudflareBackend) cloudflareZoneID(ctx context.Context) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.zoneID != "" {
		return b.zoneID, nil
	}
	var zones []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if _, err := b.do(ctx, http.MethodGet, "/zones", url.Values{"name": {b.zone}}, nil, &zones); err != nil {
		return "", fmt.Errorf("look up zone %s: %w", b.zone, err)
	}
	for _, z := range zones {
		if strings.EqualFold(z.Name, b.zone) {
			b.zoneID = z.ID
			return z.ID, nil
		}
	}
	return "", fmt.Errorf("cloudflare zone %s not found (or the token cannot read it)", b.zone)
}

func (b *cloudflareBackend) recordsPath(ctx context.Context) (string, error) {
	zid, err := b.cloudflareZoneID(ctx)
	if err != nil {
		return "", err
	}
	return "/zones/" + url.PathEscape(zid) + "/dns_records", nil
}

func (b *cloudflareBackend) lookup(ctx context.Context, name string) (map[string]*rrset, error) {
	path, err := b.recordsPath(ctx)
	if err != nil {
		return nil, err
	}
	sets := map[string]*rrset{}
	for page := 1; ; page++ {
		var recs []cfRecord
		q := url.Values{"name": {name}, "per_page": {"100"}, "page": {strconv.Itoa(page)}}
		env, err := b.do(ctx, http.MethodGet, path, q, nil, &recs)
		if err != nil {
			return nil, err
		}
		for _, r := range recs {
			if !strings.EqualFold(strings.TrimSuffix(r.Name, "."), name) {
				continue
			}
			s := sets[r.Type]
			if s == nil {
				s = &rrset{Name: name, Type: r.Type, TTL: r.TTL, Proxied: r.Proxied != nil && *r.Proxied}
				s.raw = []cfRecord(nil)
				sets[r.Type] = s
			}
			s.Values = append(s.Values, decodeCFContent(r.Type, r.Content))
			s.raw = append(s.raw.([]cfRecord), r)
		}
		if env.ResultInfo == nil || page >= env.ResultInfo.TotalPages {
			return sets, nil
		}
	}
}

func decodeCFContent(typ, v string) string {
	switch typ {
	case TypeTXT:
		return txtDecode(v)
	case TypeCNAME:
		return strings.TrimSuffix(strings.ToLower(v), ".")
	case TypeA, TypeAAAA:
		if n, err := normalizeValue(typ, v); err == nil {
			return n
		}
	}
	return v
}

func encodeCFContent(typ, v string) string {
	if typ == TypeTXT {
		return txtEncode(v)
	}
	return v
}

func proxiable(typ string) bool { return typ == TypeA || typ == TypeAAAA || typ == TypeCNAME }

// apply writes the markers first and then the records, so an interrupted
// run leaves names marked for the tenant and is retried safely.
func (b *cloudflareBackend) apply(ctx context.Context, tenantID string, markers, records []change) error {
	path, err := b.recordsPath(ctx)
	if err != nil {
		return err
	}
	comment := "managed by tenarium for tenant " + tenantID
	for _, c := range append(append([]change(nil), markers...), records...) {
		if err := b.converge(ctx, path, comment, c); err != nil {
			return err
		}
	}
	return nil
}

// converge makes the records of one name and type match c.want: matching
// records are kept (and patched when TTL or proxying differ), missing ones
// are created and surplus ones deleted afterwards.
func (b *cloudflareBackend) converge(ctx context.Context, path, comment string, c change) error {
	var existing []cfRecord
	if c.have != nil {
		existing, _ = c.have.raw.([]cfRecord)
	}
	used := make([]bool, len(existing))
	want := c.want
	for _, v := range want.Values {
		idx := -1
		for i, r := range existing {
			if !used[i] && decodeCFContent(r.Type, r.Content) == v {
				idx = i
				break
			}
		}
		rec := cfRecord{TTL: want.TTL, Comment: comment}
		if proxiable(want.Type) {
			rec.Proxied = &want.Proxied
		}
		if idx >= 0 {
			used[idx] = true
			r := existing[idx]
			proxied := r.Proxied != nil && *r.Proxied
			if r.TTL == want.TTL && proxied == want.Proxied {
				continue
			}
			if _, err := b.do(ctx, http.MethodPatch, path+"/"+url.PathEscape(r.ID), nil, rec, nil); err != nil {
				return err
			}
			continue
		}
		rec.Type, rec.Name, rec.Content = want.Type, want.Name, encodeCFContent(want.Type, v)
		if _, err := b.do(ctx, http.MethodPost, path, nil, rec, nil); err != nil {
			return err
		}
	}
	for i, r := range existing {
		if !used[i] {
			if err := b.deleteRecord(ctx, path, r.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *cloudflareBackend) deleteRecord(ctx context.Context, path, id string) error {
	_, err := b.do(ctx, http.MethodDelete, path+"/"+url.PathEscape(id), nil, nil, nil)
	var ce *cfError
	if errors.As(err, &ce) && ce.Status == http.StatusNotFound {
		return nil // Already gone.
	}
	return err
}

// remove deletes the records and then the markers.
func (b *cloudflareBackend) remove(ctx context.Context, records, markers []*rrset) error {
	path, err := b.recordsPath(ctx)
	if err != nil {
		return err
	}
	for _, s := range append(append([]*rrset(nil), records...), markers...) {
		recs, _ := s.raw.([]cfRecord)
		for _, r := range recs {
			if err := b.deleteRecord(ctx, path, r.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *cloudflareBackend) health(ctx context.Context) error {
	zid, err := b.cloudflareZoneID(ctx)
	if err != nil {
		return err
	}
	var z struct {
		Name string `json:"name"`
	}
	if _, err := b.do(ctx, http.MethodGet, "/zones/"+url.PathEscape(zid), nil, nil, &z); err != nil {
		return err
	}
	if !strings.EqualFold(z.Name, b.zone) {
		return fmt.Errorf("cloudflare zone %s is %s, not %s", zid, z.Name, b.zone)
	}
	return nil
}
