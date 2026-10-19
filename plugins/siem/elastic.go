package siem

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ElasticConfig configures the Elasticsearch / OpenSearch bulk sink.
type ElasticConfig struct {
	// URL is the cluster URL, e.g. https://es.example.com:9200.
	URL string `json:"url"`
	// Username and Password use HTTP basic authentication.
	Username string `json:"username"`
	Password string `json:"password"`
	// APIKey is an Elasticsearch API key (the base64 "id:key" form), sent
	// as "Authorization: ApiKey <key>".
	APIKey string `json:"api_key"`
	// IndexPrefix defaults to "tenarium-events".
	IndexPrefix string `json:"index_prefix"`
	// IndexDateFormat is a Go time layout appended to the prefix with "-"
	// using the event time in UTC (default "2006.01.02", one index per
	// day). Set it to "none" to write to the prefix only, e.g. a data
	// stream.
	IndexDateFormat string `json:"index_date_format"`
	// Pipeline is an optional ingest pipeline.
	Pipeline string     `json:"pipeline"`
	TLS      *TLSConfig `json:"tls"`
}

type elasticSink struct {
	cfg    ElasticConfig
	base   string
	client *http.Client
}

func newElasticSink(c ElasticConfig, timeout time.Duration) (*elasticSink, error) {
	base, err := parseBase("url", c.URL)
	if err != nil {
		return nil, err
	}
	if c.APIKey != "" && c.Username != "" {
		return nil, errors.New("set either api_key or username/password, not both")
	}
	if c.Password != "" && c.Username == "" {
		return nil, errors.New("password requires username")
	}
	c.IndexPrefix = cmp.Or(c.IndexPrefix, "tenarium-events")
	if !validIndexName(c.IndexPrefix) {
		return nil, fmt.Errorf("index_prefix %q is not a valid index name (lowercase letters, digits, '.', '_', '-')", c.IndexPrefix)
	}
	c.IndexDateFormat = cmp.Or(c.IndexDateFormat, "2006.01.02")
	if c.IndexDateFormat != "none" {
		probe := time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC).Format(c.IndexDateFormat)
		if probe == c.IndexDateFormat || !validIndexName("x"+probe) {
			return nil, fmt.Errorf("index_date_format %q is not a Go time layout producing a valid index name", c.IndexDateFormat)
		}
	}
	client, err := httpClient(timeout, c.TLS)
	if err != nil {
		return nil, err
	}
	return &elasticSink{cfg: c, base: base, client: client}, nil
}

func validIndexName(s string) bool {
	if s == "" || s[0] == '-' || s[0] == '_' || s[0] == '.' || len(s) > 255 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func (s *elasticSink) index(t time.Time) string {
	if s.cfg.IndexDateFormat == "none" {
		return s.cfg.IndexPrefix
	}
	return s.cfg.IndexPrefix + "-" + t.UTC().Format(s.cfg.IndexDateFormat)
}

func (s *elasticSink) header() http.Header {
	h := http.Header{"Content-Type": {"application/x-ndjson"}}
	switch {
	case s.cfg.APIKey != "":
		h.Set("Authorization", "ApiKey "+s.cfg.APIKey)
	case s.cfg.Username != "":
		r := &http.Request{Header: http.Header{}}
		r.SetBasicAuth(s.cfg.Username, s.cfg.Password)
		h.Set("Authorization", r.Header.Get("Authorization"))
	}
	return h
}

// document maps a record onto Elastic Common Schema fields, keeping the
// full record under "tenarium".
func document(r Record) map[string]any {
	ev := map[string]any{
		"id": r.ID, "action": r.Type, "kind": "event", "category": []string{"iam"},
		"dataset": "tenarium.audit", "provider": "tenarium", "sequence": r.Seq, "outcome": r.Outcome,
	}
	doc := map[string]any{
		"@timestamp": r.Time.Format(time.RFC3339Nano),
		"event":      ev,
		"message":    message(r),
		"tenarium":   r,
	}
	if r.TenantID != "" {
		org := map[string]any{"id": r.TenantID}
		if r.TenantName != "" {
			org["name"] = r.TenantName
		}
		doc["organization"] = org
	}
	if r.ActorID != "" {
		doc["user"] = map[string]any{"id": r.ActorID, "domain": r.ActorType}
	} else if r.Actor != "" {
		doc["user"] = map[string]any{"name": r.Actor}
	}
	return doc
}

// message is a short human-readable summary of a record.
func message(r Record) string {
	var b strings.Builder
	b.WriteString(r.Type)
	if t := cmp.Or(r.TenantSlug, r.TenantID); t != "" {
		b.WriteString(" tenant=" + t)
	}
	if r.Actor != "" {
		b.WriteString(" actor=" + r.Actor)
	}
	return b.String()
}

func (s *elasticSink) send(ctx context.Context, r Record) error {
	var body bytes.Buffer
	meta := map[string]any{"create": map[string]string{"_index": s.index(r.Time), "_id": r.ID}}
	enc := json.NewEncoder(&body) // Encode appends the newline NDJSON needs
	if err := enc.Encode(meta); err != nil {
		return err
	}
	if err := enc.Encode(document(r)); err != nil {
		return err
	}
	u := s.base + "/_bulk"
	if s.cfg.Pipeline != "" {
		u += "?pipeline=" + url.QueryEscape(s.cfg.Pipeline)
	}
	raw, err := doRequest(ctx, s.client, http.MethodPost, u, body.Bytes(), s.header())
	if err != nil {
		return fmt.Errorf("elastic: %w", err)
	}
	return bulkError(raw)
}

// bulkError inspects a _bulk response. Items that failed with 409 (a
// document with that _id exists: the event was indexed before) count as
// success.
func bulkError(raw []byte) error {
	var res struct {
		Errors bool `json:"errors"`
		Items  []map[string]struct {
			Status int `json:"status"`
			Error  *struct {
				Type   string `json:"type"`
				Reason string `json:"reason"`
			} `json:"error"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return fmt.Errorf("elastic: decode bulk response: %w", err)
	}
	if !res.Errors {
		return nil
	}
	var errs []error
	for _, item := range res.Items {
		for op, st := range item {
			if st.Error == nil || st.Status == http.StatusConflict {
				continue
			}
			errs = append(errs, fmt.Errorf("elastic: %s failed with %d: %s: %s", op, st.Status, st.Error.Type, st.Error.Reason))
		}
	}
	return errors.Join(errs...)
}

// health fetches the cluster info, which checks reachability and
// credentials.
func (s *elasticSink) health(ctx context.Context) error {
	h := s.header()
	h.Del("Content-Type")
	_, err := doRequest(ctx, s.client, http.MethodGet, s.base+"/", nil, h)
	return err
}
