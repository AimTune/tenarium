package siem

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// SplunkConfig configures the Splunk HTTP Event Collector sink.
type SplunkConfig struct {
	// URL is the HEC base URL, e.g. https://splunk.example.com:8088.
	URL string `json:"url"`
	// Token is the HEC token.
	Token string `json:"token"`
	// Index overrides the token's default index.
	Index string `json:"index"`
	// Sourcetype defaults to "tenarium:event".
	Sourcetype string `json:"sourcetype"`
	// Source defaults to "tenarium".
	Source string `json:"source"`
	// Host is the event host field; empty leaves it to Splunk.
	Host string `json:"host"`
	// Channel is sent as X-Splunk-Request-Channel, needed when the token
	// has indexer acknowledgement enabled.
	Channel string     `json:"channel"`
	TLS     *TLSConfig `json:"tls"`
}

type splunkSink struct {
	cfg    SplunkConfig
	base   string
	client *http.Client
}

func newSplunkSink(c SplunkConfig, timeout time.Duration) (*splunkSink, error) {
	if c.Token == "" {
		return nil, errors.New("token is required")
	}
	base, err := parseBase("url", c.URL)
	if err != nil {
		return nil, err
	}
	c.Sourcetype = cmp.Or(c.Sourcetype, "tenarium:event")
	c.Source = cmp.Or(c.Source, "tenarium")
	client, err := httpClient(timeout, c.TLS)
	if err != nil {
		return nil, err
	}
	return &splunkSink{cfg: c, base: base, client: client}, nil
}

// hecEvent is the HEC JSON event envelope.
type hecEvent struct {
	Time       float64           `json:"time"`
	Host       string            `json:"host,omitempty"`
	Source     string            `json:"source,omitempty"`
	Sourcetype string            `json:"sourcetype,omitempty"`
	Index      string            `json:"index,omitempty"`
	Event      Record            `json:"event"`
	Fields     map[string]string `json:"fields,omitempty"`
}

func (s *splunkSink) header() http.Header {
	h := http.Header{"Authorization": {"Splunk " + s.cfg.Token}, "Content-Type": {"application/json"}}
	if s.cfg.Channel != "" {
		h.Set("X-Splunk-Request-Channel", s.cfg.Channel)
	}
	return h
}

func (s *splunkSink) envelope(r Record) hecEvent {
	fields := make(map[string]string)
	for _, kv := range r.fields() {
		fields[kv[0]] = kv[1]
	}
	return hecEvent{
		Time:       float64(r.Time.UnixMilli()) / 1000,
		Host:       s.cfg.Host,
		Source:     s.cfg.Source,
		Sourcetype: s.cfg.Sourcetype,
		Index:      s.cfg.Index,
		Event:      r,
		Fields:     fields,
	}
}

func (s *splunkSink) send(ctx context.Context, r Record) error {
	body, err := json.Marshal(s.envelope(r))
	if err != nil {
		return err
	}
	raw, err := doRequest(ctx, s.client, http.MethodPost, s.base+"/services/collector/event", body, s.header())
	if err != nil {
		return fmt.Errorf("splunk: %w", err)
	}
	var res struct {
		Code *int   `json:"code"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &res) == nil && res.Code != nil && *res.Code != 0 {
		return fmt.Errorf("splunk: HEC code %d: %s", *res.Code, res.Text)
	}
	return nil
}

// health queries the HEC health endpoint.
func (s *splunkSink) health(ctx context.Context) error {
	_, err := doRequest(ctx, s.client, http.MethodGet, s.base+"/services/collector/health", nil, s.header())
	return err
}
