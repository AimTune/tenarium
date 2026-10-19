package client

import (
	"context"
	"fmt"
	"iter"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// EventsService reads the event log (/v1/events).
type EventsService struct{ c *Client }

// EventListOptions filter and paginate the event log.
type EventListOptions struct {
	// After is an exclusive sequence number cursor.
	After int64
	// TenantID keeps only events of this tenant (ID, not slug).
	TenantID string
	// Type is a glob on the event type, e.g. "tenant.*".
	Type string
	// Limit is the number of log entries scanned per page (1-1000).
	Limit int
}

// List returns one page of events. Filters are applied per page, so a page
// may hold fewer items than Limit (even none) while Next is set.
func (s *EventsService) List(ctx context.Context, o EventListOptions, opts ...CallOption) (Page[sdk.Event], error) {
	q := url.Values{}
	if o.After > 0 {
		q.Set("after", strconv.FormatInt(o.After, 10))
	}
	setStr(q, "tenant_id", o.TenantID)
	setStr(q, "type", o.Type)
	setLimit(q, o.Limit)
	var p Page[sdk.Event]
	err := s.c.do(ctx, http.MethodGet, "/v1/events", q, nil, &p, opts...)
	return p, err
}

// All iterates over the event log from o.After up to the current end.
func (s *EventsService) All(ctx context.Context, o EventListOptions, opts ...CallOption) iter.Seq2[sdk.Event, error] {
	return paginate(ctx, formatSeq(o.After), func(ctx context.Context, after string) (Page[sdk.Event], error) {
		var err error
		if o.After, err = parseSeq(after); err != nil {
			return Page[sdk.Event]{}, err
		}
		return s.List(ctx, o, opts...)
	})
}

// TailOption configures Tail.
type TailOption func(*tailConfig)

type tailConfig struct {
	interval time.Duration
	list     EventListOptions
}

// TailInterval sets how often Tail polls once it has caught up (default 1s).
func TailInterval(d time.Duration) TailOption { return func(c *tailConfig) { c.interval = d } }

// TailTenant keeps only events of one tenant (ID).
func TailTenant(id string) TailOption { return func(c *tailConfig) { c.list.TenantID = id } }

// TailType keeps only events whose type matches a glob such as "tenant.*".
func TailType(glob string) TailOption { return func(c *tailConfig) { c.list.Type = glob } }

// Tail calls fn for every event after sequence number after, in order, then
// keeps polling for new events until ctx is done or fn returns an error.
// It returns fn's error, an API error, or ctx.Err().
func (s *EventsService) Tail(ctx context.Context, after int64, fn func(sdk.Event) error, opts ...TailOption) error {
	cfg := tailConfig{interval: time.Second}
	for _, o := range opts {
		o(&cfg)
	}
	cfg.list.Limit = 500
	for {
		cfg.list.After = after
		p, err := s.List(ctx, cfg.list)
		if err != nil {
			return err
		}
		for _, e := range p.Items {
			if err := fn(e); err != nil {
				return err
			}
			after = e.Seq
		}
		if p.Next != "" {
			// More history to read; Next may skip filtered-out events.
			if after, err = parseSeq(p.Next); err != nil {
				return err
			}
			continue
		}
		if err := sleep(ctx, cfg.interval); err != nil {
			return err
		}
	}
}

// LastSeq returns the sequence number of the newest event (0 if the log is
// empty), e.g. to Tail only new events.
func (s *EventsService) LastSeq(ctx context.Context) (int64, error) {
	var last int64
	for {
		p, err := s.List(ctx, EventListOptions{After: last, Limit: 1000})
		if err != nil {
			return 0, err
		}
		if len(p.Items) > 0 {
			last = p.Items[len(p.Items)-1].Seq
		}
		if p.Next == "" {
			return last, nil
		}
		if last, err = parseSeq(p.Next); err != nil {
			return 0, err
		}
	}
}

func formatSeq(n int64) string {
	if n <= 0 {
		return ""
	}
	return strconv.FormatInt(n, 10)
}

func parseSeq(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("tenarium: invalid event cursor %q", s)
	}
	return n, nil
}

// DeadLettersService manages events that subscriptions gave up on.
type DeadLettersService struct{ c *Client }

// DeadLetter is an event a subscription failed to deliver.
type DeadLetter struct {
	ID           string    `json:"id"`
	Subscription string    `json:"subscription"`
	Event        sdk.Event `json:"event"`
	Error        string    `json:"error"`
	Attempts     int       `json:"attempts"`
	FailedAt     time.Time `json:"failed_at"`
}

// DeadLetterList holds dead letters and the names of all subscriptions.
type DeadLetterList struct {
	Items         []DeadLetter `json:"items"`
	Subscriptions []string     `json:"subscriptions"`
}

// List returns dead letters, optionally only for one subscription
// ("plugin-instance/name").
func (s *DeadLettersService) List(ctx context.Context, subscription string, opts ...CallOption) (DeadLetterList, error) {
	q := url.Values{}
	setStr(q, "subscription", subscription)
	var l DeadLetterList
	err := s.c.do(ctx, http.MethodGet, "/v1/dead-letters", q, nil, &l, opts...)
	return l, err
}

// Get returns one dead letter.
func (s *DeadLettersService) Get(ctx context.Context, id string, opts ...CallOption) (DeadLetter, error) {
	var d DeadLetter
	if err := checkIDs(id); err != nil {
		return d, err
	}
	err := s.c.do(ctx, http.MethodGet, "/v1/dead-letters/"+esc(id), nil, nil, &d, opts...)
	return d, err
}

// Replay redelivers a dead letter synchronously; on success it is removed.
// A failed delivery returns a 502 error with code "replay_failed".
func (s *DeadLettersService) Replay(ctx context.Context, id string, opts ...CallOption) error {
	if err := checkIDs(id); err != nil {
		return err
	}
	err := s.c.do(ctx, http.MethodPost, "/v1/dead-letters/"+esc(id)+"/replay", nil, nil, nil, opts...)
	return err
}

// Discard deletes a dead letter without redelivering it.
func (s *DeadLettersService) Discard(ctx context.Context, id string, opts ...CallOption) error {
	if err := checkIDs(id); err != nil {
		return err
	}
	err := s.c.do(ctx, http.MethodDelete, "/v1/dead-letters/"+esc(id), nil, nil, nil, opts...)
	return err
}

// PluginsService lists loaded plugins.
type PluginsService struct{ c *Client }

// PluginScope limits a plugin instance to some tenants.
type PluginScope struct {
	Plans   []string          `json:"plans,omitempty"`
	Labels  map[string]string `json:"labels,omitempty"`
	Tenants []string          `json:"tenants,omitempty"`
}

// PluginInfo describes a loaded plugin instance and what it registered.
type PluginInfo struct {
	Name           string       `json:"name"`
	Manifest       sdk.Manifest `json:"manifest"`
	Scope          *PluginScope `json:"scope,omitempty"`
	Subscriptions  []string     `json:"subscriptions,omitempty"`
	Hooks          []string     `json:"hooks,omitempty"`
	Provisioners   []string     `json:"provisioners,omitempty"`
	Routes         []string     `json:"routes,omitempty"`
	Authenticators []string     `json:"authenticators,omitempty"`
	Authorizers    []string     `json:"authorizers,omitempty"`
	UserDirectory  string       `json:"user_directory,omitempty"`
	Mailer         string       `json:"mailer,omitempty"`
}

// PluginList holds the loaded instances and the plugin IDs compiled in.
type PluginList struct {
	Items     []PluginInfo `json:"items"`
	Available []string     `json:"available"`
}

// List returns loaded plugin instances.
func (s *PluginsService) List(ctx context.Context, opts ...CallOption) (PluginList, error) {
	var l PluginList
	err := s.c.do(ctx, http.MethodGet, "/v1/plugins", nil, nil, &l, opts...)
	return l, err
}

// --- self-service ------------------------------------------------------------------

// Me returns the authenticated caller.
func (c *Client) Me(ctx context.Context, opts ...CallOption) (sdk.Principal, error) {
	var p sdk.Principal
	err := c.do(ctx, http.MethodGet, "/v1/me", nil, nil, &p, opts...)
	return p, err
}

// MyMemberships lists the calling user's tenant memberships.
func (c *Client) MyMemberships(ctx context.Context, opts ...CallOption) ([]sdk.Member, error) {
	var out struct {
		Items []sdk.Member `json:"items"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/me/memberships", nil, nil, &out, opts...)
	return out.Items, err
}

// ChangeMyPassword changes the calling user's password.
func (c *Client) ChangeMyPassword(ctx context.Context, current, next string, opts ...CallOption) error {
	body := map[string]string{"current_password": current, "new_password": next}
	err := c.do(ctx, http.MethodPost, "/v1/me/password", nil, body, nil, opts...)
	return err
}
