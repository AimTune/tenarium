package archive

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// Replay defaults.
const (
	DefaultReplayTimeout   = 10 * time.Second
	DefaultReplayMaxEvents = 100000
	replayAttempts         = 3
)

// replayer sends archived events to HTTP endpoints chosen per request.
type replayer struct {
	cfg     ReplayConfig
	client  *http.Client
	backoff time.Duration
}

func newReplayer(c ReplayConfig) (*replayer, error) {
	timeout, err := parseDuration("replay.timeout", c.Timeout, DefaultReplayTimeout)
	if err != nil {
		return nil, err
	}
	if c.MaxEvents == 0 {
		c.MaxEvents = DefaultReplayMaxEvents
	} else if c.MaxEvents < 0 {
		return nil, fmt.Errorf("replay.max_events must be positive, got %d", c.MaxEvents)
	}
	return &replayer{cfg: c, client: guardedClient(timeout, c.AllowPrivateNetworks), backoff: 500 * time.Millisecond}, nil
}

// guardedClient returns a client that refuses internal addresses after DNS
// resolution (so DNS rebinding cannot bypass it), ignores proxies and does
// not follow redirects: the same policy as Tenarium's webhook sender.
func guardedClient(timeout time.Duration, allowPrivate bool) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if !allowPrivate {
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip, err := netip.ParseAddr(host)
			if err != nil {
				return err
			}
			return checkAddr(ip)
		}
	}
	transport := &http.Transport{
		Proxy:                 nil, // a proxy would bypass the address check
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: timeout,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
	}
	return &http.Client{
		Transport:     transport,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

var (
	cgnat   = netip.MustParsePrefix("100.64.0.0/10")
	thisNet = netip.MustParsePrefix("0.0.0.0/8")
)

// checkAddr refuses loopback, private, link-local (cloud metadata), CGNAT,
// multicast and unspecified addresses.
func checkAddr(ip netip.Addr) error {
	ip = ip.WithZone("").Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() ||
		cgnat.Contains(ip) || thisNet.Contains(ip) {
		return fmt.Errorf("address %s is not allowed", ip)
	}
	return nil
}

// checkHost rejects literal internal addresses and local names up front;
// resolved addresses are checked again on every connection.
func checkHost(host string) error {
	if ip, err := netip.ParseAddr(host); err == nil {
		return checkAddr(ip)
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return errors.New("local hosts are not allowed")
	}
	return nil
}

func (rp *replayer) validateURL(raw string) error {
	u, err := url.Parse(raw)
	switch {
	case err != nil || u.Host == "" || u.User != nil:
		return errors.New("url must be an absolute URL without credentials")
	case u.Scheme != "https" && !(u.Scheme == "http" && rp.cfg.AllowHTTP):
		return errors.New("url must use https")
	case len(raw) > 2048:
		return errors.New("url is too long")
	}
	if !rp.cfg.AllowPrivateNetworks {
		if err := checkHost(u.Hostname()); err != nil {
			return fmt.Errorf("url: %w", err)
		}
	}
	return nil
}

// secretBytes decodes a Standard Webhooks secret ("whsec_" + base64) like
// Tenarium's webhooks do; other strings are used as raw bytes.
func secretBytes(s string) []byte {
	if b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, "whsec_")); err == nil {
		return b
	}
	return []byte(s)
}

// Sign computes the Standard Webhooks signature (base64 HMAC-SHA256 over
// "id.timestamp.body"), as Tenarium webhooks do.
func Sign(secret, id, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, secretBytes(secret))
	mac.Write([]byte(id + "." + timestamp + "."))
	mac.Write(body)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// send posts e as a CloudEvent, retrying a few times.
func (rp *replayer) send(ctx context.Context, target, secret string, e sdk.Event, now func() time.Time) error {
	body, err := json.Marshal(e.CloudEvent())
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := range replayAttempts {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(rp.backoff << (attempt - 1)):
			}
		}
		if lastErr = rp.post(ctx, target, secret, e.ID, body, now); lastErr == nil {
			return nil
		}
	}
	return lastErr
}

func (rp *replayer) post(ctx context.Context, target, secret, id string, body []byte, now func() time.Time) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	ts := strconv.FormatInt(now().Unix(), 10)
	req.Header.Set("Content-Type", "application/cloudevents+json")
	req.Header.Set("User-Agent", "tenarium-archive/"+version)
	req.Header.Set("webhook-id", id)
	req.Header.Set("webhook-timestamp", ts)
	req.Header.Set("webhook-signature", "v1,"+Sign(secret, id, ts, body))
	resp, err := rp.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return errors.New("endpoint responded " + resp.Status)
	}
	return nil
}

// ReplayRequest is the body of POST /replay.
type ReplayRequest struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
	// Type is a glob pattern (or comma-separated patterns) on event types.
	Type     string `json:"type"`
	TenantID string `json:"tenant_id"`
	// URL is the target endpoint; Secret signs the requests.
	URL    string `json:"url"`
	Secret string `json:"secret"`
	// Limit caps the events sent (at most replay.max_events).
	Limit int `json:"limit"`
}

// ReplayResult is the response of POST /replay.
type ReplayResult struct {
	// Matched counts the archived events selected so far, Sent the ones
	// the endpoint accepted and Failed the one it did not (replay stops at
	// the first failure).
	Matched int `json:"matched"`
	Sent    int `json:"sent"`
	Failed  int `json:"failed"`
	// LastSeq is the sequence number of the last event sent; resume a
	// stopped replay from the time of the next one.
	LastSeq int64 `json:"last_seq,omitempty"`
	// Truncated is true when the limit stopped the replay.
	Truncated bool   `json:"truncated,omitempty"`
	Error     string `json:"error,omitempty"`
}

// serveReplay re-sends archived events to an HTTP endpoint (POST /replay).
func (p *Plugin) serveReplay(w http.ResponseWriter, r *http.Request) {
	if !p.authorize(r, sdk.ActionEventsRead, sdk.ActionDeadLettersReplay) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var in ReplayRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		http.Error(w, "invalid body: "+err.Error(), http.StatusBadRequest)
		return
	}
	q := Query{From: in.From, To: in.To, TenantID: in.TenantID, Limit: in.Limit}
	if q.To.IsZero() {
		q.To = p.now()
	}
	for t := range strings.SplitSeq(in.Type, ",") {
		if t = strings.TrimSpace(t); t != "" {
			q.Types = append(q.Types, t)
		}
	}
	if maxEvents := p.replay.cfg.MaxEvents; q.Limit == 0 || q.Limit > maxEvents {
		q.Limit = maxEvents
	}
	err := q.validate()
	if err == nil {
		err = p.replay.validateURL(in.URL)
	}
	if err == nil && in.Secret == "" {
		err = errors.New("secret is required")
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	segs, err := p.segments(r.Context(), q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	var res ReplayResult
	var sendErr error
	err = p.scan(r.Context(), q, segs, func(e sdk.Event) (bool, error) {
		res.Matched++
		if sendErr = p.replay.send(r.Context(), in.URL, in.Secret, e, p.now); sendErr != nil {
			res.Failed++
			return false, nil
		}
		res.Sent++
		res.LastSeq = e.Seq
		return true, nil
	})
	status := http.StatusOK
	switch {
	case err != nil:
		res.Error, status = err.Error(), http.StatusBadGateway
	case sendErr != nil:
		res.Error, status = "event "+strconv.Itoa(res.Matched)+": "+sendErr.Error(), http.StatusBadGateway
	case res.Matched == q.Limit:
		res.Truncated = true
	}
	p.log.Info("replayed archived events", "host", hostOf(in.URL), "matched", res.Matched, "sent", res.Sent, "failed", res.Failed)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(res)
}

// hostOf returns the host of a URL for logs (the path or query may carry
// secrets).
func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Host
	}
	return ""
}
