// Package archive copies every event to object storage (Amazon S3 and
// S3-compatible stores, Google Cloud Storage, Azure Blob Storage or a local
// directory) for long-term retention, after the event log in the database
// has been pruned by events.retention. Archived events can be read back and
// replayed to an HTTP endpoint by time range.
//
// # Layout
//
// Events are stored as NDJSON (one sdk.Event JSON object per line, gzip
// compressed by default) in objects keyed by the UTC hour of the events
// they hold:
//
//	{prefix}/{yyyy}/{mm}/{dd}/{hh}/{firstSeq}-{lastSeq}.ndjson.gz
//
// Sequence numbers are zero-padded to 20 digits so keys sort by position in
// the event log. Every event of an object falls into the object's hour, so
// a time-range read only lists the days and hours it covers.
//
// # Delivery guarantees
//
// The dispatcher hands a subscription one event at a time and moves its
// durable cursor past an event as soon as the handler returns nil. An event
// that is only buffered in memory when the handler returns would be lost if
// the process stopped before the next flush. The plugin therefore
// acknowledges an event only after an object containing it has been
// written: each event is appended to the open batch, the whole batch is
// written as {firstSeq}-{lastSeq}, and the object of the previous, shorter
// batch is deleted. Storage holds one object per batch once it is closed
// (batch_size events, flush_interval of age, or a new hour), at the price of
// one write and one delete per event while it is open.
//
// Delivery is at least once. A retried event rewrites the same object
// name; a batch whose superseded object could not be deleted, or which was
// cut short by a crash or a lease moving to another replica, leaves
// overlapping objects. Readers merge objects in sequence order and drop
// duplicate event IDs, so duplicates are never visible.
//
// # Routes
//
// GET /v1/plugins/{instance}/events?from=&to=&type=&tenant_id=&limit=
// streams archived events as NDJSON in sequence order. POST
// /v1/plugins/{instance}/replay re-sends archived events to an HTTP
// endpoint, signed like Tenarium webhooks (Standard Webhooks). Both routes
// are restricted to platform-wide callers.
package archive

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

const version = "0.1.0"

func init() {
	sdk.Register("archive", func() sdk.Plugin { return &Plugin{} })
}

// Backends.
const (
	BackendS3    = "s3"
	BackendGCS   = "gcs"
	BackendAzure = "azure"
	BackendFile  = "file"
)

// Compression modes.
const (
	CompressionGzip = "gzip"
	CompressionNone = "none"
)

// Defaults.
const (
	DefaultPrefix        = "events"
	DefaultBatchSize     = 100
	MaxBatchSize         = 1000
	DefaultFlushInterval = time.Minute
	DefaultTimeout       = 30 * time.Second
	DefaultMaxAttempts   = 30
)

// Config is the plugin configuration.
type Config struct {
	// Backend is s3, gcs, azure or file; the block of the same name holds
	// its settings.
	Backend string `json:"backend"`
	// Prefix is prepended to every object key (default "events").
	Prefix string `json:"prefix"`
	// Events are glob patterns (path.Match) of event types to archive.
	// Empty means all.
	Events []string `json:"events"`
	// BatchSize is the maximum number of events per object (default 100).
	BatchSize int `json:"batch_size"`
	// FlushInterval closes a batch once it is this old, e.g. "1m"
	// (default), so a quiet period does not keep one object open.
	FlushInterval string `json:"flush_interval"`
	// Compression is "gzip" (default) or "none".
	Compression string `json:"compression"`
	// Timeout bounds one storage request, e.g. "30s" (default).
	Timeout string `json:"timeout"`
	// MaxAttempts before an event is dead-lettered (default 30, with
	// backoff up to 2 minutes: about an hour of storage outage).
	MaxAttempts int `json:"max_attempts"`

	S3    *S3Config    `json:"s3"`
	GCS   *GCSConfig   `json:"gcs"`
	Azure *AzureConfig `json:"azure"`
	File  *FileConfig  `json:"file"`

	Replay ReplayConfig `json:"replay"`
}

// S3Config configures the s3 backend (Amazon S3 or an S3-compatible store).
type S3Config struct {
	// Endpoint is host[:port] of the S3 API, without scheme.
	Endpoint  string `json:"endpoint"`
	Region    string `json:"region"`
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
	// Secure selects HTTPS (default true).
	Secure *bool  `json:"secure"`
	Bucket string `json:"bucket"`
}

// GCSConfig configures the gcs backend.
type GCSConfig struct {
	// Endpoint is the GCS base URL (default https://storage.googleapis.com).
	Endpoint string `json:"endpoint"`
	// Anonymous sends unauthenticated requests (emulators only).
	Anonymous bool `json:"anonymous"`
	// CredentialsFile and CredentialsJSON hold a Google credentials JSON.
	// Default: application default credentials.
	CredentialsFile string `json:"credentials_file"`
	CredentialsJSON string `json:"credentials_json"`
	Bucket          string `json:"bucket"`
}

// AzureConfig configures the azure backend.
type AzureConfig struct {
	// ConnectionString is an Azure Storage connection string; the
	// alternative is AccountName, AccountKey and optionally Endpoint
	// (default https://<account>.blob.core.windows.net).
	ConnectionString string `json:"connection_string"`
	AccountName      string `json:"account_name"`
	AccountKey       string `json:"account_key"`
	Endpoint         string `json:"endpoint"`
	Container        string `json:"container"`
}

// FileConfig configures the file backend.
type FileConfig struct {
	// Dir is the root directory; it is created if missing.
	Dir string `json:"dir"`
}

// ReplayConfig configures POST /replay.
type ReplayConfig struct {
	// Timeout per request to the target, e.g. "10s" (default).
	Timeout string `json:"timeout"`
	// MaxEvents caps the events sent by one replay request (default
	// 100000).
	MaxEvents int `json:"max_events"`
	// AllowHTTP permits http:// targets (development only).
	AllowHTTP bool `json:"allow_http"`
	// AllowPrivateNetworks permits loopback and private targets
	// (development only).
	AllowPrivateNetworks bool `json:"allow_private_networks"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["backend"],
  "properties": {
    "backend": {"enum": ["s3", "gcs", "azure", "file"]},
    "prefix": {"type": "string", "pattern": "^[A-Za-z0-9._/-]*$"},
    "events": {"type": "array", "items": {"type": "string", "minLength": 1}},
    "batch_size": {"type": "integer", "minimum": 1, "maximum": 1000},
    "flush_interval": {"type": "string"},
    "compression": {"enum": ["gzip", "none"]},
    "timeout": {"type": "string"},
    "max_attempts": {"type": "integer", "minimum": 1},
    "s3": {
      "type": "object",
      "additionalProperties": false,
      "required": ["endpoint", "access_key", "secret_key", "bucket"],
      "properties": {
        "endpoint": {"type": "string", "minLength": 1},
        "region": {"type": "string"},
        "access_key": {"type": "string", "minLength": 1},
        "secret_key": {"type": "string", "minLength": 1},
        "secure": {"type": "boolean"},
        "bucket": {"type": "string", "minLength": 3}
      }
    },
    "gcs": {
      "type": "object",
      "additionalProperties": false,
      "required": ["bucket"],
      "properties": {
        "endpoint": {"type": "string", "pattern": "^https?://"},
        "anonymous": {"type": "boolean"},
        "credentials_file": {"type": "string", "minLength": 1},
        "credentials_json": {"type": "string", "minLength": 1},
        "bucket": {"type": "string", "minLength": 3}
      },
      "not": {"required": ["credentials_file", "credentials_json"]}
    },
    "azure": {
      "type": "object",
      "additionalProperties": false,
      "required": ["container"],
      "properties": {
        "connection_string": {"type": "string", "minLength": 1},
        "account_name": {"type": "string", "pattern": "^[a-z0-9]{3,24}$"},
        "account_key": {"type": "string", "minLength": 1},
        "endpoint": {"type": "string", "pattern": "^https?://"},
        "container": {"type": "string", "pattern": "^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$"}
      },
      "oneOf": [
        {"required": ["connection_string"], "not": {"anyOf": [{"required": ["account_name"]}, {"required": ["account_key"]}, {"required": ["endpoint"]}]}},
        {"required": ["account_name", "account_key"], "not": {"required": ["connection_string"]}}
      ]
    },
    "file": {
      "type": "object",
      "additionalProperties": false,
      "required": ["dir"],
      "properties": {"dir": {"type": "string", "minLength": 1}}
    },
    "replay": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "timeout": {"type": "string"},
        "max_events": {"type": "integer", "minimum": 1},
        "allow_http": {"type": "boolean"},
        "allow_private_networks": {"type": "boolean"}
      }
    }
  },
  "allOf": [
    {"if": {"properties": {"backend": {"const": "s3"}}}, "then": {"required": ["s3"]}},
    {"if": {"properties": {"backend": {"const": "gcs"}}}, "then": {"required": ["gcs"]}},
    {"if": {"properties": {"backend": {"const": "azure"}}}, "then": {"required": ["azure"]}},
    {"if": {"properties": {"backend": {"const": "file"}}}, "then": {"required": ["file"]}}
  ]
}`)

// Plugin is the event archive plugin.
type Plugin struct {
	cfg           Config
	flushInterval time.Duration
	timeout       time.Duration
	store         objectStore
	host          sdk.Host
	log           *slog.Logger
	now           func() time.Time
	replay        *replayer

	mu  sync.Mutex
	cur batch
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "archive",
		Name:         "Event archive",
		Version:      version,
		Description:  "Archives events to S3, GCS, Azure Blob Storage or a directory, and reads back or replays them by time range.",
		ConfigSchema: configSchema,
	}
}

func (p *Plugin) Init(ctx context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	if err := p.applyConfig(); err != nil {
		return err
	}
	if p.now == nil {
		p.now = time.Now
	}
	p.host = r.Host()
	p.log = r.Logger()
	if p.store == nil {
		s, err := p.newStore(ctx)
		if err != nil {
			return err
		}
		p.store = s
	}
	rp, err := newReplayer(p.cfg.Replay)
	if err != nil {
		return err
	}
	p.replay = rp

	r.Subscribe("archive", sdk.EventFilter{Types: p.cfg.Events}, p.handle,
		sdk.WithMaxAttempts(p.cfg.MaxAttempts), sdk.WithBackoff(500*time.Millisecond, 2*time.Minute))
	r.Route("GET /events", http.HandlerFunc(p.serveEvents))
	r.Route("POST /replay", http.HandlerFunc(p.serveReplay))
	return nil
}

var prefixRE = regexp.MustCompile(`^[A-Za-z0-9._/-]*$`)

// applyConfig checks and defaults the configuration.
func (p *Plugin) applyConfig() error {
	c := &p.cfg
	blocks := map[string]bool{BackendS3: c.S3 != nil, BackendGCS: c.GCS != nil, BackendAzure: c.Azure != nil, BackendFile: c.File != nil}
	if _, ok := blocks[c.Backend]; !ok {
		return fmt.Errorf("backend must be s3, gcs, azure or file, got %q", c.Backend)
	}
	for name, set := range blocks {
		if name == c.Backend && !set {
			return fmt.Errorf("backend %s needs a %s block", name, name)
		}
		if name != c.Backend && set {
			return fmt.Errorf("%s block is set but backend is %s", name, c.Backend)
		}
	}
	if c.Prefix == "" {
		c.Prefix = DefaultPrefix
	}
	c.Prefix = strings.Trim(c.Prefix, "/")
	if !prefixRE.MatchString(c.Prefix) || strings.Contains(c.Prefix, "//") || slices.ContainsFunc(strings.Split(c.Prefix, "/"), func(s string) bool { return s == ".." || s == "." }) {
		return fmt.Errorf("prefix %q must be slash-separated segments of letters, digits, '.', '_' and '-'", c.Prefix)
	}
	for _, pat := range c.Events {
		if _, err := path.Match(pat, ""); err != nil || pat == "" {
			return fmt.Errorf("events: invalid pattern %q", pat)
		}
	}
	switch {
	case c.BatchSize == 0:
		c.BatchSize = DefaultBatchSize
	case c.BatchSize < 0 || c.BatchSize > MaxBatchSize:
		return fmt.Errorf("batch_size must be between 1 and %d, got %d", MaxBatchSize, c.BatchSize)
	}
	var err error
	if p.flushInterval, err = parseDuration("flush_interval", c.FlushInterval, DefaultFlushInterval); err != nil {
		return err
	}
	if p.timeout, err = parseDuration("timeout", c.Timeout, DefaultTimeout); err != nil {
		return err
	}
	switch c.Compression {
	case "":
		c.Compression = CompressionGzip
	case CompressionGzip, CompressionNone:
	default:
		return fmt.Errorf("compression must be gzip or none, got %q", c.Compression)
	}
	if c.MaxAttempts == 0 {
		c.MaxAttempts = DefaultMaxAttempts
	} else if c.MaxAttempts < 0 {
		return fmt.Errorf("max_attempts must be positive, got %d", c.MaxAttempts)
	}
	return nil
}

func parseDuration(field, s string, def time.Duration) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", field, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive, got %s", field, s)
	}
	return d, nil
}

// newStore builds the configured backend.
func (p *Plugin) newStore(ctx context.Context) (objectStore, error) {
	switch p.cfg.Backend {
	case BackendS3:
		return newS3Store(*p.cfg.S3, p.timeout)
	case BackendGCS:
		return newGCSStore(ctx, *p.cfg.GCS, p.timeout)
	case BackendAzure:
		return newAzureStore(*p.cfg.Azure, p.timeout)
	default:
		return newFileStore(p.cfg.File.Dir)
	}
}

// Health checks that the bucket, container or directory is reachable.
func (p *Plugin) Health(ctx context.Context) error { return p.store.Check(ctx) }

// batch is the open batch: the events of the object last written.
type batch struct {
	hour    time.Time // UTC hour of every event in the batch
	started time.Time // when the batch was opened (p.now)
	events  []sdk.Event
	ids     map[string]bool
	key     string // object holding events, "" if none
}

func (b *batch) last() sdk.Event { return b.events[len(b.events)-1] }

// closedFor reports whether e must start a new batch.
func (p *Plugin) closedFor(e sdk.Event, hour time.Time) bool {
	b := &p.cur
	return len(b.events) == 0 ||
		len(b.events) >= p.cfg.BatchSize ||
		p.now().Sub(b.started) >= p.flushInterval ||
		!hour.Equal(b.hour) ||
		e.Seq <= b.last().Seq // a redelivery or a dead-letter replay
}

// handle archives one event. It returns only once an object containing e
// is stored, so the dispatcher never moves its cursor past an event that
// could still be lost.
func (p *Plugin) handle(ctx context.Context, e sdk.Event) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cur.ids[e.ID] {
		return nil // already stored with the open batch
	}
	hour := e.Time.UTC().Truncate(time.Hour)
	next := batch{hour: hour, started: p.now(), ids: map[string]bool{}}
	if !p.closedFor(e, hour) {
		next = p.cur
	}
	events := append(append(make([]sdk.Event, 0, len(next.events)+1), next.events...), e)
	body, err := encode(events, p.cfg.Compression == CompressionGzip)
	if err != nil {
		return err
	}
	key := objectKey(p.cfg.Prefix, hour, events[0].Seq, e.Seq, p.cfg.Compression == CompressionGzip)
	if err := p.store.Put(ctx, key, body, contentType(p.cfg.Compression == CompressionGzip)); err != nil {
		return fmt.Errorf("archive %s: %w", key, err)
	}
	prev := next.key
	ids := next.ids
	if len(next.events) > 0 {
		// Copy so a retained old batch is never mutated.
		ids = make(map[string]bool, len(next.ids)+1)
		for id := range next.ids {
			ids[id] = true
		}
	}
	ids[e.ID] = true
	p.cur = batch{hour: hour, started: next.started, events: events, ids: ids, key: key}
	if prev != "" && prev != key {
		// The new object supersedes the previous one. If deleting it fails
		// readers see overlapping objects and drop the duplicates.
		if err := p.store.Delete(ctx, prev); err != nil {
			p.log.Warn("delete superseded archive object", "key", prev, "err", err)
		}
	}
	return nil
}

// encode renders events as NDJSON, gzip-compressed if gz. The gzip header
// carries no timestamp, so equal input gives equal bytes.
func encode(events []sdk.Event, gz bool) ([]byte, error) {
	var buf bytes.Buffer
	var w interface {
		Write([]byte) (int, error)
	} = &buf
	var zw *gzip.Writer
	if gz {
		zw = gzip.NewWriter(&buf)
		w = zw
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			return nil, err
		}
	}
	if zw != nil {
		if err := zw.Close(); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func contentType(gz bool) string {
	if gz {
		return "application/gzip"
	}
	return "application/x-ndjson"
}

// Object names.
const (
	extNDJSON = ".ndjson"
	extGzip   = ".ndjson.gz"
)

// objectKey returns {prefix}/{yyyy}/{mm}/{dd}/{hh}/{first}-{last}.ndjson[.gz].
func objectKey(prefix string, hour time.Time, first, last int64, gz bool) string {
	ext := extNDJSON
	if gz {
		ext = extGzip
	}
	return fmt.Sprintf("%s%s/%020d-%020d%s", prefixPath(prefix), hour.UTC().Format("2006/01/02/15"), first, last, ext)
}

// dayPrefix is the key prefix of all objects of day's hours.
func dayPrefix(prefix string, day time.Time) string {
	return prefixPath(prefix) + day.UTC().Format("2006/01/02") + "/"
}

func prefixPath(prefix string) string {
	if prefix == "" {
		return ""
	}
	return prefix + "/"
}

// segment is a parsed object key.
type segment struct {
	key         string
	hour        time.Time
	first, last int64
	gz          bool
}

var keyRE = regexp.MustCompile(`(?:^|/)(\d{4})/(\d{2})/(\d{2})/(\d{2})/(\d{20})-(\d{20})(\.ndjson(?:\.gz)?)$`)

// parseKey parses an object key below prefix; ok is false for keys the
// plugin did not write.
func parseKey(prefix, key string) (segment, bool) {
	rest, ok := strings.CutPrefix(key, prefixPath(prefix))
	if !ok {
		return segment{}, false
	}
	m := keyRE.FindStringSubmatch(rest)
	if m == nil || len(m[0]) != len(rest) {
		return segment{}, false
	}
	hour, err := time.Parse("2006/01/02/15", m[1]+"/"+m[2]+"/"+m[3]+"/"+m[4])
	if err != nil {
		return segment{}, false
	}
	first, err := strconv.ParseInt(m[5], 10, 64)
	if err != nil {
		return segment{}, false
	}
	last, err := strconv.ParseInt(m[6], 10, 64)
	if err != nil {
		return segment{}, false
	}
	if last < first {
		return segment{}, false
	}
	return segment{key: key, hour: hour, first: first, last: last, gz: m[7] == extGzip}, true
}

// errNotFound is returned by objectStore.Get for missing objects.
var errNotFound = errors.New("object not found")
