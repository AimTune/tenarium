package siem

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

var testTime = time.Date(2026, 10, 10, 8, 30, 0, 123456000, time.UTC)

func tenantEvent() sdk.Event {
	e := sdktest.TenantEvent(sdk.EventTenantSuspended, sdk.Tenant{ID: "t-1", Slug: "acme", Name: "Acme", Status: sdk.StatusSuspended})
	e.ID, e.Seq, e.Time, e.Actor = "evt-1", 42, testTime, "oidc:alice@example.com"
	return e
}

func setup(t *testing.T, cfg map[string]any) (*Plugin, *sdktest.Registrar) {
	t.Helper()
	reg := sdktest.NewRegistrar(cfg)
	p := &Plugin{now: func() time.Time { return testTime }}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { _ = p.Stop(context.Background()) })
	return p, reg
}

type recorded struct {
	Method, Path, Query string
	Header              http.Header
	Body                []byte
}

type fakeHTTP struct {
	mu    sync.Mutex
	reqs  []recorded
	srv   *httptest.Server
	reply func(w http.ResponseWriter, r *http.Request, body []byte)
}

func newFake(t *testing.T, reply func(w http.ResponseWriter, r *http.Request, body []byte)) *fakeHTTP {
	f := &fakeHTTP{reply: reply}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.reqs = append(f.reqs, recorded{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), body})
		f.mu.Unlock()
		f.reply(w, r, body)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeHTTP) requests() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.reqs...)
}

func TestRecord(t *testing.T) {
	p, _ := setup(t, map[string]any{"syslog": map[string]any{"address": "127.0.0.1:1"}})
	r := p.record(tenantEvent())
	if r.TenantID != "t-1" || r.TenantSlug != "acme" || r.TenantName != "Acme" || r.ActorType != "oidc" ||
		r.ActorID != "alice@example.com" || r.Outcome != "success" || r.Seq != 42 || len(r.Data) == 0 {
		t.Fatalf("record = %+v", r)
	}
	sys := p.record(sdk.Event{ID: "e", Type: sdk.EventTenantProvisioningFailed, Actor: "system"})
	if sys.ActorType != "system" || sys.ActorID != "" || sys.Outcome != "failure" || !sys.Time.Equal(testTime) {
		t.Fatalf("system record = %+v", sys)
	}
	p.cfg.IncludeData = new(bool)
	if r := p.record(tenantEvent()); r.Data != nil {
		t.Fatal("data included with include_data false")
	}
}

func TestSplunk(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/services/collector/health" {
			_, _ = io.WriteString(w, `{"text":"HEC is healthy","code":17}`)
			return
		}
		_, _ = io.WriteString(w, `{"text":"Success","code":0}`)
	})
	p, reg := setup(t, map[string]any{
		"exclude_events": []string{"tenant.usage_*"},
		"splunk":         map[string]any{"url": f.srv.URL + "/", "token": "hec-token", "index": "audit", "channel": "ch-1"},
	})
	ctx := context.Background()
	if err := reg.Deliver(ctx, "splunk", tenantEvent()); err != nil {
		t.Fatal(err)
	}
	if err := reg.Deliver(ctx, "splunk", sdk.Event{ID: "x", Type: sdk.EventTenantUsagePeriodClosed}); err != nil {
		t.Fatal(err)
	}
	reqs := f.requests()
	if len(reqs) != 1 {
		t.Fatalf("requests = %d, want 1 (excluded event sent?)", len(reqs))
	}
	r := reqs[0]
	if r.Method != "POST" || r.Path != "/services/collector/event" || r.Header.Get("Authorization") != "Splunk hec-token" ||
		r.Header.Get("X-Splunk-Request-Channel") != "ch-1" {
		t.Fatalf("request = %+v", r)
	}
	var ev struct {
		Time       float64           `json:"time"`
		Index      string            `json:"index"`
		Sourcetype string            `json:"sourcetype"`
		Source     string            `json:"source"`
		Event      Record            `json:"event"`
		Fields     map[string]string `json:"fields"`
	}
	if err := json.Unmarshal(r.Body, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Time != 1791621000.123 || ev.Index != "audit" || ev.Sourcetype != "tenarium:event" || ev.Source != "tenarium" ||
		ev.Event.ID != "evt-1" || ev.Fields["tenant_id"] != "t-1" || ev.Fields["actor"] != "oidc:alice@example.com" ||
		ev.Fields["event_type"] != sdk.EventTenantSuspended {
		t.Fatalf("event = %+v", ev)
	}
	if err := p.Health(ctx); err != nil {
		t.Fatalf("health: %v", err)
	}
}

func TestSplunkErrors(t *testing.T) {
	status, body := http.StatusForbidden, `{"text":"Invalid token","code":4}`
	f := newFake(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})
	_, reg := setup(t, map[string]any{"splunk": map[string]any{"url": f.srv.URL, "token": "secret-token"}})
	err := reg.Deliver(context.Background(), "splunk", tenantEvent())
	if err == nil || !strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("err = %v", err)
	}
	status, body = http.StatusOK, `{"text":"Data channel is missing","code":10}`
	if err := reg.Deliver(context.Background(), "splunk", tenantEvent()); err == nil || !strings.Contains(err.Error(), "code 10") {
		t.Fatalf("err = %v", err)
	}
}

func TestElastic(t *testing.T) {
	var resp string
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/" {
			_, _ = io.WriteString(w, `{"cluster_name":"x"}`)
			return
		}
		_, _ = io.WriteString(w, resp)
	})
	p, reg := setup(t, map[string]any{"elastic": map[string]any{
		"url": f.srv.URL, "username": "elastic", "password": "pw", "pipeline": "audit-pipe",
	}})
	ctx := context.Background()
	resp = `{"errors":false,"items":[{"create":{"status":201}}]}`
	if err := reg.Deliver(ctx, "elastic", tenantEvent()); err != nil {
		t.Fatal(err)
	}
	// A redelivered event conflicts with the existing document: success.
	resp = `{"errors":true,"items":[{"create":{"status":409,"error":{"type":"version_conflict_engine_exception","reason":"exists"}}}]}`
	if err := reg.Deliver(ctx, "elastic", tenantEvent()); err != nil {
		t.Fatalf("conflict not treated as success: %v", err)
	}
	resp = `{"errors":true,"items":[{"create":{"status":400,"error":{"type":"mapper_parsing_exception","reason":"bad"}}}]}`
	if err := reg.Deliver(ctx, "elastic", tenantEvent()); err == nil || !strings.Contains(err.Error(), "mapper_parsing_exception") {
		t.Fatalf("err = %v", err)
	}

	r := f.requests()[0]
	user, pass, _ := (&http.Request{Header: r.Header}).BasicAuth()
	if r.Path != "/_bulk" || r.Query != "pipeline=audit-pipe" || user != "elastic" || pass != "pw" ||
		r.Header.Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("request = %+v", r)
	}
	lines := strings.Split(strings.TrimSuffix(string(r.Body), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("bulk body = %q", r.Body)
	}
	var meta map[string]map[string]string
	_ = json.Unmarshal([]byte(lines[0]), &meta)
	if meta["create"]["_index"] != "tenarium-events-2026.10.10" || meta["create"]["_id"] != "evt-1" {
		t.Fatalf("meta = %v", meta)
	}
	var doc struct {
		Timestamp string `json:"@timestamp"`
		Event     struct {
			Action, ID, Outcome string
		} `json:"event"`
		Organization struct{ ID, Name string }   `json:"organization"`
		User         struct{ ID, Domain string } `json:"user"`
		Tenarium     Record                      `json:"tenarium"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Timestamp != "2026-10-10T08:30:00.123456Z" || doc.Event.Action != sdk.EventTenantSuspended || doc.Event.ID != "evt-1" ||
		doc.Organization.ID != "t-1" || doc.Organization.Name != "Acme" || doc.User.ID != "alice@example.com" ||
		doc.User.Domain != "oidc" || doc.Tenarium.TenantSlug != "acme" {
		t.Fatalf("doc = %s", lines[1])
	}
	if err := p.Health(ctx); err != nil {
		t.Fatalf("health: %v", err)
	}
}

func TestElasticAPIKeyAndIndex(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		_, _ = io.WriteString(w, `{"errors":false,"items":[]}`)
	})
	_, reg := setup(t, map[string]any{"elastic": map[string]any{
		"url": f.srv.URL, "api_key": "a2V5", "index_prefix": "logs-tenarium", "index_date_format": "none",
	}})
	if err := reg.Deliver(context.Background(), "elastic", tenantEvent()); err != nil {
		t.Fatal(err)
	}
	r := f.requests()[0]
	if r.Header.Get("Authorization") != "ApiKey a2V5" || !strings.Contains(string(r.Body), `"_index":"logs-tenarium"`) {
		t.Fatalf("request = %+v %s", r.Header, r.Body)
	}
}

func TestSyslogTCPJSON(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	msgs := make(chan string, 4)
	go acceptFrames(ln, msgs)

	p, reg := setup(t, map[string]any{"syslog": map[string]any{
		"address": ln.Addr().String(), "hostname": "cp-1", "facility": 10,
	}})
	ctx := context.Background()
	if err := reg.Deliver(ctx, "syslog", tenantEvent()); err != nil {
		t.Fatal(err)
	}
	failed := tenantEvent()
	failed.Type, failed.ID = sdk.EventTenantProvisioningFailed, "evt-2"
	if err := reg.Deliver(ctx, "syslog", failed); err != nil {
		t.Fatal(err)
	}
	m := recv(t, msgs)
	pid := strconv.Itoa(os.Getpid())
	prefix := `<86>1 2026-10-10T08:30:00.123456Z cp-1 tenarium ` + pid + ` tenant.suspended [tenarium@32473 event_id="evt-1" event_type="tenant.suspended" seq="42" tenant_id="t-1" tenant_slug="acme" actor="oidc:alice@example.com" actor_type="oidc" actor_id="alice@example.com" outcome="success"] {`
	if !strings.HasPrefix(m, prefix) {
		t.Fatalf("message:\n%s\nwant prefix:\n%s", m, prefix)
	}
	var r Record
	if err := json.Unmarshal([]byte(m[len(prefix)-1:]), &r); err != nil || r.ID != "evt-1" {
		t.Fatalf("json payload: %v %+v", err, r)
	}
	// Failures are sent as warnings: facility 10 * 8 + 4.
	if m := recv(t, msgs); !strings.HasPrefix(m, "<84>1 ") {
		t.Fatalf("failure message = %s", m)
	}
	if err := p.Health(ctx); err != nil {
		t.Fatal(err)
	}
}

// acceptFrames reads octet-counted frames from every connection.
func acceptFrames(ln net.Listener, out chan<- string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			br := bufio.NewReader(c)
			for {
				n, err := br.ReadString(' ')
				if err != nil {
					return
				}
				size, err := strconv.Atoi(strings.TrimSpace(n))
				if err != nil {
					out <- "bad frame length: " + n
					return
				}
				buf := make([]byte, size)
				if _, err := io.ReadFull(br, buf); err != nil {
					return
				}
				out <- string(buf)
			}
		}()
	}
}

func recv(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case m := <-ch:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no syslog message received")
		return ""
	}
}

func TestSyslogReconnects(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	msgs := make(chan string, 4)
	go acceptFrames(ln, msgs)
	p, reg := setup(t, map[string]any{"syslog": map[string]any{"address": ln.Addr().String()}})
	ctx := context.Background()
	if err := reg.Deliver(ctx, "syslog", tenantEvent()); err != nil {
		t.Fatal(err)
	}
	recv(t, msgs)
	// Break the pooled connection; the next send dials again.
	_ = p.syslog.conn.Close()
	if err := reg.Deliver(ctx, "syslog", tenantEvent()); err != nil {
		t.Fatal(err)
	}
	recv(t, msgs)
}

func TestSyslogUDPCEF(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_, reg := setup(t, map[string]any{"syslog": map[string]any{
		"address": pc.LocalAddr().String(), "network": "udp", "format": "cef", "sd_id": "-", "app_name": "cp",
	}})
	e := tenantEvent()
	e.Actor = "plugin:billing|x"
	if err := reg.Deliver(context.Background(), "syslog", e); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	m := string(buf[:n])
	if !strings.Contains(m, " cp ") || !strings.Contains(m, " tenant.suspended - CEF:0|Tenarium|Tenarium|"+version+"|tenant.suspended|tenant.suspended|3|rt=1791621000123 externalId=evt-1 ") ||
		!strings.Contains(m, `suser=plugin:billing|x`) || !strings.Contains(m, "cs1Label=tenantId cs1=t-1") ||
		!strings.Contains(m, `msg={"tenant":{"id":"t-1"`) {
		t.Fatalf("message = %s", m)
	}
}

func TestCEFEscaping(t *testing.T) {
	r := Record{Time: testTime, ID: "a=b", Type: "x|y", Outcome: "failure", Data: json.RawMessage("{\"a\":\"l1\nl2\\\\\"}")}
	got := cef(r)
	if !strings.HasPrefix(got, `CEF:0|Tenarium|Tenarium|`+version+`|x\|y|x\|y|7|`) || !strings.Contains(got, `externalId=a\=b`) ||
		!strings.Contains(got, `l1\nl2\\\\`) {
		t.Fatalf("cef = %s", got)
	}
	if got := sdEscape(`a"b]c\`); got != `a\"b\]c\\` {
		t.Fatalf("sdEscape = %s", got)
	}
	if got := msgID("tenant.member_added_with_a_very_long_suffix"); len(got) != 32 {
		t.Fatalf("msgID = %q", got)
	}
}

func TestSyslogTLSNonTransparent(t *testing.T) {
	dir := t.TempDir()
	cert, caFile := selfSigned(t, dir)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	lines := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		l, _ := bufio.NewReader(c).ReadString('\n')
		lines <- l
	}()
	_, reg := setup(t, map[string]any{"syslog": map[string]any{
		"address": ln.Addr().String(), "network": "tls", "framing": "non_transparent",
		"tls": map[string]any{"ca_file": caFile, "server_name": "localhost"},
	}})
	if err := reg.Deliver(context.Background(), "syslog", tenantEvent()); err != nil {
		t.Fatal(err)
	}
	if l := recv(t, lines); !strings.HasPrefix(l, "<110>1 ") || !strings.HasSuffix(l, "}\n") {
		t.Fatalf("line = %q", l)
	}
}

func selfSigned(t *testing.T, dir string) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kb, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return cert, caFile
}

func TestSubscriptionsAndFilter(t *testing.T) {
	_, reg := setup(t, map[string]any{
		"events":  []string{"tenant.*"},
		"splunk":  map[string]any{"url": "https://splunk:8088", "token": "t"},
		"elastic": map[string]any{"url": "https://es:9200"},
	})
	if len(reg.Subscriptions) != 2 || reg.Subscriptions[0].Name != "splunk" || reg.Subscriptions[1].Name != "elastic" ||
		reg.Subscriptions[0].Filter.Types[0] != "tenant.*" {
		t.Fatalf("subscriptions = %+v", reg.Subscriptions)
	}
	// user.* is filtered out before reaching the sink (no request is made
	// to the unreachable URL).
	if err := reg.Deliver(context.Background(), "splunk", sdk.Event{ID: "u", Type: sdk.EventUserCreated}); err != nil {
		t.Fatal(err)
	}
}

func TestInitValidation(t *testing.T) {
	for name, cfg := range map[string]map[string]any{
		"no sink":           {},
		"bad timeout":       {"timeout": "soon", "splunk": map[string]any{"url": "https://s", "token": "t"}},
		"bad pattern":       {"events": []string{"["}, "splunk": map[string]any{"url": "https://s", "token": "t"}},
		"splunk no token":   {"splunk": map[string]any{"url": "https://s"}},
		"splunk bad url":    {"splunk": map[string]any{"url": "splunk:8088", "token": "t"}},
		"syslog address":    {"syslog": map[string]any{"address": "nohost"}},
		"syslog network":    {"syslog": map[string]any{"address": "h:514", "network": "sctp"}},
		"syslog format":     {"syslog": map[string]any{"address": "h:514", "format": "leef"}},
		"syslog facility":   {"syslog": map[string]any{"address": "h:514", "facility": 24}},
		"syslog severity":   {"syslog": map[string]any{"address": "h:514", "severity": -1}},
		"syslog app":        {"syslog": map[string]any{"address": "h:514", "app_name": "has space"}},
		"syslog sd_id":      {"syslog": map[string]any{"address": "h:514", "sd_id": "nonum"}},
		"syslog tls on tcp": {"syslog": map[string]any{"address": "h:514", "tls": map[string]any{"insecure_skip_verify": true}}},
		"syslog ca missing": {"syslog": map[string]any{"address": "h:514", "network": "tls", "tls": map[string]any{"ca_file": "/nonexistent/ca.pem"}}},
		"elastic both auth": {"elastic": map[string]any{"url": "https://es", "api_key": "k", "username": "u"}},
		"elastic pw only":   {"elastic": map[string]any{"url": "https://es", "password": "p"}},
		"elastic index":     {"elastic": map[string]any{"url": "https://es", "index_prefix": "Bad"}},
		"elastic date":      {"elastic": map[string]any{"url": "https://es", "index_date_format": "daily"}},
		"elastic cert pair": {"elastic": map[string]any{"url": "https://es", "tls": map[string]any{"cert_file": "c.pem"}}},
		"unknown key":       {"splunk": map[string]any{"url": "https://s", "token": "t", "idx": "x"}},
	} {
		if err := (&Plugin{}).Init(context.Background(), sdktest.NewRegistrar(cfg)); err == nil {
			t.Errorf("%s: config accepted", name)
		}
	}
}

func TestDefaults(t *testing.T) {
	p, _ := setup(t, map[string]any{
		"splunk":  map[string]any{"url": "https://s:8088", "token": "t"},
		"syslog":  map[string]any{"address": "collector:6514", "network": "tls"},
		"elastic": map[string]any{"url": "https://es:9200"},
	})
	if p.timeout != 10*time.Second || p.splunk.cfg.Sourcetype != "tenarium:event" || p.splunk.cfg.Source != "tenarium" ||
		p.syslog.facility != 13 || p.syslog.severity != 6 || p.syslog.cfg.Format != "json" ||
		p.syslog.cfg.Framing != "octet_counting" || p.syslog.tls.ServerName != "collector" ||
		p.elastic.index(testTime) != "tenarium-events-2026.10.10" {
		t.Fatalf("defaults not applied: %+v", p.cfg)
	}
}

func TestConfigSchema(t *testing.T) {
	sch, err := schema.Compile((&Plugin{}).Manifest().ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	good := map[string]any{
		"events": []any{"tenant.*"}, "exclude_events": []any{"tenant.usage_*"}, "include_data": false, "timeout": "5s",
		"splunk": map[string]any{"url": "https://s:8088", "token": "t", "index": "i", "sourcetype": "st", "source": "s",
			"host": "h", "channel": "c", "tls": map[string]any{"ca_file": "/ca.pem", "insecure_skip_verify": false}},
		"syslog": map[string]any{"address": "h:6514", "network": "tls", "format": "cef", "framing": "non_transparent",
			"facility": 13, "severity": 5, "app_name": "tenarium", "hostname": "cp-1", "sd_id": "tenarium@32473",
			"tls": map[string]any{"cert_file": "/c.pem", "key_file": "/k.pem", "server_name": "h"}},
		"elastic": map[string]any{"url": "https://es:9200", "username": "u", "password": "p",
			"index_prefix": "tenarium-audit", "index_date_format": "2006.01", "pipeline": "p"},
	}
	if err := sch.Validate(good); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for _, bad := range []map[string]any{
		{},
		{"timeout": "5s"},
		{"splunk": map[string]any{"url": "https://s"}},
		{"splunk": map[string]any{"url": "https://s", "token": "t"}, "extra": true},
		{"syslog": map[string]any{"address": "h:514", "network": "sctp"}},
		{"syslog": map[string]any{"address": "h:514", "facility": 30}},
		{"syslog": map[string]any{"address": "h"}},
		{"syslog": map[string]any{"address": "h:514", "tls": map[string]any{"cert_file": "/c.pem"}}},
		{"elastic": map[string]any{"url": "https://es", "api_key": "k", "username": "u"}},
		{"elastic": map[string]any{"url": "https://es", "index_prefix": "UPPER"}},
		{"elastic": map[string]any{"url": "ftp://es"}},
	} {
		if err := sch.Validate(bad); err == nil {
			t.Errorf("invalid config accepted: %v", bad)
		}
	}
}

func TestHealthFailure(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) { w.WriteHeader(http.StatusServiceUnavailable) })
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close() // nothing listens there now
	p, _ := setup(t, map[string]any{
		"splunk": map[string]any{"url": f.srv.URL, "token": "t"},
		"syslog": map[string]any{"address": addr, "network": "tcp"},
	})
	err := p.Health(context.Background())
	if err == nil || !strings.Contains(err.Error(), "splunk:") || !strings.Contains(err.Error(), "syslog:") {
		t.Fatalf("health = %v", err)
	}
}

func TestReconfigure(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		_, _ = io.WriteString(w, `{"text":"Success","code":0}`)
	})
	listen := func() (net.Listener, chan string) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		msgs := make(chan string, 4)
		go acceptFrames(ln, msgs)
		return ln, msgs
	}
	ln1, msgs1 := listen()
	ln2, msgs2 := listen()
	cfg := func(token, addr string) map[string]any {
		return map[string]any{
			"splunk": map[string]any{"url": f.srv.URL, "token": token},
			"syslog": map[string]any{"address": addr, "app_name": token},
		}
	}
	p, reg := setup(t, cfg("old", ln1.Addr().String()))
	ctx := context.Background()
	deliver := func() {
		t.Helper()
		for _, sub := range []string{"splunk", "syslog"} {
			if err := reg.Deliver(ctx, sub, tenantEvent()); err != nil {
				t.Fatal(err)
			}
		}
	}
	deliver()
	recv(t, msgs1)
	old := p.syslog

	if err := p.Reconfigure(ctx, sdktest.NewRegistrar(cfg("new", ln2.Addr().String())).Config); err != nil {
		t.Fatal(err)
	}
	deliver()
	reqs := f.requests()
	if h := reqs[len(reqs)-1].Header.Get("Authorization"); h != "Splunk new" {
		t.Fatalf("Authorization = %q", h)
	}
	if m := recv(t, msgs2); !strings.Contains(m, " new ") {
		t.Fatalf("syslog message = %s", m)
	}
	old.mu.Lock()
	closed := old.closed && old.conn == nil
	old.mu.Unlock()
	if !closed {
		t.Fatal("previous syslog connection not closed")
	}

	bad := cfg("bad", ln1.Addr().String())
	bad["timeout"] = "soon"
	if err := p.Reconfigure(ctx, sdktest.NewRegistrar(bad).Config); err == nil {
		t.Fatal("invalid timeout accepted")
	}
	deliver()
	reqs = f.requests()
	if h := reqs[len(reqs)-1].Header.Get("Authorization"); h != "Splunk new" {
		t.Fatalf("invalid config applied: Authorization = %q", h)
	}
	recv(t, msgs2)

	filtered := cfg("new", ln2.Addr().String())
	filtered["events"] = []string{"tenant.*"}
	if err := p.Reconfigure(ctx, sdktest.NewRegistrar(filtered).Config); err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("events change: err = %v", err)
	}
	noSyslog := cfg("new", "")
	delete(noSyslog, "syslog")
	if err := p.Reconfigure(ctx, sdktest.NewRegistrar(noSyslog).Config); err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("sink removal: err = %v", err)
	}
}
