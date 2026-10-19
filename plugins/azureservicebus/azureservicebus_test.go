package azureservicebus

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

const testKey = "c2VjcmV0LWtleS1mb3ItdGVzdHM="

func connString(extra string) string {
	return "Endpoint=sb://acme.servicebus.windows.net/;SharedAccessKeyName=send;SharedAccessKey=" + testKey + extra
}

func TestParseConnectionString(t *testing.T) {
	cs, err := ParseConnectionString(connString(";EntityPath=events"))
	if err != nil {
		t.Fatal(err)
	}
	if cs.Endpoint != "sb://acme.servicebus.windows.net/" || cs.KeyName != "send" || cs.Key != testKey || cs.EntityPath != "events" {
		t.Fatalf("%+v", cs)
	}
	for _, bad := range []string{
		"",
		"Endpoint=sb://x/",
		"Endpoint=sb://x/;SharedAccessKeyName=a",
		"Endpoint=sb://x/;Bogus=1;SharedAccessKeyName=a;SharedAccessKey=b",
		"Endpoint=sb://x/;nonsense",
		"Endpoint=sb://localhost;SharedAccessKeyName=a;SharedAccessKey=b;UseDevelopmentEmulator=true",
		"Endpoint=sb://x/;SharedAccessSignature=sr=x",
	} {
		if _, err := ParseConnectionString(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := ParseConnectionString("Endpoint=sb://x/;SharedAccessSignature=SharedAccessSignature sr=a&sig=b&se=1&skn=k"); err != nil {
		t.Fatal(err)
	}
}

// verifySAS checks a token the way Service Bus does.
func verifySAS(t *testing.T, token, wantResource, keyName, key string) {
	t.Helper()
	rest, ok := strings.CutPrefix(token, "SharedAccessSignature ")
	if !ok {
		t.Fatalf("token %q", token)
	}
	q, err := url.ParseQuery(rest)
	if err != nil {
		t.Fatal(err)
	}
	if q.Get("sr") != wantResource || q.Get("skn") != keyName {
		t.Fatalf("token fields %v", q)
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(url.QueryEscape(q.Get("sr")) + "\n" + q.Get("se")))
	if want := base64.StdEncoding.EncodeToString(mac.Sum(nil)); q.Get("sig") != want {
		t.Fatalf("signature %q, want %q", q.Get("sig"), want)
	}
}

func TestSASToken(t *testing.T) {
	exp := time.Unix(1700000000, 0)
	tok := SASToken("https://acme.servicebus.windows.net/events", "send", testKey, exp)
	verifySAS(t, tok, "https://acme.servicebus.windows.net/events", "send", testKey)
	if !strings.Contains(tok, "se=1700000000") {
		t.Fatal(tok)
	}
}

func TestTokenCaching(t *testing.T) {
	p := &Plugin{cfg: Config{ConnectionString: connString(""), Entity: "events"}}
	if _, err := p.validate(); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0)
	p.now = func() time.Time { return now }
	a := p.authorization()
	now = now.Add(30 * time.Minute)
	if p.authorization() != a {
		t.Fatal("token not cached")
	}
	now = now.Add(26 * time.Minute) // within 5 minutes of expiry
	if p.authorization() == a {
		t.Fatal("token not renewed")
	}
}

type captured struct {
	method, path string
	header       http.Header
	body         []byte
}

func fakeServiceBus(t *testing.T, sendStatus int, healthStatus int, healthBody string) (*httptest.Server, func() []captured) {
	t.Helper()
	var mu sync.Mutex
	var reqs []captured
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		reqs = append(reqs, captured{r.Method, r.URL.Path, r.Header.Clone(), b})
		mu.Unlock()
		if r.Method == http.MethodPost {
			w.WriteHeader(sendStatus)
			if sendStatus != http.StatusCreated {
				_, _ = w.Write([]byte("<Error><Code>400</Code><Detail>SessionId needs to be set for all brokered messages to a Partitioned Topic that supports Ordering</Detail></Error>"))
			}
			return
		}
		w.WriteHeader(healthStatus)
		_, _ = w.Write([]byte(healthBody))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []captured {
		mu.Lock()
		defer mu.Unlock()
		return append([]captured(nil), reqs...)
	}
}

func TestPublish(t *testing.T) {
	srv, reqs := fakeServiceBus(t, http.StatusCreated, http.StatusOK, `<entry xmlns="http://www.w3.org/2005/Atom"></entry>`)
	reg := sdktest.NewRegistrar(map[string]any{
		"connection_string": connString(";EntityPath=events"), "endpoint": srv.URL, "session": true,
		"properties": map[string]string{"env": "prod"}, "time_to_live": "1h",
	})
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	e := sdktest.TenantEvent(sdk.EventTenantCreated, sdk.Tenant{ID: "t1", Slug: "acme"})
	if err := reg.Deliver(context.Background(), "publish", e); err != nil {
		t.Fatal(err)
	}
	if err := p.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := reqs()[0]
	if r.method != http.MethodPost || r.path != "/events/messages" {
		t.Fatalf("%s %s", r.method, r.path)
	}
	verifySAS(t, r.header.Get("Authorization"), "https://acme.servicebus.windows.net/events", "send", testKey)
	var bp brokerProperties
	if err := json.Unmarshal([]byte(r.header.Get("BrokerProperties")), &bp); err != nil {
		t.Fatal(err)
	}
	if bp.MessageID != e.ID || bp.SessionID != "t1" || bp.Label != e.Type || bp.TimeToLive != 3600 {
		t.Fatalf("broker properties %+v", bp)
	}
	if r.header.Get("Content-Type") != "application/cloudevents+json" {
		t.Fatal(r.header)
	}
	// httptest canonicalizes header names on the server side.
	if r.header.Get("Tenant_id") != `"t1"` || r.header.Get("Ce_type") != `"tenant.created"` || r.header.Get("Env") != `"prod"` {
		t.Fatalf("custom properties %v", r.header)
	}
	var ce sdk.CloudEvent
	if err := json.Unmarshal(r.body, &ce); err != nil || ce.ID != e.ID {
		t.Fatalf("body %s", r.body)
	}
	// The plugin sends custom property names with their configured case.
	req, err := p.request(context.Background(), e)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := req.Header["tenant_id"]; !ok { //nolint:staticcheck // property names are sent non-canonical on purpose
		t.Fatalf("raw headers %v", req.Header)
	}
}

func TestPublishError(t *testing.T) {
	srv, _ := fakeServiceBus(t, http.StatusBadRequest, http.StatusOK, "")
	reg := sdktest.NewRegistrar(map[string]any{"connection_string": connString(""), "entity": "orders", "endpoint": srv.URL})
	if err := (&Plugin{}).Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	err := reg.Deliver(context.Background(), "publish", sdktest.TenantEvent(sdk.EventTenantCreated, sdk.Tenant{ID: "t1"}))
	if err == nil || !strings.Contains(err.Error(), "SessionId needs to be set") {
		t.Fatalf("publish: %v", err)
	}
}

func TestHealth(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		body   string
		ok     bool
	}{
		"entity":        {http.StatusOK, `<entry><content/></entry>`, true},
		"missing":       {http.StatusOK, `<feed xmlns="http://www.w3.org/2005/Atom"></feed>`, false},
		"send-only key": {http.StatusUnauthorized, `<Error><Code>401</Code><Detail>Manage,EntityRead claims required for this operation.</Detail></Error>`, true},
		"bad signature": {http.StatusUnauthorized, `<Error><Code>401</Code><Detail>InvalidSignature: The token has an invalid signature.</Detail></Error>`, false},
	} {
		srv, _ := fakeServiceBus(t, http.StatusCreated, tc.status, tc.body)
		p := &Plugin{}
		if err := p.Init(context.Background(), sdktest.NewRegistrar(map[string]any{"connection_string": connString(""), "entity": "events", "endpoint": srv.URL})); err != nil {
			t.Fatal(err)
		}
		if err := p.Health(context.Background()); (err == nil) != tc.ok {
			t.Errorf("%s: health %v", name, err)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	for _, cfg := range []map[string]any{
		{},
		{"connection_string": connString("")},
		{"connection_string": connString(";EntityPath=a"), "entity": "b"},
		{"connection_string": connString(""), "entity": "../x"},
		{"connection_string": connString(""), "entity": "e", "nope": 1},
		{"connection_string": connString(""), "entity": "e", "endpoint": "http://example.com"},
		{"connection_string": connString(""), "entity": "e", "properties": map[string]string{"tenant_id": "x"}},
		{"connection_string": connString(""), "entity": "e", "properties": map[string]string{"bad name": "x"}},
		{"connection_string": connString(""), "entity": "e", "token_ttl": "1m"},
		{"connection_string": connString(""), "entity": "e", "time_to_live": "x"},
	} {
		if err := (&Plugin{}).Init(context.Background(), sdktest.NewRegistrar(cfg)); err == nil {
			t.Errorf("config %v accepted", cfg)
		}
	}
}

func TestConfigSchema(t *testing.T) {
	s, err := schema.Compile((&Plugin{}).Manifest().ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	good := map[string]any{"connection_string": connString(""), "entity": "events", "events": []any{"tenant.*"},
		"session": true, "properties": map[string]any{"env": "prod"}, "time_to_live": "24h", "token_ttl": "2h", "timeout": "10s"}
	if err := s.Validate(good); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]map[string]any{
		"missing conn":  {"entity": "e"},
		"unknown field": {"connection_string": connString(""), "nope": 1},
		"bad property":  {"connection_string": connString(""), "properties": map[string]any{"a b": "x"}},
	} {
		if err := s.Validate(bad); err == nil {
			t.Errorf("%s: expected schema error", name)
		}
	}
}

// TestRealNamespace publishes to a real Service Bus entity:
// TENARIUM_TEST_AZURE_SERVICEBUS_CONNECTION_STRING and
// TENARIUM_TEST_AZURE_SERVICEBUS_ENTITY (a queue or topic without sessions).
func TestRealNamespace(t *testing.T) {
	conn := os.Getenv("TENARIUM_TEST_AZURE_SERVICEBUS_CONNECTION_STRING")
	if conn == "" {
		t.Skip("TENARIUM_TEST_AZURE_SERVICEBUS_CONNECTION_STRING not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	reg := sdktest.NewRegistrar(map[string]any{"connection_string": conn, "entity": os.Getenv("TENARIUM_TEST_AZURE_SERVICEBUS_ENTITY")})
	p := &Plugin{}
	if err := p.Init(ctx, reg); err != nil {
		t.Fatal(err)
	}
	if err := p.Health(ctx); err != nil {
		t.Fatalf("health: %v", err)
	}
	if err := reg.Deliver(ctx, "publish", sdktest.TenantEvent(sdk.EventTenantCreated, sdk.Tenant{ID: "t1"})); err != nil {
		t.Fatal(err)
	}
}

func TestReconfigure(t *testing.T) {
	oldSrv, oldReqs := fakeServiceBus(t, http.StatusCreated, http.StatusOK, "")
	newSrv, newReqs := fakeServiceBus(t, http.StatusCreated, http.StatusOK, "")
	base := map[string]any{"connection_string": connString(""), "entity": "events", "endpoint": oldSrv.URL}
	reg := sdktest.NewRegistrar(base)
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	e := sdktest.TenantEvent(sdk.EventTenantCreated, sdk.Tenant{ID: "t1"})

	// Key rotation and a new endpoint and entity.
	const newKey = "bmV3LXNlY3JldC1rZXk="
	if err := p.Reconfigure(context.Background(), sdktest.NewRegistrar(map[string]any{
		"connection_string": "Endpoint=sb://acme.servicebus.windows.net/;SharedAccessKeyName=rotated;SharedAccessKey=" + newKey,
		"entity":            "orders", "endpoint": newSrv.URL,
	}).Config); err != nil {
		t.Fatal(err)
	}
	if err := reg.Deliver(context.Background(), "publish", e); err != nil {
		t.Fatal(err)
	}
	got := newReqs()
	if len(got) != 1 || got[0].path != "/orders/messages" || len(oldReqs()) != 0 {
		t.Fatalf("new %v old %v", got, oldReqs())
	}
	verifySAS(t, got[0].header.Get("Authorization"), "https://acme.servicebus.windows.net/orders", "rotated", newKey)

	// Invalid config: rejected, the previous settings stay.
	if err := p.Reconfigure(context.Background(), sdktest.NewRegistrar(map[string]any{
		"connection_string": connString(""), "entity": "events", "token_ttl": "1m",
	}).Config); err == nil {
		t.Fatal("invalid config accepted")
	}
	if err := reg.Deliver(context.Background(), "publish", e); err != nil || len(newReqs()) != 2 {
		t.Fatalf("after failed reconfigure: %v %d", err, len(newReqs()))
	}

	// The event filter is fixed at startup.
	base["events"] = []string{"tenant.*"}
	if err := p.Reconfigure(context.Background(), sdktest.NewRegistrar(base).Config); err == nil ||
		!strings.Contains(err.Error(), "restart") {
		t.Fatalf("events change: %v", err)
	}
}
