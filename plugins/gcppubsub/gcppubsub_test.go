package gcppubsub

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
	"golang.org/x/oauth2"
)

type recorded struct {
	path string
	auth string
	body []byte
}

// fakePubSub serves topics.publish, topics.get and testIamPermissions.
func fakePubSub(t *testing.T, status int, perms []string) (*httptest.Server, func() []recorded) {
	t.Helper()
	var mu sync.Mutex
	var reqs []recorded
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		reqs = append(reqs, recorded{path: r.URL.Path, auth: r.Header.Get("Authorization"), body: b})
		mu.Unlock()
		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":{"code":404,"message":"Resource not found","status":"NOT_FOUND"}}`))
			return
		}
		switch {
		case strings.HasSuffix(r.URL.Path, ":publish"):
			_, _ = w.Write([]byte(`{"messageIds":["1"]}`))
		case strings.HasSuffix(r.URL.Path, ":testIamPermissions"):
			_ = json.NewEncoder(w).Encode(map[string]any{"permissions": perms})
		default:
			_, _ = w.Write([]byte(`{"name":"x"}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []recorded {
		mu.Lock()
		defer mu.Unlock()
		return append([]recorded(nil), reqs...)
	}
}

// serviceAccount returns a service account key whose token endpoint is a
// local fake issuing "test-token".
func serviceAccount(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"test-token","token_type":"Bearer","expires_in":3600}`))
	}))
	t.Cleanup(tokenSrv.Close)
	sa, _ := json.Marshal(map[string]string{
		"type":           "service_account",
		"project_id":     "my-project",
		"private_key_id": "k1",
		"private_key":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email":   "tenarium@my-project.iam.gserviceaccount.com",
		"client_id":      "1",
		"token_uri":      tokenSrv.URL + "/token",
	})
	return string(sa)
}

func initPlugin(t *testing.T, cfg map[string]any, srv *httptest.Server) (*Plugin, *sdktest.Registrar) {
	t.Helper()
	reg := sdktest.NewRegistrar(cfg)
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	// Trust the TLS test server.
	if tr, ok := p.client.Transport.(*oauth2.Transport); ok {
		tr.Base = srv.Client().Transport
	} else {
		p.client.Transport = srv.Client().Transport
	}
	return p, reg
}

func TestPublishWithServiceAccount(t *testing.T) {
	srv, reqs := fakePubSub(t, http.StatusOK, []string{"pubsub.topics.publish"})
	p, reg := initPlugin(t, map[string]any{
		"project": "my-project", "topic": "tenarium-events", "endpoint": srv.URL,
		"credentials_json": serviceAccount(t), "ordering": true, "attributes": map[string]string{"env": "prod"},
	}, srv)
	e := sdktest.TenantEvent(sdk.EventTenantCreated, sdk.Tenant{ID: "t1", Slug: "acme"})
	if err := reg.Deliver(context.Background(), "publish", e); err != nil {
		t.Fatal(err)
	}
	if err := p.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := reqs()
	if got[0].path != "/v1/projects/my-project/topics/tenarium-events:publish" || got[0].auth != "Bearer test-token" {
		t.Fatalf("request %s %q", got[0].path, got[0].auth)
	}
	var body struct {
		Messages []pubsubMessage `json:"messages"`
	}
	if err := json.Unmarshal(got[0].body, &body); err != nil {
		t.Fatal(err)
	}
	m := body.Messages[0]
	if m.OrderingKey != "t1" || m.Attributes["ce-type"] != e.Type || m.Attributes["ce-id"] != e.ID ||
		m.Attributes["tenant_id"] != "t1" || m.Attributes["env"] != "prod" {
		t.Fatalf("message %+v", m)
	}
	data, _ := base64.StdEncoding.DecodeString(m.Data)
	var ce sdk.CloudEvent
	if err := json.Unmarshal(data, &ce); err != nil || ce.ID != e.ID {
		t.Fatalf("data %s %v", data, err)
	}
	if !strings.HasSuffix(got[1].path, ":testIamPermissions") {
		t.Fatalf("health request %s", got[1].path)
	}
}

func TestHealthMissingPermission(t *testing.T) {
	srv, _ := fakePubSub(t, http.StatusOK, nil)
	p, _ := initPlugin(t, map[string]any{"project": "my-project", "topic": "events", "endpoint": srv.URL,
		"credentials_json": serviceAccount(t)}, srv)
	if err := p.Health(context.Background()); err == nil || !strings.Contains(err.Error(), "pubsub.topics.publish") {
		t.Fatalf("health: %v", err)
	}
}

func TestPublishError(t *testing.T) {
	srv, _ := fakePubSub(t, http.StatusNotFound, nil)
	_, reg := initPlugin(t, map[string]any{"project": "my-project", "topic": "events", "endpoint": srv.URL,
		"credentials_json": serviceAccount(t)}, srv)
	err := reg.Deliver(context.Background(), "publish", sdktest.TenantEvent(sdk.EventTenantCreated, sdk.Tenant{ID: "t1"}))
	if err == nil || !strings.Contains(err.Error(), "NOT_FOUND") {
		t.Fatalf("publish: %v", err)
	}
}

func TestEmulatorNoAuth(t *testing.T) {
	srv, reqs := fakePubSub(t, http.StatusOK, nil)
	p, reg := initPlugin(t, map[string]any{"project": "my-project", "topic": "events", "endpoint": srv.URL, "emulator": true}, srv)
	if err := reg.Deliver(context.Background(), "publish", sdk.Event{ID: "p1", Type: sdk.EventPlanCreated}); err != nil {
		t.Fatal(err)
	}
	if err := p.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := reqs()
	if got[0].auth != "" || got[1].path != "/v1/projects/my-project/topics/events" {
		t.Fatalf("requests %+v", got)
	}
	if bytes.Contains(got[0].body, []byte("orderingKey")) {
		t.Fatal("ordering key without ordering")
	}
}

func TestConfigValidation(t *testing.T) {
	for _, cfg := range []map[string]any{
		{},
		{"project": "my-project"},
		{"project": "My Project", "topic": "events"},
		{"project": "my-project", "topic": "goog-events"},
		{"project": "my-project", "topic": "events", "nope": 1},
		{"project": "my-project", "topic": "events", "endpoint": "http://pubsub.example.com", "credentials_json": "{}"},
		{"project": "my-project", "topic": "events", "credentials_json": "{}", "credentials_file": "/x"},
		{"project": "my-project", "topic": "events", "credentials_json": `{"type":"weird"}`},
		{"project": "my-project", "topic": "events", "credentials_json": "not json"},
		{"project": "my-project", "topic": "events", "emulator": true, "credentials_json": "{}"},
		{"project": "my-project", "topic": "events", "emulator": true, "attributes": map[string]string{"ce-id": "x"}},
		{"project": "my-project", "topic": "events", "emulator": true, "timeout": "-1s"},
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
	good := map[string]any{"project": "my-project", "topic": "tenarium-events", "events": []any{"tenant.*"},
		"credentials_file": "/sa.json", "ordering": true, "attributes": map[string]any{"env": "prod"},
		"endpoint": "https://europe-west1-pubsub.googleapis.com", "timeout": "10s"}
	if err := s.Validate(good); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]map[string]any{
		"missing topic":  {"project": "my-project"},
		"unknown field":  {"project": "my-project", "topic": "events", "nope": 1},
		"both creds":     {"project": "my-project", "topic": "events", "credentials_file": "a", "credentials_json": "b"},
		"attribute type": {"project": "my-project", "topic": "events", "attributes": map[string]any{"a": 1}},
	} {
		if err := s.Validate(bad); err == nil {
			t.Errorf("%s: expected schema error", name)
		}
	}
}

// TestEmulator runs against the Pub/Sub emulator, e.g.
// `docker run -d -p 18085:8085 gcr.io/google.com/cloudsdktool/google-cloud-cli:emulators
// gcloud beta emulators pubsub start --host-port=0.0.0.0:8085` and
// TENARIUM_TEST_PUBSUB_EMULATOR=http://localhost:18085.
func TestEmulator(t *testing.T) {
	endpoint := os.Getenv("TENARIUM_TEST_PUBSUB_EMULATOR")
	if endpoint == "" {
		t.Skip("TENARIUM_TEST_PUBSUB_EMULATOR not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	project, topic, sub := "tenarium-test", fmt.Sprintf("events-%d", time.Now().UnixNano()), fmt.Sprintf("sub-%d", time.Now().UnixNano())
	base := strings.TrimRight(endpoint, "/") + "/v1/projects/" + project
	do := func(method, url string, body any, out any) {
		t.Helper()
		b, _ := json.Marshal(body)
		req, _ := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		if resp.StatusCode/100 != 2 {
			t.Fatalf("%s %s: %d %s", method, url, resp.StatusCode, raw)
		}
		if out != nil {
			_ = json.Unmarshal(raw, out)
		}
	}
	do(http.MethodPut, base+"/topics/"+topic, map[string]any{}, nil)
	defer do(http.MethodDelete, base+"/topics/"+topic, nil, nil)
	do(http.MethodPut, base+"/subscriptions/"+sub, map[string]any{
		"topic": "projects/" + project + "/topics/" + topic, "enableMessageOrdering": true}, nil)
	defer do(http.MethodDelete, base+"/subscriptions/"+sub, nil, nil)

	reg := sdktest.NewRegistrar(map[string]any{"project": project, "topic": topic, "endpoint": endpoint,
		"emulator": true, "ordering": true})
	p := &Plugin{}
	if err := p.Init(ctx, reg); err != nil {
		t.Fatal(err)
	}
	if err := p.Health(ctx); err != nil {
		t.Fatal(err)
	}
	e := sdktest.TenantEvent(sdk.EventTenantCreated, sdk.Tenant{ID: "t1"})
	if err := reg.Deliver(ctx, "publish", e); err != nil {
		t.Fatal(err)
	}
	var pulled struct {
		ReceivedMessages []struct {
			Message struct {
				Data        string            `json:"data"`
				Attributes  map[string]string `json:"attributes"`
				OrderingKey string            `json:"orderingKey"`
			} `json:"message"`
		} `json:"receivedMessages"`
	}
	do(http.MethodPost, base+"/subscriptions/"+sub+":pull", map[string]any{"maxMessages": 10}, &pulled)
	if len(pulled.ReceivedMessages) != 1 {
		t.Fatalf("pulled %+v", pulled)
	}
	m := pulled.ReceivedMessages[0].Message
	data, _ := base64.StdEncoding.DecodeString(m.Data)
	if m.Attributes["ce-id"] != e.ID || m.OrderingKey != "t1" || !strings.Contains(string(data), e.ID) {
		t.Fatalf("message %+v %s", m, data)
	}

	missing := &Plugin{}
	if err := missing.Init(ctx, sdktest.NewRegistrar(map[string]any{"project": project, "topic": "missing-topic",
		"endpoint": endpoint, "emulator": true})); err != nil {
		t.Fatal(err)
	}
	if err := missing.Health(ctx); err == nil {
		t.Fatal("health passed for a missing topic")
	}
}

func TestReconfigure(t *testing.T) {
	// Plain-HTTP emulator fakes; each records the request paths it served.
	fake := func() (*httptest.Server, func() []string) {
		var mu sync.Mutex
		var paths []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			paths = append(paths, r.URL.Path)
			mu.Unlock()
			_, _ = w.Write([]byte(`{"messageIds":["1"]}`))
		}))
		t.Cleanup(srv.Close)
		return srv, func() []string {
			mu.Lock()
			defer mu.Unlock()
			return append([]string(nil), paths...)
		}
	}
	oldSrv, oldPaths := fake()
	newSrv, newPaths := fake()
	base := map[string]any{"project": "my-project", "topic": "events", "endpoint": oldSrv.URL, "emulator": true}
	reg := sdktest.NewRegistrar(base)
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	e := sdktest.TenantEvent(sdk.EventTenantCreated, sdk.Tenant{ID: "t1"})

	if err := p.Reconfigure(context.Background(), sdktest.NewRegistrar(map[string]any{
		"project": "my-project", "topic": "other", "endpoint": newSrv.URL, "emulator": true,
	}).Config); err != nil {
		t.Fatal(err)
	}
	if err := reg.Deliver(context.Background(), "publish", e); err != nil {
		t.Fatal(err)
	}
	if got := newPaths(); len(got) != 1 || got[0] != "/v1/projects/my-project/topics/other:publish" || len(oldPaths()) != 0 {
		t.Fatalf("new %v old %v", got, oldPaths())
	}

	// Invalid config: rejected, the previous settings stay.
	if err := p.Reconfigure(context.Background(), sdktest.NewRegistrar(map[string]any{
		"project": "my-project", "topic": "events", "emulator": true, "credentials_json": "{}",
	}).Config); err == nil {
		t.Fatal("invalid config accepted")
	}
	if err := reg.Deliver(context.Background(), "publish", e); err != nil || len(newPaths()) != 2 {
		t.Fatalf("after failed reconfigure: %v %v", err, newPaths())
	}

	// The event filter is fixed at startup.
	base["events"] = []string{"tenant.*"}
	if err := p.Reconfigure(context.Background(), sdktest.NewRegistrar(base).Config); err == nil ||
		!strings.Contains(err.Error(), "restart") {
		t.Fatalf("events change: %v", err)
	}
}
