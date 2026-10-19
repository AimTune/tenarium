package salesforce

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

type apiCall struct {
	Method, Path, Token string
	Body                map[string]string
}

// fakeSF serves the token endpoint and the REST API, keeping records by
// external ID.
type fakeSF struct {
	mu        sync.Mutex
	srv       *httptest.Server
	tokenReqs []map[string]string
	issued    int
	valid     map[string]bool
	records   map[string]map[string]string
	calls     []apiCall
}

func newFake(t *testing.T) *fakeSF {
	f := &fakeSF{valid: map[string]bool{}, records: map[string]map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSF) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/services/oauth2/token" {
		_ = r.ParseForm()
		form := map[string]string{}
		for k := range r.PostForm {
			form[k] = r.PostForm.Get(k)
		}
		f.tokenReqs = append(f.tokenReqs, form)
		if form["client_secret"] == "wrong" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"invalid_client","error_description":"invalid client credentials"}`)
			return
		}
		f.issued++
		tok := fmt.Sprintf("tok-%d", f.issued)
		f.valid[tok] = true
		// Like Salesforce: no expires_in.
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": tok, "token_type": "Bearer", "instance_url": f.srv.URL})
		return
	}
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	var body map[string]string
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.calls = append(f.calls, apiCall{r.Method, r.URL.EscapedPath(), tok, body})
	if !f.valid[tok] {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `[{"message":"Session expired or invalid","errorCode":"INVALID_SESSION_ID"}]`)
		return
	}
	const prefix = "/services/data/v62.0"
	path := strings.TrimPrefix(r.URL.Path, prefix)
	switch {
	case path == "/limits" && r.Method == http.MethodGet:
		_, _ = io.WriteString(w, `{"DailyApiRequests":{"Max":15000,"Remaining":14999}}`)
	case strings.HasPrefix(path, "/sobjects/Account/Tenarium_Tenant_Id__c/"):
		id := strings.TrimPrefix(path, "/sobjects/Account/Tenarium_Tenant_Id__c/")
		switch r.Method {
		case http.MethodPatch:
			if body["Name"] == "" && f.records[id] == nil {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `[{"message":"Required fields are missing: [Name]","errorCode":"REQUIRED_FIELD_MISSING","fields":["Name"]}]`)
				return
			}
			if rec := f.records[id]; rec != nil {
				maps.Copy(rec, body)
				w.WriteHeader(http.StatusNoContent)
				return
			}
			f.records[id] = body
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"id":"001xx","success":true,"errors":[],"created":true}`)
		case http.MethodDelete:
			if f.records[id] == nil {
				w.WriteHeader(http.StatusNotFound)
				_, _ = io.WriteString(w, `[{"message":"not found","errorCode":"NOT_FOUND"}]`)
				return
			}
			delete(f.records, id)
			w.WriteHeader(http.StatusNoContent)
		}
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `[{"message":"bad path","errorCode":"NOT_FOUND"}]`)
	}
}

func (f *fakeSF) expireTokens() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.valid = map[string]bool{}
}

func (f *fakeSF) record(id string) map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return maps.Clone(f.records[id])
}

func (f *fakeSF) snapshot() ([]map[string]string, []apiCall) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]string(nil), f.tokenReqs...), append([]apiCall(nil), f.calls...)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func setup(t *testing.T, f *fakeSF, overrides map[string]any) (*Plugin, *sdktest.Registrar, *clock) {
	t.Helper()
	cfg := map[string]any{
		"login_url": f.srv.URL,
		"auth":      map[string]any{"flow": "client_credentials", "client_id": "cid", "client_secret": "secret"},
	}
	maps.Copy(cfg, overrides)
	reg := sdktest.NewRegistrar(cfg)
	clk := &clock{t: time.Date(2026, 10, 11, 8, 0, 0, 0, time.UTC)}
	p := &Plugin{now: clk.now}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return p, reg, clk
}

func deliver(t *testing.T, reg *sdktest.Registrar, e sdk.Event) {
	t.Helper()
	if err := reg.Deliver(context.Background(), "sync", e); err != nil {
		t.Fatalf("deliver %s: %v", e.Type, err)
	}
}

var tenant = sdk.Tenant{ID: "t-1", Slug: "acme", Name: "Acme", Plan: "pro", Status: sdk.StatusActive, Labels: map[string]string{"region": "eu"}}

func TestClientCredentialsUpsert(t *testing.T) {
	f := newFake(t)
	_, reg, _ := setup(t, f, map[string]any{"fields": map[string]string{
		"Name": "{{.Name}}", "Tenarium_Plan__c": "{{.Plan}}", "Region__c": `{{index .Labels "region"}}`, "Website": `{{index .Labels "site"}}`,
	}})
	e := sdktest.TenantEvent(sdk.EventTenantCreated, tenant)
	deliver(t, reg, e)
	deliver(t, reg, e) // redelivery updates the same record
	updated := tenant
	updated.Plan = "enterprise"
	deliver(t, reg, sdktest.TenantEvent(sdk.EventTenantPlanChanged, updated))

	rec := f.record("t-1")
	if rec["Name"] != "Acme" || rec["Tenarium_Plan__c"] != "enterprise" || rec["Region__c"] != "eu" {
		t.Fatalf("record = %v", rec)
	}
	if _, sent := rec["Website"]; sent {
		t.Fatal("empty value was sent")
	}
	tokens, calls := f.snapshot()
	if len(tokens) != 1 || tokens[0]["grant_type"] != "client_credentials" || tokens[0]["client_id"] != "cid" || tokens[0]["client_secret"] != "secret" {
		t.Fatalf("token requests = %v", tokens)
	}
	if len(calls) != 3 || calls[0].Method != http.MethodPatch || calls[0].Path != "/services/data/v62.0/sobjects/Account/Tenarium_Tenant_Id__c/t-1" || calls[0].Token != "tok-1" {
		t.Fatalf("calls = %+v", calls)
	}
}

func TestPathEscaping(t *testing.T) {
	f := newFake(t)
	_, reg, _ := setup(t, f, nil)
	tn := tenant
	tn.ID = "a/b c"
	_ = reg.Deliver(context.Background(), "sync", sdktest.TenantEvent(sdk.EventTenantCreated, tn))
	_, calls := f.snapshot()
	if calls[0].Path != "/services/data/v62.0/sobjects/Account/Tenarium_Tenant_Id__c/a%2Fb%20c" {
		t.Fatalf("path = %s", calls[0].Path)
	}
}

func TestRefreshOn401AndTTL(t *testing.T) {
	f := newFake(t)
	p, reg, clk := setup(t, f, map[string]any{"token_ttl": "30m"})
	deliver(t, reg, sdktest.TenantEvent(sdk.EventTenantCreated, tenant))
	f.expireTokens() // revoked or session timeout
	deliver(t, reg, sdktest.TenantEvent(sdk.EventTenantUpdated, tenant))
	tokens, calls := f.snapshot()
	if len(tokens) != 2 || len(calls) != 3 || calls[1].Token != "tok-1" || calls[2].Token != "tok-2" {
		t.Fatalf("tokens=%d calls=%+v", len(tokens), calls)
	}
	// After token_ttl a new token is fetched proactively.
	clk.add(31 * time.Minute)
	if err := p.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	if tokens, _ := f.snapshot(); len(tokens) != 3 {
		t.Fatalf("token requests = %d, want 3", len(tokens))
	}
}

func TestPersistent401IsAnError(t *testing.T) {
	f := newFake(t)
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/services/oauth2/token" {
			_, _ = io.WriteString(w, `{"access_token":"x","instance_url":"`+f.srv.URL+`"}`)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `[{"message":"Session expired or invalid","errorCode":"INVALID_SESSION_ID"}]`)
	})
	p, _, _ := setup(t, f, nil)
	if err := p.Health(context.Background()); err == nil || !strings.Contains(err.Error(), "INVALID_SESSION_ID") {
		t.Fatalf("health = %v", err)
	}
}

func TestTokenError(t *testing.T) {
	f := newFake(t)
	p, _, _ := setup(t, f, map[string]any{"auth": map[string]any{"flow": "client_credentials", "client_id": "cid", "client_secret": "wrong"}})
	if err := p.Health(context.Background()); err == nil || !strings.Contains(err.Error(), "get token") {
		t.Fatalf("health = %v", err)
	}
}

func TestInstanceURLOverride(t *testing.T) {
	f := newFake(t)
	api := newFake(t)
	api.valid["tok-1"] = true
	p, _, _ := setup(t, f, map[string]any{"instance_url": api.srv.URL + "/"})
	if err := p.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, calls := api.snapshot(); len(calls) != 1 || calls[0].Path != "/services/data/v62.0/limits" {
		t.Fatalf("calls = %+v", calls)
	}
}

func rsaKeyPEM(t *testing.T, pkcs8 bool) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if pkcs8 {
		der, _ := x509.MarshalPKCS8PrivateKey(key)
		return key, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}

func decodeSegment(t *testing.T, s string) map[string]any {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestJWTBearer(t *testing.T) {
	for _, pkcs8 := range []bool{false, true} {
		f := newFake(t)
		_, keyPEM := rsaKeyPEM(t, pkcs8)
		auth := map[string]any{"flow": "jwt_bearer", "client_id": "3MVG9", "username": "int@acme.com"}
		if pkcs8 {
			file := filepath.Join(t.TempDir(), "sf.key")
			if err := os.WriteFile(file, []byte(keyPEM), 0o600); err != nil {
				t.Fatal(err)
			}
			auth["private_key_file"] = file
		} else {
			auth["private_key"] = keyPEM
		}
		p, _, _ := setup(t, f, map[string]any{"auth": auth})
		if err := p.Health(context.Background()); err != nil {
			t.Fatal(err)
		}
		tokens, _ := f.snapshot()
		if len(tokens) != 1 || tokens[0]["grant_type"] != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			t.Fatalf("token request = %v", tokens)
		}
		parts := strings.Split(tokens[0]["assertion"], ".")
		if len(parts) != 3 {
			t.Fatalf("assertion = %q", tokens[0]["assertion"])
		}
		hdr, claims := decodeSegment(t, parts[0]), decodeSegment(t, parts[1])
		exp, _ := claims["exp"].(float64)
		if hdr["alg"] != "RS256" || claims["iss"] != "3MVG9" || claims["sub"] != "int@acme.com" || claims["aud"] != f.srv.URL ||
			time.Until(time.Unix(int64(exp), 0)) > 3*time.Minute {
			t.Fatalf("header = %v claims = %v", hdr, claims)
		}
	}
}

func TestOnDelete(t *testing.T) {
	f := newFake(t)
	_, keep, _ := setup(t, f, nil)
	deliver(t, keep, sdktest.TenantEvent(sdk.EventTenantCreated, tenant))
	deliver(t, keep, sdktest.TenantEvent(sdk.EventTenantDeleted, tenant))
	if f.record("t-1") == nil {
		t.Fatal("keep deleted the record")
	}

	_, del, _ := setup(t, f, map[string]any{"on_delete": "delete"})
	deliver(t, del, sdktest.TenantEvent(sdk.EventTenantDeleted, tenant))
	deliver(t, del, sdktest.TenantEvent(sdk.EventTenantDeleted, tenant)) // already gone
	if f.record("t-1") != nil {
		t.Fatal("record not deleted")
	}

	_, upd, _ := setup(t, f, map[string]any{
		"on_delete":      "update",
		"fields":         map[string]string{"Name": "{{.Name}}", "Status__c": "{{.Status}}"},
		"deleted_fields": map[string]string{"Status__c": "deleted"},
	})
	deliver(t, upd, sdktest.TenantEvent(sdk.EventTenantCreated, tenant))
	deliver(t, upd, sdktest.TenantEvent(sdk.EventTenantDeleted, tenant))
	if rec := f.record("t-1"); rec["Status__c"] != "deleted" || rec["Name"] != "Acme" {
		t.Fatalf("record = %v", rec)
	}
}

func TestAPIErrorsAreReported(t *testing.T) {
	f := newFake(t)
	_, reg, _ := setup(t, f, map[string]any{"fields": map[string]string{"Name": `{{index .Labels "missing"}}`}})
	err := reg.Deliver(context.Background(), "sync", sdktest.TenantEvent(sdk.EventTenantCreated, tenant))
	if err == nil || !strings.Contains(err.Error(), "REQUIRED_FIELD_MISSING") {
		t.Fatalf("err = %v", err)
	}
	_, reg2, _ := setup(t, f, map[string]any{"fields": map[string]string{"Name": "{{.Nope}}"}})
	if err := reg2.Deliver(context.Background(), "sync", sdktest.TenantEvent(sdk.EventTenantCreated, tenant)); err == nil {
		t.Fatal("template error not reported")
	}
}

func TestDefaults(t *testing.T) {
	f := newFake(t)
	p, reg, _ := setup(t, f, nil)
	if p.cfg.APIVersion != "v62.0" || p.cfg.ExternalIDField != "Tenarium_Tenant_Id__c" || p.cfg.SObject != "Account" ||
		p.cfg.OnDelete != "keep" || p.tokens.ttl != time.Hour || p.client.Timeout != 15*time.Second || len(p.fields) != 1 ||
		len(reg.Subscriptions) != 1 {
		t.Fatalf("defaults: %+v", p.cfg)
	}
	p2 := &Plugin{}
	if err := p2.Init(context.Background(), sdktest.NewRegistrar(map[string]any{
		"auth": map[string]any{"flow": "client_credentials", "client_id": "c", "client_secret": "s"},
	})); err != nil || p2.loginURL != "https://login.salesforce.com" {
		t.Fatalf("login url = %s, %v", p2.loginURL, err)
	}
}

func TestInitValidation(t *testing.T) {
	_, keyPEM := rsaKeyPEM(t, false)
	cc := map[string]any{"flow": "client_credentials", "client_id": "c", "client_secret": "s"}
	jb := func(kv ...any) map[string]any {
		m := map[string]any{"flow": "jwt_bearer", "client_id": "c", "username": "u", "private_key": keyPEM}
		for i := 0; i < len(kv); i += 2 {
			if kv[i+1] == nil {
				delete(m, kv[i].(string))
			} else {
				m[kv[i].(string)] = kv[i+1]
			}
		}
		return m
	}
	for name, cfg := range map[string]map[string]any{
		"no auth":           {},
		"bad flow":          {"auth": map[string]any{"flow": "password", "client_id": "c"}},
		"no client id":      {"auth": map[string]any{"flow": "client_credentials", "client_secret": "s"}},
		"no secret":         {"auth": map[string]any{"flow": "client_credentials", "client_id": "c"}},
		"cc with key":       {"auth": map[string]any{"flow": "client_credentials", "client_id": "c", "client_secret": "s", "private_key": keyPEM}},
		"jwt no username":   {"auth": jb("username", nil)},
		"jwt no key":        {"auth": jb("private_key", nil)},
		"jwt both keys":     {"auth": jb("private_key_file", "/k.pem")},
		"jwt bad key":       {"auth": jb("private_key", "not a key")},
		"jwt missing file":  {"auth": jb("private_key", nil, "private_key_file", "/nonexistent/key.pem")},
		"jwt secret":        {"auth": jb("client_secret", "s")},
		"bad login url":     {"auth": cc, "login_url": "login.salesforce.com"},
		"bad instance url":  {"auth": cc, "instance_url": "/x"},
		"bad version":       {"auth": cc, "api_version": "62"},
		"bad external id":   {"auth": cc, "external_id_field": "TenantId"},
		"bad sobject":       {"auth": cc, "sobject": "My-Object"},
		"bad field name":    {"auth": cc, "fields": map[string]string{"Bad Name": "x"}},
		"external in field": {"auth": cc, "fields": map[string]string{"Tenarium_Tenant_Id__c": "{{.ID}}"}},
		"bad template":      {"auth": cc, "fields": map[string]string{"Name": "{{.Name"}},
		"update no fields":  {"auth": cc, "on_delete": "update"},
		"deleted on keep":   {"auth": cc, "deleted_fields": map[string]string{"X__c": "y"}},
		"bad on_delete":     {"auth": cc, "on_delete": "archive"},
		"bad ttl":           {"auth": cc, "token_ttl": "10s"},
		"bad timeout":       {"auth": cc, "timeout": "x"},
		"unknown key":       {"auth": cc, "object": "Account"},
	} {
		if err := (&Plugin{}).Init(context.Background(), sdktest.NewRegistrar(cfg)); err == nil {
			t.Errorf("%s: config accepted", name)
		}
	}
}

func TestConfigSchema(t *testing.T) {
	sch, err := schema.Compile((&Plugin{}).Manifest().ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	for _, good := range []map[string]any{
		{
			"login_url": "https://test.salesforce.com", "instance_url": "https://acme.my.salesforce.com", "api_version": "v61.0",
			"auth":              map[string]any{"flow": "client_credentials", "client_id": "c", "client_secret": "s"},
			"external_id_field": "Tenant__c", "sobject": "Account", "fields": map[string]any{"Name": "{{.Name}}"},
			"on_delete": "update", "deleted_fields": map[string]any{"Status__c": "deleted"}, "token_ttl": "30m", "timeout": "10s",
		},
		{"auth": map[string]any{"flow": "jwt_bearer", "client_id": "c", "username": "u", "private_key_file": "/k.pem"}},
	} {
		if err := sch.Validate(good); err != nil {
			t.Fatalf("valid config rejected: %v", err)
		}
	}
	cc := map[string]any{"flow": "client_credentials", "client_id": "c", "client_secret": "s"}
	for _, bad := range []map[string]any{
		{},
		{"auth": map[string]any{"flow": "client_credentials", "client_id": "c"}},
		{"auth": map[string]any{"flow": "jwt_bearer", "client_id": "c", "username": "u"}},
		{"auth": map[string]any{"flow": "jwt_bearer", "client_id": "c", "username": "u", "private_key": "k", "private_key_file": "f"}},
		{"auth": map[string]any{"flow": "device", "client_id": "c"}},
		{"auth": cc, "on_delete": "update"},
		{"auth": cc, "external_id_field": "NoSuffix"},
		{"auth": cc, "api_version": "62.0"},
		{"auth": cc, "extra": true},
	} {
		if err := sch.Validate(bad); err == nil {
			t.Errorf("invalid config accepted: %v", bad)
		}
	}
}

func TestReconfigure(t *testing.T) {
	f := newFake(t)
	p, reg, _ := setup(t, f, nil)
	deliver(t, reg, sdktest.TenantEvent(sdk.EventTenantCreated, tenant))

	// Rotated secret and new templates: a fresh token is fetched with the new
	// credentials.
	cfg := map[string]any{
		"login_url": f.srv.URL,
		"auth":      map[string]any{"flow": "client_credentials", "client_id": "cid", "client_secret": "secret2"},
		"fields":    map[string]string{"Name": "New {{.Name}}"},
	}
	if err := p.Reconfigure(context.Background(), sdktest.NewRegistrar(cfg).Config); err != nil {
		t.Fatal(err)
	}
	deliver(t, reg, sdktest.TenantEvent(sdk.EventTenantUpdated, tenant))
	if rec := f.record("t-1"); rec["Name"] != "New Acme" {
		t.Fatalf("record = %v", rec)
	}
	tokens, calls := f.snapshot()
	if len(tokens) != 2 || tokens[1]["client_secret"] != "secret2" || calls[len(calls)-1].Token != "tok-2" {
		t.Fatalf("tokens = %v, calls = %+v", tokens, calls)
	}

	// Invalid config: rejected, the previous one stays.
	cfg["on_delete"] = "update"
	if err := p.Reconfigure(context.Background(), sdktest.NewRegistrar(cfg).Config); err == nil {
		t.Fatal("on_delete update without deleted_fields accepted")
	}
	renamed := tenant
	renamed.Name = "Acme 2"
	deliver(t, reg, sdktest.TenantEvent(sdk.EventTenantUpdated, renamed))
	if rec := f.record("t-1"); rec["Name"] != "New Acme 2" {
		t.Fatalf("record = %v", rec)
	}
	if tokens, _ := f.snapshot(); len(tokens) != 2 {
		t.Fatalf("token requests = %v", tokens)
	}
	// Nothing in the configuration is fixed at startup: the subscribed
	// events are not configurable.
}
