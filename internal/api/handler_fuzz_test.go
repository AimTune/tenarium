package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/AimTune/tenarium/internal/tenant"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/server"
)

const fuzzAPIKey = "fuzz-key"

// fuzzRoutes are the request shapes the fuzzer explores. {id} is a live
// tenant (or the fuzzed segment), {seg} is always the fuzzed segment.
// Routes that make outbound calls (SSO metadata, webhook tests, DNS
// verification) are left out so the fuzzer stays hermetic.
var fuzzRoutes = []struct{ method, path string }{
	{"POST", "/v1/tenants"},
	{"PATCH", "/v1/tenants/{id}"},
	{"GET", "/v1/tenants"},
	{"POST", "/v1/tenants/{id}/members"},
	{"PATCH", "/v1/tenants/{id}/members/{seg}"},
	{"POST", "/v1/tenants/{id}/usage/{seg}"},
	{"GET", "/v1/tenants/{id}/usage/{seg}/history"},
	{"GET", "/v1/events"},
	{"GET", "/v1/audit"},
	{"GET", "/v1/tenants/{id}/audit"},
	{"POST", "/v1/plans"},
	{"PATCH", "/v1/plans/{seg}"},
	{"POST", "/v1/tenants/{id}/webhooks"},
	{"POST", "/v1/tenants/{id}/domains"},
	{"PUT", "/v1/tenants/{id}/roles/{seg}"},
	{"POST", "/v1/tenants/{id}/schedule"},
	{"POST", "/v1/tenants/{id}/api-keys"},
	{"GET", "/v1/tenants/{id}/scim/v2/Users"},
	{"POST", "/v1/tenants/{id}/scim/v2/Users"},
	{"PATCH", "/v1/tenants/{id}/scim/v2/Users/{seg}"},
	{"POST", "/v1/tenants/{id}/scim/v2/Groups"},
	{"POST", "/v1/users"},
	{"POST", "/v1/tenants/{id}/suspend"},
	{"POST", "/v1/tenants/{id}/groups"},
	{"POST", "/v1/auth/token"},
	{"GET", "/v1/tenants/{id}/entitlements"},
}

var fuzzMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE"}

type fuzzApp struct {
	app *server.App
	h   http.Handler
	n   int
}

var (
	fuzzOnce sync.Once
	fuzzSrv  *fuzzApp
	fuzzErr  error
)

// sharedApp builds one in-memory server per fuzz worker process.
func sharedApp() (*fuzzApp, error) {
	fuzzOnce.Do(func() {
		cfg := server.DefaultConfig()
		cfg.Server.APIKeys = []string{fuzzAPIKey}
		cfg.Auth.RateLimit = 0
		cfg.Usage.Metrics = map[string]tenant.MetricPolicy{"api_calls": {Period: "month", Overage: "block"}}
		cfg.Bootstrap.Plans = []server.BootstrapPlan{{ID: "free", Name: "Free", Limits: map[string]int64{"members": 5, "api_calls": 100}}}
		log := slog.New(slog.NewTextHandler(io.Discard, nil))
		noDNS := server.WithTXTResolver(func(context.Context, string) ([]string, error) { return nil, nil })
		app, err := server.New(context.Background(), cfg, log, noDNS)
		if err != nil {
			fuzzErr = err
			return
		}
		fuzzSrv = &fuzzApp{app: app, h: app.Handler()}
	})
	return fuzzSrv, fuzzErr
}

// liveTenant returns the ID of an active tenant, creating a new one when
// fuzzed requests suspended or deleted the previous one.
func (a *fuzzApp) liveTenant(t *testing.T) string {
	ctx := context.Background()
	slug := fmt.Sprintf("fuzz-%d", a.n)
	if tn, err := a.app.Tenants().Get(ctx, slug); err == nil && tn.Status == sdk.StatusActive {
		return tn.ID
	}
	a.n++
	slug = fmt.Sprintf("fuzz-%d", a.n)
	tn, err := a.app.Tenants().Create(ctx, tenant.CreateInput{Slug: slug, Name: "Fuzz", Plan: "free"})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	return tn.ID
}

// FuzzHandler sends arbitrary methods, path segments, queries, bodies and
// headers through the full API handler (auth, idempotency, routing,
// decoding, validation, service, memory store). It must never panic and
// never answer 5xx: the memory store does not fail, so a 5xx means an
// error the API failed to map (or a bug).
func FuzzHandler(f *testing.F) {
	type seed struct {
		route        uint8
		method       uint8
		useSeg       bool
		seg, query   string
		body         string
		auth, ifm    string
		idempotencyK string
	}
	for _, s := range []seed{
		{0, 0, false, "", "", `{"slug":"acme","name":"Acme","labels":{"env":"prod"},"settings":{"a":{"b":1}}}`, "", "", "k1"},
		{0, 0, false, "", "", `{"slug":"kid","name":"Kid","parent_id":"nope"}`, "", "", ""},
		{1, 0, false, "", "", `{"settings":{"a":null},"name":"N"}`, "", `"1"`, ""},
		{1, 0, true, "acme", "", `{"plan":"nope"}`, "", `W/"x"`, ""},
		{2, 0, false, "", "status=active&label=env=prod&limit=0&after=zzz", "", "", "", ""},
		{3, 0, false, "", "", `{"email":"bob@example.com","role":"member"}`, "", "", ""},
		{3, 0, false, "", "", `{"email":"Bob <bob@example.com>","role":"admin"}`, "", "", ""},
		{4, 0, false, "x", "", `{"role":"admin","active":false}`, "", "", ""},
		{5, 0, false, "api_calls", "", `{"delta":9223372036854775807}`, "", "", ""},
		{5, 0, false, "api_calls", "", `{"delta":-5}`, "", "", ""},
		{6, 0, false, "api_calls", "limit=400", "", "", "", ""},
		{7, 0, false, "", "after=-1&limit=1000&type=tenant.*", "", "", "", ""},
		{8, 0, false, "", "tenant_id=fuzz-1&type=tenant.created&since=2020-01-01T00:00:00Z&limit=1", "", "", "", ""},
		{9, 0, false, "", "before=abc", "", "", "", ""},
		{10, 0, false, "", "", `{"id":"pro","name":"Pro","limits":{"members":-1}}`, "", "", ""},
		{11, 0, false, "pro", "", `{"features":null}`, "", "", ""},
		{12, 0, false, "", "", `{"url":"https://127.0.0.1/hook","types":["["]}`, "", "", ""},
		{12, 0, false, "", "", `{"url":"https://LOCALHOST/hook"}`, "", "", ""},
		{13, 0, false, "", "", `{"hostname":"Example.COM."}`, "", "", ""},
		{14, 0, false, "editor", "", `{"actions":["tenants:read","*"]}`, "", "", ""},
		{15, 0, false, "", "", `{"action":"suspend","at":"2000-01-01T00:00:00Z"}`, "", "", ""},
		{16, 0, false, "", "", `{"name":"ci","role":"admin","expires_at":"1999-01-01T00:00:00Z"}`, "", "", ""},
		{17, 0, false, "", `filter=userName%20eq%20"a@b.c"&startIndex=-1&count=99999`, "", "", "", ""},
		{18, 0, false, "", "", `{"userName":"a@b.c","emails":[{"value":"a@b.c","primary":true}],"active":"yes"}`, "", "", ""},
		{19, 0, false, "nope", "", `{"Operations":[{"op":"replace","path":"active","value":"False"}]}`, "", "", ""},
		{20, 0, false, "", "", `{"displayName":"Admins","members":[{"value":"x"}]}`, "", "", ""},
		{21, 0, false, "", "", `{"email":"u@example.com","name":"U","roles":["admin"],"password":"short"}`, "", "", ""},
		{22, 0, false, "", "", `{"reason":"` + strings.Repeat("r", 600) + `"}`, "", "", ""},
		{24, 0, false, "", "", `{"grant_type":"password","username":"x@y.z","password":"p"}`, "none", "", ""},
		{24, 0, false, "", "", `{"grant_type":"refresh_token","refresh_token":"a.b.c"}`, "none", "", ""},
		{25, 0, false, "", "", "", "Bearer eyJhbGciOiJub25lIn0.e30.", "", ""},
		{0, 0, false, "", "", `{"slug":"a","name":"b"}{"extra":1}`, "", "", strings.Repeat("k", 256)},
		{1, 3, true, "../../v1/plans", "", "", "", "", ""},
	} {
		f.Add(s.route, s.method, s.useSeg, s.seg, s.query, []byte(s.body), s.auth, s.ifm, s.idempotencyK)
	}

	f.Fuzz(func(t *testing.T, route, method uint8, useSeg bool, seg, query string, body []byte, auth, ifMatch, idemKey string) {
		a, err := sharedApp()
		if err != nil {
			t.Fatal(err)
		}
		rt := fuzzRoutes[int(route)%len(fuzzRoutes)]
		m := rt.method
		if method >= 200 { // occasionally use another method on the route
			m = fuzzMethods[int(method)%len(fuzzMethods)]
		}
		id := a.liveTenant(t)
		if useSeg {
			id = seg
		}
		p := strings.ReplaceAll(rt.path, "{id}", url.PathEscape(id))
		p = strings.ReplaceAll(p, "{seg}", url.PathEscape(seg))
		u, err := url.Parse(p)
		if err != nil {
			return
		}
		u.RawQuery = query
		req := httptest.NewRequest("GET", "/", bytes.NewReader(body))
		req.Method, req.URL, req.RequestURI = m, u, u.RequestURI()
		req.Header.Set("Content-Type", "application/json")
		switch auth {
		case "":
			req.Header.Set("Authorization", "Bearer "+fuzzAPIKey)
		case "none":
		default:
			req.Header.Set("Authorization", auth)
		}
		if ifMatch != "" {
			req.Header.Set("If-Match", ifMatch)
		}
		if idemKey != "" {
			req.Header.Set("Idempotency-Key", idemKey)
		}
		rec := httptest.NewRecorder()
		a.h.ServeHTTP(rec, req)
		if rec.Code >= 500 {
			t.Fatalf("%s %s body=%q auth=%q if-match=%q: %d %s", m, u, body, auth, ifMatch, rec.Code, rec.Body)
		}
		if strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") && rec.Body.Len() > 0 && !json.Valid(rec.Body.Bytes()) {
			t.Fatalf("%s %s: invalid JSON response %q", m, u, rec.Body)
		}
	})
}
