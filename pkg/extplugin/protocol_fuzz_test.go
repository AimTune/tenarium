package extplugin

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// FuzzDecodePrincipal decodes arbitrary X-Tenarium-Principal headers. A
// decoded principal must survive an encode/decode round trip unchanged.
func FuzzDecodePrincipal(f *testing.F) {
	f.Add(EncodePrincipal(&sdk.Principal{Subject: "alice", Kind: "user", TenantID: "t1", Roles: []string{"admin"}}))
	f.Add(EncodePrincipal(&sdk.Principal{}))
	f.Add("bnVsbA") // "null"
	f.Add("e30")    // "{}"
	f.Add("!!not base64")
	f.Add("eyJzdWJqZWN0IjoxfQ") // {"subject":1}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := DecodePrincipal(s)
		if err != nil {
			return
		}
		if p == nil {
			t.Fatal("nil principal without error")
		}
		p2, err := DecodePrincipal(EncodePrincipal(p))
		if err != nil {
			t.Fatalf("re-decode: %v", err)
		}
		// Compare encodings: [] and {} legitimately decode back as nil (omitempty).
		if e1, e2 := EncodePrincipal(p), EncodePrincipal(p2); e1 != e2 && !reflect.DeepEqual(p, p2) {
			t.Fatalf("round trip changed principal:\n%+v\n%+v", p, p2)
		}
	})
}

// FuzzEventFromCloudEvent decodes arbitrary CloudEvent bodies as a plugin
// receives them on /events/{subscription}.
func FuzzEventFromCloudEvent(f *testing.F) {
	ev := sdk.Event{Seq: 42, ID: "e1", Type: sdk.EventTenantCreated, Source: "tenarium", TenantID: "t1",
		Data:        json.RawMessage(`{"tenant":{"id":"t1"}}`),
		TraceParent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", TraceState: "vendor=x"}
	b, _ := json.Marshal(ev.CloudEvent())
	f.Add(b)
	f.Add([]byte(`{"specversion":"1.0","sequence":"-1","time":"not a time","data":null}`))
	f.Add([]byte(`{"sequence":"99999999999999999999999","data":[1,2,3]}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		var ce sdk.CloudEvent
		if json.Unmarshal(body, &ce) != nil {
			return
		}
		e := EventFromCloudEvent(ce)
		if e.ID != ce.ID || e.Type != ce.Type || e.TenantID != ce.TenantID ||
			e.TraceParent != ce.TraceParent || e.TraceState != ce.TraceState {
			t.Fatalf("fields lost: %+v from %+v", e, ce)
		}
		// Re-encoding must not panic.
		_, _ = json.Marshal(e.CloudEvent())
	})
}

// fuzzPlugin registers one of every extension point; none of them fail,
// so any 5xx from the handler is a protocol handling bug.
type fuzzPlugin struct{}

func (fuzzPlugin) Manifest() sdk.Manifest {
	return sdk.Manifest{ID: "fuzz", Name: "Fuzz", Version: "0"}
}
func (fuzzPlugin) Init(_ context.Context, r sdk.Registrar) error {
	r.Subscribe("sub", sdk.EventFilter{}, func(context.Context, sdk.Event) error { return nil })
	r.Hook(sdk.HookBeforeTenantCreate, func(_ context.Context, req *sdk.HookRequest) error {
		if req.Tenant != nil && req.Tenant.Slug == "reject" {
			return sdk.Reject("no")
		}
		return nil
	})
	r.Provisioner(fuzzProvisioner{})
	r.Authorizer(fuzzAuthorizer{})
	r.Authenticator(fuzzAuthenticator{})
	r.UserDirectory(fuzzDirectory{})
	r.Mailer(fuzzMailer{})
	r.Route("GET /hello", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := sdk.PrincipalFrom(r.Context())
		_ = json.NewEncoder(w).Encode(p)
	}))
	return nil
}

type fuzzProvisioner struct{}

func (fuzzProvisioner) Name() string                                  { return "prov" }
func (fuzzProvisioner) Provision(context.Context, sdk.Tenant) error   { return nil }
func (fuzzProvisioner) Deprovision(context.Context, sdk.Tenant) error { return nil }

type fuzzAuthorizer struct{}

func (fuzzAuthorizer) Name() string { return "authz" }
func (fuzzAuthorizer) Authorize(context.Context, *sdk.Principal, sdk.Action, sdk.Resource) (sdk.Decision, error) {
	return sdk.Allow, nil
}

type fuzzAuthenticator struct{}

func (fuzzAuthenticator) Name() string { return "authn" }
func (fuzzAuthenticator) Authenticate(_ context.Context, r *http.Request) (*sdk.Principal, error) {
	if u := r.Header.Get("X-User"); u != "" {
		return &sdk.Principal{Subject: u}, nil
	}
	return nil, sdk.ErrNoCredentials
}

type fuzzDirectory struct{}

func (fuzzDirectory) Name() string                                         { return "dir" }
func (fuzzDirectory) CreateUser(context.Context, sdk.User) (string, error) { return "ext", nil }
func (fuzzDirectory) UpdateUser(context.Context, sdk.User) error           { return nil }
func (fuzzDirectory) DeleteUser(context.Context, sdk.User) error           { return nil }
func (fuzzDirectory) SetPassword(context.Context, sdk.User, string) error  { return nil }
func (fuzzDirectory) VerifyPassword(context.Context, sdk.User, string) error {
	return nil
}
func (fuzzDirectory) SendInvitation(context.Context, sdk.User) error { return nil }

type fuzzMailer struct{}

func (fuzzMailer) Name() string                            { return "mail" }
func (fuzzMailer) Send(context.Context, sdk.Message) error { return nil }

// New paths are appended so existing corpus entries keep their target.
var protocolPaths = []string{
	"/init", "/events/sub", "/events/unknown", "/hooks/" + string(sdk.HookBeforeTenantCreate), "/hooks/bogus",
	"/provisioners/prov/provision", "/provisioners/prov/deprovision", "/provisioners/prov/explode",
	"/provisioners/nope/provision", "/authorize/authz", "/authorize/nope", "/authenticate/authn",
	"/authenticate/nope", "/health", "/routes/hello", "/routes/missing",
	"/directory/create_user", "/directory/update_user", "/directory/delete_user", "/directory/set_password",
	"/directory/verify_password", "/directory/send_invitation", "/directory/explode", "/mailer/send",
}

// FuzzHandler sends arbitrary bodies, methods and principal headers to
// every endpoint of an initialised plugin. The handler must not panic and
// must not answer 5xx: the fuzz plugin never fails, so a 5xx can only come
// from the protocol layer.
func FuzzHandler(f *testing.F) {
	init := []byte(`{"protocol":1,"instance":"fz","config":{}}`)
	f.Add(uint8(0), "POST", init, "")
	f.Add(uint8(1), "POST", []byte(`{"specversion":"1.0","id":"e1","type":"tenant.created","sequence":"1"}`), "")
	f.Add(uint8(3), "POST", []byte(`{"tenant":{"slug":"reject","name":"x"}}`), "")
	f.Add(uint8(5), "POST", []byte(`{"id":"t1","slug":"acme"}`), "")
	f.Add(uint8(9), "POST", []byte(`{"principal":{"subject":"a"},"action":"tenants:read","resource":{"type":"tenant"}}`), "")
	f.Add(uint8(11), "POST", []byte(`{"method":"GET","path":"/v1/tenants","headers":{"X-User":["bob"]}}`), "")
	f.Add(uint8(11), "POST", []byte(`{"method":"GET","path":"/v1/me","headers":null}`), "")
	f.Add(uint8(14), "GET", []byte{}, EncodePrincipal(&sdk.Principal{Subject: "alice"}))
	f.Add(uint8(14), "GET", []byte{}, "%%%")
	f.Add(uint8(0), "POST", []byte(`{"protocol":2}`), "")
	f.Add(uint8(2), "PUT", []byte(`[]`), "")
	f.Add(uint8(16), "POST", []byte(`{"user":{"id":"u1","email":"a@b.c","status":"invited"}}`), "")
	f.Add(uint8(19), "POST", []byte(`{"user":{"external_id":"ext"},"password":"pw"}`), "")
	f.Add(uint8(20), "POST", []byte(`{"user":null,"password":7}`), "")
	f.Add(uint8(21), "POST", []byte(`{"user":{}}`), "")
	f.Add(uint8(23), "POST", []byte(`{"to":["a@b.c"],"subject":"s","text":"t","tag":"invitation"}`), "")
	f.Add(uint8(23), "POST", []byte(`{"to":"a@b.c"}`), "")

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	f.Fuzz(func(t *testing.T, which uint8, method string, body []byte, principal string) {
		h := NewHandler(fuzzPlugin{}, "", log)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", "/init", bytes.NewReader(init)))
		if rec.Code != http.StatusOK {
			t.Fatalf("init: %d %s", rec.Code, rec.Body)
		}
		switch method {
		case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		default:
			method = "POST"
		}
		path := protocolPaths[int(which)%len(protocolPaths)]
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		if principal != "" {
			req.Header.Set(PrincipalHeader, principal)
		}
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code >= 500 {
			t.Fatalf("%s %s %q: %d %s", method, path, body, rec.Code, rec.Body)
		}
	})
}
