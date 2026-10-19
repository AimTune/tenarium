package external

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

// fakeRemote is a plugin endpoint whose answers the fuzzer controls. Fuzz
// functions run sequentially within a worker process, so one server per
// target is enough.
type fakeRemote struct {
	mu     sync.Mutex
	init   []byte
	reply  []byte
	status int
}

func (f *fakeRemote) set(init, reply []byte, status int) {
	f.mu.Lock()
	f.init, f.reply, f.status = init, reply, status
	f.mu.Unlock()
}

func (f *fakeRemote) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	init, reply, status := f.init, f.reply, f.status
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/health":
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	case r.URL.Path == "/init":
		_, _ = w.Write(init)
	default:
		w.WriteHeader(status)
		_, _ = w.Write(reply)
	}
}

// fuzzRegistrar records registrations like the server's registrar, without
// mounting routes (which is checked separately below).
type fuzzRegistrar struct {
	*sdktest.Registrar
}

func (r fuzzRegistrar) Route(pattern string, _ http.Handler) {
	r.Routes = append(r.Routes, pattern)
}

// mountable reports whether api.Server would accept the plugin's routes:
// it mounts every pattern of an instance into one ServeMux, which panics
// on invalid or conflicting patterns.
func mountable(patterns []string) (err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("%v", rec)
		}
	}()
	mux := http.NewServeMux()
	for _, p := range patterns {
		mux.Handle(p, http.NotFoundHandler())
	}
	return nil
}

func newFuzzPlugin(t *testing.T, url string) (*Plugin, *fuzzRegistrar, error) {
	t.Helper()
	reg := &fuzzRegistrar{sdktest.NewRegistrar(map[string]any{
		"url": url, "secret": "s", "startup_timeout": "2s", "request_timeout": "2s",
	})}
	p := &Plugin{}
	err := p.Init(context.Background(), reg)
	return p, reg, err
}

// FuzzInitResponse plays a misbehaving plugin answering /init with
// arbitrary JSON. Tenarium must either refuse the plugin with an error or
// register something it can actually serve: an init response must not be
// able to crash the server when the API mounts the plugin's routes.
func FuzzInitResponse(f *testing.F) {
	f.Add([]byte(`{"protocol":1,"manifest":{"id":"x","name":"X","version":"1"},"subscriptions":[{"name":"s","types":["tenant.*"],"max_attempts":3,"timeout_ms":100}],"hooks":[{"point":"before_tenant_create","priority":1}],"provisioners":["p"],"routes":["GET /stats","/things/{id}"],"authenticators":["a"],"authorizers":["z"]}`))
	f.Add([]byte(`{"protocol":2}`))
	f.Add([]byte(`{"protocol":1,"routes":["GET /a","POST /a"]}`))
	f.Add([]byte(`{"protocol":1,"subscriptions":[{"name":"../x","timeout_ms":-1}]}`))
	f.Add([]byte(`{"protocol":1,"hooks":[{"point":""}]}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"protocol":1,"manifest":null,"routes":null}`))
	f.Add([]byte(`{"protocol":1,"manifest":{"id":"x"},"user_directory":{"name":"d","verify_password":true,"send_invitation":true},"mailer":{"name":"m"}}`))
	f.Add([]byte(`{"protocol":1,"user_directory":{},"mailer":{}}`))
	f.Add([]byte(`{"protocol":1,"user_directory":{"name":"\u0000"},"mailer":{"name":" "}}`))
	f.Add([]byte(`{"protocol":1,"user_directory":null,"mailer":[]}`))

	remote := &fakeRemote{status: http.StatusOK, reply: []byte(`{}`)}
	// Plugin.Init builds its own client on http.DefaultTransport; serve it
	// in memory so thousands of inits per second do not exhaust ephemeral
	// ports (the health check does not drain its response body, so every
	// call would open a new connection). No test in this package runs in
	// parallel, so swapping the default transport is safe here.
	orig := http.DefaultTransport
	http.DefaultTransport = inMemory{remote}
	f.Cleanup(func() { http.DefaultTransport = orig })
	f.Fuzz(func(t *testing.T, initBody []byte) {
		remote.set(initBody, []byte(`{}`), http.StatusOK)
		p, reg, err := newFuzzPlugin(t, "http://plugin.test")
		if err != nil {
			return // refused cleanly
		}
		if err := mountable(reg.Routes); err != nil {
			t.Fatalf("plugin accepted with routes %q that crash route mounting: %v", reg.Routes, err)
		}
		if d := reg.Directory; d != nil {
			if err := validIdentifier(d.Name(), maxNameLen); err != nil {
				t.Fatalf("directory accepted with name %q: %v", d.Name(), err)
			}
		}
		if m := reg.MailerImpl; m != nil {
			if err := validIdentifier(m.Name(), maxNameLen); err != nil {
				t.Fatalf("mailer accepted with name %q: %v", m.Name(), err)
			}
		}
		_ = p.Manifest()
	})
}

// inMemory serves the plugin's HTTP calls without sockets, so the fuzzer
// does not exhaust ephemeral ports (each reply may leave a connection
// unusable).
type inMemory struct{ h http.Handler }

func (m inMemory) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	m.h.ServeHTTP(rec, r)
	resp := rec.Result()
	resp.Request = r
	return resp, nil
}

// FuzzRemoteReplies plays a plugin answering hooks, authentication,
// authorization, user directory and mailer calls with arbitrary bodies and
// statuses. The host side must turn every reply into a result or an error,
// never a panic; an authenticator must never report success without a
// principal, a directory must never return an invalid external ID, and no
// call may succeed on a non-2xx status (in particular, a password check).
func FuzzRemoteReplies(f *testing.F) {
	f.Add([]byte(`{"reject":"no"}`), 200)
	f.Add([]byte(`{"tenant":{"slug":"changed","name":"C"},"member":{"email":"a@b.c"}}`), 200)
	f.Add([]byte(`{"principal":{"subject":"alice"}}`), 200)
	f.Add([]byte(`{"no_credentials":true}`), 200)
	f.Add([]byte(`{"error":"bad token"}`), 200)
	f.Add([]byte(`{"decision":"allow"}`), 200)
	f.Add([]byte(`{"principal":null}`), 200)
	f.Add([]byte(`{"error":"boom"}`), 500)
	f.Add([]byte(``), 204)
	f.Add([]byte(`[1,2`), 200)
	f.Add([]byte(`{"external_id":"ext-1"}`), 200)
	f.Add([]byte(`{"external_id":""}`), 200)
	f.Add([]byte(`{"external_id":"a\u0007b"}`), 200)
	f.Add([]byte(`{"error":"gone","code":"not_found"}`), 404)
	f.Add([]byte(`{"error":"bad password","code":"invalid_credentials"}`), 403)
	f.Add([]byte(`{"code":"unsupported"}`), 501)

	remote := &fakeRemote{status: http.StatusOK, reply: []byte(`{}`), init: []byte(`{"protocol":1,"manifest":{"id":"x","name":"X","version":"1"},` +
		`"hooks":[{"point":"before_tenant_create"}],"authenticators":["a"],"authorizers":["z"],` +
		`"user_directory":{"verify_password":true,"send_invitation":true},"mailer":{}}`)}
	srv := httptest.NewServer(remote)
	f.Cleanup(srv.Close)
	var (
		once sync.Once
		reg  *fuzzRegistrar
	)
	f.Fuzz(func(t *testing.T, body []byte, status int) {
		once.Do(func() {
			p, r, err := newFuzzPlugin(t, srv.URL)
			if err != nil {
				t.Fatalf("init: %v", err)
			}
			p.client = &http.Client{Transport: inMemory{remote}}
			reg = r
		})
		if reg == nil {
			t.Skip("init failed in an earlier run")
		}
		if status < 200 || status > 599 {
			status = 200
		}
		remote.set(remote.init, body, status)
		ctx := context.Background()
		tn := &sdk.Tenant{Slug: "acme", Name: "Acme"}
		_ = reg.Hooks[0].Handler(ctx, &sdk.HookRequest{Point: sdk.HookBeforeTenantCreate, Tenant: tn})
		req := httptest.NewRequest("GET", "/v1/tenants?x=1", nil)
		req.Header.Set("Authorization", "Bearer caller")
		pr, err := reg.Authenticators[0].Authenticate(ctx, req)
		if err == nil && pr == nil {
			t.Fatalf("authenticator succeeded without a principal for %d %q", status, body)
		}
		d, err := reg.Authorizers[0].Authorize(ctx, &sdk.Principal{Subject: "u"}, sdk.ActionTenantsRead, sdk.Resource{Type: "tenant"})
		if err != nil && d != sdk.Abstain {
			t.Fatalf("authorizer error with decision %v", d)
		}
		if status >= 300 && d == sdk.Allow {
			t.Fatalf("authorizer allowed on HTTP %d", status)
		}

		u := sdk.User{ID: "u1", Email: "a@b.c", ExternalID: "ext-1"}
		id, err := reg.Directory.CreateUser(ctx, u)
		if err == nil {
			if verr := validIdentifier(id, maxExternalIDLen); verr != nil {
				t.Fatalf("directory returned invalid external id %q: %v", id, verr)
			}
		}
		errs := []error{
			err,
			reg.Directory.UpdateUser(ctx, u),
			reg.Directory.DeleteUser(ctx, u),
			reg.Directory.SetPassword(ctx, u, "pw"),
			reg.Directory.(sdk.PasswordVerifier).VerifyPassword(ctx, u, "pw"),
			reg.Directory.(sdk.InvitationSender).SendInvitation(ctx, u),
			reg.MailerImpl.Send(ctx, sdk.Message{To: []string{"a@b.c"}, Subject: "s"}),
		}
		for i, err := range errs {
			if status >= 300 && err == nil {
				t.Fatalf("directory/mailer call %d succeeded on HTTP %d", i, status)
			}
		}
	})
}
