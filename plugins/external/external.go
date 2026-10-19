// Package external hosts out-of-process plugins written in any language
// (see pkg/extplugin for the protocol). It runs in one of two modes:
//
//   - remote: the plugin is already running somewhere (url).
//   - managed: Tenarium starts the plugin process (command), hands it an
//     address and a secret, captures its output, and restarts it if it
//     crashes, re-initialising it with the same configuration.
//
// Whatever the remote plugin registers in its init response (event
// subscriptions, hooks, provisioners, routes, authenticators, authorizers,
// a user directory and a mailer) is registered in Tenarium as if it were a
// built-in plugin.
package external

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AimTune/tenarium/pkg/extplugin"
	"github.com/AimTune/tenarium/pkg/sdk"
)

func init() {
	sdk.Register("external", func() sdk.Plugin { return &Plugin{} })
}

type Config struct {
	// URL of a running plugin (remote mode).
	URL string `json:"url"`
	// Command starts the plugin (managed mode), e.g. ["node", "plugin.ts"].
	Command []string          `json:"command"`
	Env     map[string]string `json:"env"`
	// InheritEnv names extra environment variables the managed process may
	// see. By default it only gets a minimal set (PATH, HOME, ...), so
	// Tenarium's own secrets do not leak into plugins.
	InheritEnv []string `json:"inherit_env"`
	Dir        string   `json:"dir"`
	// Secret authenticates Tenarium to the plugin in remote mode. Managed
	// processes get a fresh random secret on every start.
	Secret string `json:"secret"`
	// Config is passed to the plugin's init.
	Config         map[string]any `json:"config"`
	StartupTimeout string         `json:"startup_timeout"`
	RequestTimeout string         `json:"request_timeout"`
}

var configSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "url": {"type": "string", "format": "uri"},
    "command": {"type": "array", "items": {"type": "string"}, "minItems": 1},
    "env": {"type": "object", "additionalProperties": {"type": "string"}},
    "inherit_env": {"type": "array", "items": {"type": "string"}},
    "dir": {"type": "string"},
    "secret": {"type": "string"},
    "config": {"type": "object"},
    "startup_timeout": {"type": "string"},
    "request_timeout": {"type": "string"}
  },
  "oneOf": [{"required": ["url", "secret"]}, {"required": ["command"]}],
  "additionalProperties": false
}`)

type Plugin struct {
	cfg      Config
	base     *url.URL
	client   *http.Client
	log      *slog.Logger
	instance string
	proc     *process
	// ready is false while a managed process restarts, until its new
	// instance has proven its identity; no calls are made meanwhile.
	ready atomic.Bool

	mu       sync.RWMutex
	manifest sdk.Manifest
	initResp extplugin.InitResponse
}

func (p *Plugin) Manifest() sdk.Manifest {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.manifest.ID != "" {
		return p.manifest
	}
	return sdk.Manifest{
		ID: "external", Name: "External Plugin", Version: "0.1.0",
		Description:  "Hosts an out-of-process plugin over HTTP/JSON.",
		ConfigSchema: configSchema,
	}
}

func (p *Plugin) Init(ctx context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	p.log, p.instance = r.Logger(), r.InstanceName()
	startup, err := duration(p.cfg.StartupTimeout, 30*time.Second)
	if err != nil {
		return fmt.Errorf("startup_timeout: %w", err)
	}
	reqTimeout, err := duration(p.cfg.RequestTimeout, 30*time.Second)
	if err != nil {
		return fmt.Errorf("request_timeout: %w", err)
	}
	p.client = &http.Client{Timeout: reqTimeout}

	if len(p.cfg.Command) > 0 {
		p.proc = &process{cfg: p.cfg, log: p.log, onRestart: p.reinit, onExit: func() { p.ready.Store(false) }}
		addr, err := p.proc.start()
		if err != nil {
			return err
		}
		p.cfg.URL = "http://" + addr
	}
	if p.base, err = url.Parse(strings.TrimRight(p.cfg.URL, "/")); err != nil || p.base.Host == "" {
		return fmt.Errorf("invalid url %q", p.cfg.URL)
	}

	if err := p.waitHealthy(ctx, startup); err != nil {
		return err
	}
	resp, err := p.callInit(ctx)
	if err != nil {
		return err
	}
	if err := validRoutes(resp.Routes); err != nil {
		return fmt.Errorf("plugin declared an invalid route: %w", err)
	}
	if err := p.validServices(&resp); err != nil {
		return err
	}
	p.register(r, resp)
	return nil
}

// secret returns the bearer secret for the current plugin process.
func (p *Plugin) secret() string {
	if p.proc != nil {
		s, _ := p.proc.credentials()
		return s
	}
	return p.cfg.Secret
}

func (p *Plugin) callInit(ctx context.Context) (extplugin.InitResponse, error) {
	var resp extplugin.InitResponse
	nonce := randomSecret()
	req := extplugin.InitRequest{Protocol: extplugin.ProtocolVersion, Instance: p.instance, Config: p.cfg.Config, Nonce: nonce}
	if err := p.post(ctx, "/init", req, &resp); err != nil {
		return resp, fmt.Errorf("plugin init: %w", err)
	}
	if resp.Protocol != extplugin.ProtocolVersion {
		return resp, fmt.Errorf("plugin speaks protocol %d, want %d", resp.Protocol, extplugin.ProtocolVersion)
	}
	if p.proc != nil {
		_, key := p.proc.credentials()
		if !hmac.Equal([]byte(resp.Proof), []byte(extplugin.Proof(key, nonce))) {
			return resp, errors.New("plugin did not prove its identity; another process may be listening on its address")
		}
	}
	resp.Proof = ""
	p.mu.Lock()
	p.manifest, p.initResp = resp.Manifest, resp
	p.mu.Unlock()
	p.ready.Store(true)
	return resp, nil
}

// reinit runs after a managed process restarts. Registrations are fixed at
// startup, so a plugin that changes them needs a Tenarium restart.
func (p *Plugin) reinit(ctx context.Context) {
	if err := p.waitHealthy(ctx, 30*time.Second); err != nil {
		p.log.Error("restarted plugin not healthy", "err", err)
		return
	}
	p.mu.RLock()
	before, _ := json.Marshal(p.initResp)
	p.mu.RUnlock()
	resp, err := p.callInit(ctx)
	if err != nil {
		p.log.Error("re-initialising restarted plugin", "err", err)
		return
	}
	if after, _ := json.Marshal(resp); !bytes.Equal(before, after) {
		p.log.Warn("restarted plugin changed its registrations; restart Tenarium to apply them")
	}
}

func (p *Plugin) register(r sdk.Registrar, resp extplugin.InitResponse) {
	for _, s := range resp.Subscriptions {
		opts := []sdk.SubscribeOption{}
		if s.MaxAttempts > 0 {
			opts = append(opts, sdk.WithMaxAttempts(s.MaxAttempts))
		}
		if s.StartAtEnd {
			opts = append(opts, sdk.WithStartAtEnd())
		}
		if s.TimeoutMS > 0 {
			timeout := time.Duration(s.TimeoutMS) * time.Millisecond
			opts = append(opts, func(o *sdk.SubscribeOptions) { o.Timeout = timeout })
		}
		path := "/events/" + url.PathEscape(s.Name)
		r.Subscribe(s.Name, sdk.EventFilter{Types: s.Types}, func(ctx context.Context, e sdk.Event) error {
			return p.call(ctx, path, e.CloudEvent(), nil)
		}, opts...)
	}
	for _, h := range resp.Hooks {
		path := "/hooks/" + url.PathEscape(string(h.Point))
		r.Hook(h.Point, func(ctx context.Context, req *sdk.HookRequest) error {
			var out extplugin.HookResponse
			if err := p.call(ctx, path, req, &out); err != nil {
				return err
			}
			if out.Reject != "" {
				return sdk.Reject("%s", out.Reject)
			}
			if out.Tenant != nil && req.Tenant != nil {
				*req.Tenant = *out.Tenant
			}
			if out.Member != nil && req.Member != nil {
				*req.Member = *out.Member
			}
			if out.User != nil && req.User != nil {
				*req.User = *out.User
			}
			return nil
		}, sdk.WithPriority(h.Priority))
	}
	for _, name := range resp.Provisioners {
		r.Provisioner(&provisioner{p: p, name: name})
	}
	if len(resp.Routes) > 0 {
		proxy := p.routeProxy()
		for _, pattern := range resp.Routes {
			r.Route(pattern, proxy)
		}
	}
	for _, name := range resp.Authenticators {
		r.Authenticator(&authenticator{p: p, name: name})
	}
	for _, name := range resp.Authorizers {
		r.Authorizer(&authorizer{p: p, name: name})
	}
	if d := resp.UserDirectory; d != nil {
		r.UserDirectory(newDirectory(p, *d))
	}
	if m := resp.Mailer; m != nil {
		r.Mailer(&mailer{p: p, name: m.Name})
	}
}

// routeProxy forwards plugin routes to {url}/routes/..., replacing the
// caller's credentials with the plugin secret and the resolved principal.
func (p *Plugin) routeProxy() http.Handler {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(p.base)
			pr.Out.URL.Path = p.base.Path + "/routes" + pr.In.URL.Path
			pr.Out.URL.RawPath = ""
			pr.Out.Header.Set("Authorization", "Bearer "+p.secret())
			pr.Out.Header.Del(extplugin.PrincipalHeader)
			if pl, ok := sdk.PrincipalFrom(pr.In.Context()); ok {
				pr.Out.Header.Set(extplugin.PrincipalHeader, extplugin.EncodePrincipal(pl))
			}
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			p.log.Warn("plugin route proxy", "err", err)
			http.Error(w, "plugin unavailable", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !p.ready.Load() {
			http.Error(w, errNotReady.Error(), http.StatusServiceUnavailable)
			return
		}
		proxy.ServeHTTP(w, r)
	})
}

func (p *Plugin) waitHealthy(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for {
		if last = p.Health(ctx); last == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("plugin at %s not healthy after %s: %w", p.base, timeout, last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func (p *Plugin) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.base.String()+"/health", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.secret())
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		// Drain so the connection is reused.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
	}()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("health: %s", readError(resp))
	}
	return nil
}

func (p *Plugin) Stop(ctx context.Context) error {
	if p.proc != nil {
		return p.proc.shutdown(ctx)
	}
	return nil
}

var errNotReady = errors.New("external plugin is restarting")

// call POSTs to a ready plugin.
func (p *Plugin) call(ctx context.Context, path string, in, out any) error {
	if !p.ready.Load() {
		return errNotReady
	}
	return p.post(ctx, path, in, out)
}

// post POSTs in as JSON and decodes the response into out (if non-nil).
func (p *Plugin) post(ctx context.Context, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.base.String()+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.secret())
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return responseError(resp)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponse))
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponse)).Decode(out); err != nil {
		return fmt.Errorf("invalid plugin response: %w", err)
	}
	return nil
}

// maxResponse bounds what Tenarium reads from a plugin response, matching
// the request limit of the plugin side.
const maxResponse = 8 << 20

// responseError turns a non-2xx response into an error. A known code in the
// error body is mapped back to its sdk sentinel (errors.Is works on the
// result); the HTTP status alone is never interpreted.
func responseError(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var e extplugin.ErrorResponse
	if json.Unmarshal(b, &e) == nil && e.Error != "" {
		msg := fmt.Sprintf("%s: %s", resp.Status, e.Error)
		if sentinel := extplugin.ErrorForCode(e.Code); sentinel != nil {
			return fmt.Errorf("%w: %s", sentinel, msg)
		}
		return errors.New(msg)
	}
	if sentinel := extplugin.ErrorForCode(e.Code); sentinel != nil {
		return fmt.Errorf("%w: %s", sentinel, resp.Status)
	}
	return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(b)))
}

func readError(resp *http.Response) string {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var e extplugin.ErrorResponse
	if json.Unmarshal(b, &e) == nil && e.Error != "" {
		return fmt.Sprintf("%s: %s", resp.Status, e.Error)
	}
	return fmt.Sprintf("%s: %s", resp.Status, strings.TrimSpace(string(b)))
}

type provisioner struct {
	p    *Plugin
	name string
}

func (pr *provisioner) Name() string { return pr.name }
func (pr *provisioner) Provision(ctx context.Context, t sdk.Tenant) error {
	return pr.p.call(ctx, "/provisioners/"+url.PathEscape(pr.name)+"/provision", t, nil)
}
func (pr *provisioner) Deprovision(ctx context.Context, t sdk.Tenant) error {
	return pr.p.call(ctx, "/provisioners/"+url.PathEscape(pr.name)+"/deprovision", t, nil)
}

type authenticator struct {
	p    *Plugin
	name string
}

func (a *authenticator) Name() string { return a.name }
func (a *authenticator) Authenticate(ctx context.Context, r *http.Request) (*sdk.Principal, error) {
	var out extplugin.AuthenticateResponse
	err := a.p.call(ctx, "/authenticate/"+url.PathEscape(a.name), extplugin.AuthenticateRequest{
		Method: r.Method, Path: r.URL.RequestURI(), Headers: r.Header,
	}, &out)
	switch {
	case err != nil:
		return nil, err
	case out.NoCredentials:
		return nil, sdk.ErrNoCredentials
	case out.Error != "":
		return nil, errors.New(out.Error)
	case out.Principal == nil:
		return nil, errors.New("authenticator returned no principal")
	}
	return out.Principal, nil
}

type authorizer struct {
	p    *Plugin
	name string
}

func (a *authorizer) Name() string { return a.name }
func (a *authorizer) Authorize(ctx context.Context, pr *sdk.Principal, action sdk.Action, res sdk.Resource) (sdk.Decision, error) {
	var out extplugin.AuthorizeResponse
	if err := a.p.call(ctx, "/authorize/"+url.PathEscape(a.name), extplugin.AuthorizeRequest{
		Principal: *pr, Action: action, Resource: res,
	}, &out); err != nil {
		return sdk.Abstain, err
	}
	return extplugin.ParseDecision(out.Decision), nil
}

func duration(s string, def time.Duration) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	return time.ParseDuration(s)
}

// validRoutes rejects patterns http.ServeMux would panic on (invalid or
// conflicting), so a misbehaving plugin fails its Init instead of crashing
// the server when routes are mounted.
func validRoutes(patterns []string) (err error) {
	mux := http.NewServeMux()
	for _, p := range patterns {
		if strings.TrimSpace(p) == "" {
			return errors.New("empty route pattern")
		}
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					err = fmt.Errorf("%q: %v", p, rec)
				}
			}()
			mux.Handle(p, http.NotFoundHandler())
		}()
		if err != nil {
			return err
		}
	}
	return nil
}
