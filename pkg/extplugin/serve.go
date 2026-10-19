package extplugin

import (
	"bytes"
	"cmp"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// Serve runs p as an external plugin. It listens on TENARIUM_PLUGIN_ADDR
// (default 127.0.0.1:9333) and requires TENARIUM_PLUGIN_SECRET when set.
// It returns when the process receives SIGINT/SIGTERM.
//
//	func main() {
//		if err := extplugin.Serve(&myplugin.Plugin{}); err != nil {
//			log.Fatal(err)
//		}
//	}
func Serve(p sdk.Plugin) error {
	addr := os.Getenv(EnvAddr)
	if addr == "" {
		addr = "127.0.0.1:9333"
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	h := NewHandler(p, os.Getenv(EnvSecret), log)
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("external plugin listening", "addr", addr, "plugin", p.Manifest().ID)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := srv.Shutdown(shutdownCtx)
	return errors.Join(err, h.stop(shutdownCtx))
}

// Handler serves the plugin protocol for one plugin instance.
type Handler struct {
	plugin   sdk.Plugin
	secret   []byte
	proofKey string
	log      *slog.Logger
	host     sdk.Host

	mu   sync.RWMutex
	reg  *registrar
	mux  *http.ServeMux
	init bool
}

// NewHandler returns the protocol handler for p. An empty secret disables
// authentication (only for tests or trusted networks).
func NewHandler(p sdk.Plugin, secret string, log *slog.Logger) *Handler {
	h := &Handler{plugin: p, secret: []byte(secret), proofKey: os.Getenv(EnvProofKey), log: log, host: HostFromEnv()}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /init", h.handleInit)
	mux.HandleFunc("POST /events/{sub}", h.handleEvent)
	mux.HandleFunc("POST /hooks/{point}", h.handleHook)
	mux.HandleFunc("POST /provisioners/{name}/{op}", h.handleProvisioner)
	mux.HandleFunc("POST /authorize/{name}", h.handleAuthorize)
	mux.HandleFunc("POST /authenticate/{name}", h.handleAuthenticate)
	mux.HandleFunc("POST /directory/{op}", h.handleDirectory)
	mux.HandleFunc("POST /mailer/send", h.handleMailer)
	mux.HandleFunc("GET /health", h.handleHealth)
	mux.Handle("/routes/", http.StripPrefix("/routes", http.HandlerFunc(h.handleRoute)))
	h.mux = mux
	return h
}

// WithHost overrides the sdk.Host given to the plugin.
func (h *Handler) WithHost(host sdk.Host) *Handler {
	h.host = host
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if len(h.secret) > 0 {
		tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(tok), h.secret) != 1 {
			writeErr(w, http.StatusUnauthorized, errors.New("invalid plugin secret"))
			return
		}
	}
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) stop(ctx context.Context) error {
	if s, ok := h.plugin.(sdk.Stopper); ok && h.init {
		return s.Stop(ctx)
	}
	return nil
}

func (h *Handler) handleInit(w http.ResponseWriter, r *http.Request) {
	var req InitRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Protocol != ProtocolVersion {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("unsupported protocol %d (want %d)", req.Protocol, ProtocolVersion))
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	// Tenarium restarted: re-initialise from scratch.
	if err := h.stop(r.Context()); err != nil {
		h.log.Warn("stop before re-init", "err", err)
	}
	reg := newRegistrar(req.Instance, req.Config, h.log, h.host)
	if err := h.plugin.Init(r.Context(), reg); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	reg.closed = true
	slices.SortStableFunc(reg.hooks, func(a, b hook) int { return cmp.Compare(a.priority, b.priority) })
	h.reg, h.init = reg, true
	resp := reg.response(h.plugin.Manifest())
	if h.proofKey != "" && req.Nonce != "" {
		resp.Proof = Proof(h.proofKey, req.Nonce)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) current(w http.ResponseWriter) *registrar {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.reg == nil {
		writeErr(w, http.StatusConflict, errors.New("plugin not initialised"))
	}
	return h.reg
}

func (h *Handler) handleEvent(w http.ResponseWriter, r *http.Request) {
	reg := h.current(w)
	if reg == nil {
		return
	}
	var ce sdk.CloudEvent
	if !readJSON(w, r, &ce) {
		return
	}
	sub, ok := reg.subs[r.PathValue("sub")]
	if !ok {
		writeErr(w, http.StatusNotFound, fmt.Errorf("unknown subscription %q", r.PathValue("sub")))
		return
	}
	if err := sub.handler(r.Context(), EventFromCloudEvent(ce)); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleHook(w http.ResponseWriter, r *http.Request) {
	reg := h.current(w)
	if reg == nil {
		return
	}
	var req sdk.HookRequest
	if !readJSON(w, r, &req) {
		return
	}
	req.Point = sdk.HookPoint(r.PathValue("point"))
	for _, hk := range reg.hooks {
		if hk.point != req.Point {
			continue
		}
		if err := hk.handler(r.Context(), &req); err != nil {
			if re, ok := sdk.IsReject(err); ok {
				writeJSON(w, http.StatusOK, HookResponse{Reject: re.Reason})
				return
			}
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, HookResponse{Tenant: req.Tenant, Member: req.Member, User: req.User})
}

func (h *Handler) handleProvisioner(w http.ResponseWriter, r *http.Request) {
	reg := h.current(w)
	if reg == nil {
		return
	}
	var t sdk.Tenant
	if !readJSON(w, r, &t) {
		return
	}
	p, ok := reg.provisioners[r.PathValue("name")]
	if !ok {
		writeErr(w, http.StatusNotFound, fmt.Errorf("unknown provisioner %q", r.PathValue("name")))
		return
	}
	var err error
	switch r.PathValue("op") {
	case "provision":
		err = p.Provision(r.Context(), t)
	case "deprovision":
		err = p.Deprovision(r.Context(), t)
	default:
		writeErr(w, http.StatusNotFound, fmt.Errorf("unknown operation %q", r.PathValue("op")))
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	reg := h.current(w)
	if reg == nil {
		return
	}
	var req AuthorizeRequest
	if !readJSON(w, r, &req) {
		return
	}
	a, ok := reg.authorizers[r.PathValue("name")]
	if !ok {
		writeErr(w, http.StatusNotFound, fmt.Errorf("unknown authorizer %q", r.PathValue("name")))
		return
	}
	d, err := a.Authorize(r.Context(), &req.Principal, req.Action, req.Resource)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, AuthorizeResponse{Decision: d.String()})
}

func (h *Handler) handleAuthenticate(w http.ResponseWriter, r *http.Request) {
	reg := h.current(w)
	if reg == nil {
		return
	}
	var req AuthenticateRequest
	if !readJSON(w, r, &req) {
		return
	}
	a, ok := reg.authenticators[r.PathValue("name")]
	if !ok {
		writeErr(w, http.StatusNotFound, fmt.Errorf("unknown authenticator %q", r.PathValue("name")))
		return
	}
	in, err := http.NewRequestWithContext(r.Context(), req.Method, req.Path, nil)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid request: %w", err))
		return
	}
	in.Header = http.Header(req.Headers)
	p, err := a.Authenticate(r.Context(), in)
	switch {
	case errors.Is(err, sdk.ErrNoCredentials):
		writeJSON(w, http.StatusOK, AuthenticateResponse{NoCredentials: true})
	case err != nil:
		writeJSON(w, http.StatusOK, AuthenticateResponse{Error: err.Error()})
	default:
		writeJSON(w, http.StatusOK, AuthenticateResponse{Principal: p})
	}
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	initialised := h.init
	h.mu.RUnlock()
	if hc, ok := h.plugin.(sdk.HealthChecker); ok && initialised {
		if err := hc.Health(r.Context()); err != nil {
			writeErr(w, http.StatusServiceUnavailable, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "initialised": initialised})
}

func (h *Handler) handleRoute(w http.ResponseWriter, r *http.Request) {
	reg := h.current(w)
	if reg == nil {
		return
	}
	if v := r.Header.Get(PrincipalHeader); v != "" {
		if p, err := DecodePrincipal(v); err == nil {
			r = r.WithContext(sdk.WithPrincipal(r.Context(), p))
		}
	}
	reg.mux.ServeHTTP(w, r)
}

// registrar records what the plugin registers during Init.
type registrar struct {
	instance string
	cfg      map[string]any
	log      *slog.Logger
	host     sdk.Host
	closed   bool

	subs           map[string]subscription
	subOrder       []SubscriptionSpec
	hooks          []hook
	provisioners   map[string]sdk.Provisioner
	provOrder      []string
	routes         []string
	mux            *http.ServeMux
	authenticators map[string]sdk.Authenticator
	authorizers    map[string]sdk.Authorizer
	directory      sdk.UserDirectory
	mailer         sdk.Mailer
}

type subscription struct {
	handler sdk.EventHandler
}

type hook struct {
	point    sdk.HookPoint
	priority int
	handler  sdk.HookHandler
}

func newRegistrar(instance string, cfg map[string]any, log *slog.Logger, host sdk.Host) *registrar {
	return &registrar{
		instance: instance, cfg: cfg, log: log, host: host,
		subs: map[string]subscription{}, provisioners: map[string]sdk.Provisioner{},
		mux: http.NewServeMux(), authenticators: map[string]sdk.Authenticator{}, authorizers: map[string]sdk.Authorizer{},
	}
}

func (r *registrar) check() {
	if r.closed {
		panic("sdk.Registrar used after Init returned")
	}
}

func (r *registrar) Config(v any) error {
	raw, err := json.Marshal(r.cfg)
	if err != nil {
		return err
	}
	if string(raw) == "null" {
		raw = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	return nil
}

func (r *registrar) Logger() *slog.Logger { return r.log.With("instance", r.instance) }
func (r *registrar) Host() sdk.Host       { return r.host }
func (r *registrar) InstanceName() string { return r.instance }

func (r *registrar) Subscribe(name string, f sdk.EventFilter, h sdk.EventHandler, opts ...sdk.SubscribeOption) {
	r.check()
	o := sdk.DefaultSubscribeOptions()
	for _, opt := range opts {
		opt(&o)
	}
	r.subs[name] = subscription{handler: h}
	r.subOrder = append(r.subOrder, SubscriptionSpec{
		Name: name, Types: f.Types, MaxAttempts: o.MaxAttempts, TimeoutMS: o.Timeout.Milliseconds(), StartAtEnd: o.StartAtEnd,
	})
}

func (r *registrar) Hook(point sdk.HookPoint, h sdk.HookHandler, opts ...sdk.HookOption) {
	r.check()
	var o sdk.HookOptions
	for _, opt := range opts {
		opt(&o)
	}
	r.hooks = append(r.hooks, hook{point: point, priority: o.Priority, handler: h})
}

func (r *registrar) Provisioner(p sdk.Provisioner) {
	r.check()
	r.provisioners[p.Name()] = p
	r.provOrder = append(r.provOrder, p.Name())
}

func (r *registrar) Route(pattern string, h http.Handler) {
	r.check()
	r.routes = append(r.routes, pattern)
	r.mux.Handle(pattern, h)
}

func (r *registrar) Authenticator(a sdk.Authenticator) {
	r.check()
	r.authenticators[a.Name()] = a
}

func (r *registrar) Authorizer(a sdk.Authorizer) {
	r.check()
	r.authorizers[a.Name()] = a
}

func (r *registrar) response(m sdk.Manifest) InitResponse {
	resp := InitResponse{Protocol: ProtocolVersion, Manifest: m, Subscriptions: r.subOrder,
		Provisioners: r.provOrder, Routes: r.routes}
	// The server runs hooks for a point in priority order; each registered
	// handler for the point is reported once and executed together here.
	seen := map[sdk.HookPoint]bool{}
	for _, h := range r.hooks {
		if !seen[h.point] {
			seen[h.point] = true
			resp.Hooks = append(resp.Hooks, HookSpec{Point: h.point, Priority: h.priority})
		}
	}
	for name := range r.authenticators {
		resp.Authenticators = append(resp.Authenticators, name)
	}
	for name := range r.authorizers {
		resp.Authorizers = append(resp.Authorizers, name)
	}
	if d := r.directory; d != nil {
		_, verify := d.(sdk.PasswordVerifier)
		_, invite := d.(sdk.InvitationSender)
		resp.UserDirectory = &DirectorySpec{Name: d.Name(), VerifyPassword: verify, SendInvitation: invite}
	}
	if m := r.mailer; m != nil {
		resp.Mailer = &MailerSpec{Name: m.Name()}
	}
	return resp
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<20)).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, ErrorResponse{Error: err.Error(), Code: ErrorCode(err)})
}

// writeOpErr reports an error from a directory or mailer, choosing the
// status from its code. The host only interprets the code.
func writeOpErr(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch ErrorCode(err) {
	case CodeNotFound:
		status = http.StatusNotFound
	case CodeUnsupported:
		status = http.StatusNotImplemented
	case CodeForbidden, CodeInvalidCredentials:
		status = http.StatusForbidden
	}
	writeErr(w, status, err)
}

// UserDirectory offers d to Tenarium (at most one; a later call replaces
// it). Implementing sdk.PasswordVerifier or sdk.InvitationSender is
// declared in the init response. VerifyPassword should return (or wrap)
// ErrInvalidCredentials for a rejected password.
func (r *registrar) UserDirectory(d sdk.UserDirectory) {
	r.check()
	r.directory = d
}

// Mailer offers m to Tenarium (at most one; a later call replaces it).
func (r *registrar) Mailer(m sdk.Mailer) {
	r.check()
	r.mailer = m
}

func (h *Handler) handleDirectory(w http.ResponseWriter, r *http.Request) {
	reg := h.current(w)
	if reg == nil {
		return
	}
	d := reg.directory
	if d == nil {
		writeErr(w, http.StatusNotFound, errors.New("plugin offers no user directory"))
		return
	}
	var req DirectoryRequest
	if !readJSON(w, r, &req) {
		return
	}
	ctx := r.Context()
	var err error
	switch op := r.PathValue("op"); op {
	case DirCreateUser:
		var id string
		if id, err = d.CreateUser(ctx, req.User); err == nil {
			if id == "" {
				writeErr(w, http.StatusInternalServerError, errors.New("directory returned an empty external id"))
				return
			}
			writeJSON(w, http.StatusOK, CreateUserResponse{ExternalID: id})
			return
		}
	case DirUpdateUser:
		err = d.UpdateUser(ctx, req.User)
	case DirDeleteUser:
		err = d.DeleteUser(ctx, req.User)
	case DirSetPassword:
		err = d.SetPassword(ctx, req.User, req.Password)
	case DirVerifyPassword:
		v, ok := d.(sdk.PasswordVerifier)
		if !ok {
			writeOpErr(w, fmt.Errorf("%w: directory does not verify passwords", sdk.ErrUnsupported))
			return
		}
		err = v.VerifyPassword(ctx, req.User, req.Password)
	case DirSendInvitation:
		s, ok := d.(sdk.InvitationSender)
		if !ok {
			writeOpErr(w, fmt.Errorf("%w: directory does not send invitations", sdk.ErrUnsupported))
			return
		}
		err = s.SendInvitation(ctx, req.User)
	default:
		writeErr(w, http.StatusNotFound, fmt.Errorf("unknown directory operation %q", op))
		return
	}
	if err != nil {
		writeOpErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleMailer(w http.ResponseWriter, r *http.Request) {
	reg := h.current(w)
	if reg == nil {
		return
	}
	if reg.mailer == nil {
		writeErr(w, http.StatusNotFound, errors.New("plugin offers no mailer"))
		return
	}
	var m sdk.Message
	if !readJSON(w, r, &m) {
		return
	}
	if err := reg.mailer.Send(r.Context(), m); err != nil {
		writeOpErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// PublicRoute is not proxied for external plugins yet; it is ignored with a
// warning.
func (r *registrar) PublicRoute(string, http.Handler) {
	r.log.Warn("external plugins cannot register public routes yet; ignored")
}
