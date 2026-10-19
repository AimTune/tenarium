// Package api exposes Tenarium over a JSON/HTTP API.
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/AimTune/tenarium/internal/authz"
	"github.com/AimTune/tenarium/internal/certs"
	"github.com/AimTune/tenarium/internal/events"
	"github.com/AimTune/tenarium/internal/identity"
	"github.com/AimTune/tenarium/internal/metrics"
	"github.com/AimTune/tenarium/internal/oidcprovider"
	"github.com/AimTune/tenarium/internal/plugin"
	"github.com/AimTune/tenarium/internal/social"
	"github.com/AimTune/tenarium/internal/sso"
	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/internal/tenant"
	"github.com/AimTune/tenarium/internal/webhooks"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const maxBodyBytes = 1 << 20

type Server struct {
	Tenants    *tenant.Service
	Store      store.Store
	Plugins    *plugin.Manager
	Dispatcher *events.Dispatcher
	Authz      *authz.Engine
	Metrics    *metrics.Metrics
	Log        *slog.Logger
	// APIKeys are accepted as "Authorization: Bearer <key>".
	APIKeys []string
	// AllowAnonymous serves the API without credentials when no
	// authenticator is configured (development only).
	AllowAnonymous bool
	// OpenAPI is served at /openapi.yaml when set.
	OpenAPI []byte
	// UI is mounted at /ui/ when set.
	UI http.Handler
	// Issuer verifies Tenarium user tokens; nil disables them.
	Issuer *identity.Issuer
	// Webhooks manages self-service tenant webhooks; nil disables them.
	Webhooks *webhooks.Service
	// SSO runs per-tenant OIDC sign-in; nil disables it.
	SSO *sso.Handler
	// Social runs sign-in with social providers; nil disables it.
	Social *social.Handler
	// Reload re-reads the configuration file; nil when there is none.
	Reload func(ctx context.Context) (any, error)

	authLimiter *rateLimiter
	// OIDC makes Tenarium an OpenID provider at /oauth; nil disables it.
	OIDC *oidcprovider.Handler
	// Certs manages ACME certificates of custom domains; nil when off.
	Certs *certs.Manager
	// AuthRateLimit caps unauthenticated /v1/auth requests per IP per
	// minute (0 disables the limit).
	AuthRateLimit int
	// SharedRateLimit counts AuthRateLimit in the store, across replicas.
	SharedRateLimit bool
}

// Handler builds the root HTTP handler.
func (s *Server) Handler() http.Handler {
	v1 := http.NewServeMux()
	h := func(pattern string, fn http.HandlerFunc) { v1.HandleFunc(pattern, routed(pattern, fn)) }

	h("POST /v1/tenants", s.createTenant)
	h("GET /v1/tenants", s.listTenants)
	h("GET /v1/tenants/{id}", s.getTenant)
	h("PATCH /v1/tenants/{id}", s.updateTenant)
	h("DELETE /v1/tenants/{id}", s.deleteTenant)
	h("POST /v1/tenants/{id}/suspend", s.suspendTenant)
	h("POST /v1/tenants/{id}/resume", s.resumeTenant)
	h("POST /v1/tenants/{id}/retry-provisioning", s.retryProvisioning)
	h("POST /v1/tenants/{id}/restore", s.restoreTenant)
	h("GET /v1/tenants/{id}/audit", s.listTenantAudit)
	h("GET /v1/tenants/{id}/export", s.exportTenant)
	s.mountSCIM(h)
	h("GET /v1/tenants/{id}/roles", s.listRoles)
	h("GET /v1/tenants/{id}/roles/{role}", s.getRole)
	h("PUT /v1/tenants/{id}/roles/{role}", s.putRole)
	h("DELETE /v1/tenants/{id}/roles/{role}", s.deleteRole)
	h("GET /v1/tenants/{id}/groups", s.listGroups)
	h("POST /v1/tenants/{id}/groups", s.createGroup)
	h("GET /v1/tenants/{id}/groups/{group}", s.getGroup)
	h("PATCH /v1/tenants/{id}/groups/{group}", s.updateGroup)
	h("DELETE /v1/tenants/{id}/groups/{group}", s.deleteGroup)
	h("PUT /v1/tenants/{id}/groups/{group}/members/{member}", s.groupMember(true))
	h("DELETE /v1/tenants/{id}/groups/{group}/members/{member}", s.groupMember(false))
	h("GET /v1/tenants/{id}/sso", s.getSSO)
	h("PUT /v1/tenants/{id}/sso", s.putSSO)
	h("DELETE /v1/tenants/{id}/sso", s.deleteSSO)
	h("GET /v1/tenants/{id}/webhooks", s.listWebhooks)
	h("POST /v1/tenants/{id}/webhooks", s.createWebhook)
	h("GET /v1/tenants/{id}/webhooks/{webhook}", s.getWebhook)
	h("PATCH /v1/tenants/{id}/webhooks/{webhook}", s.updateWebhook)
	h("DELETE /v1/tenants/{id}/webhooks/{webhook}", s.deleteWebhook)
	h("POST /v1/tenants/{id}/webhooks/{webhook}/rotate-secret", s.rotateWebhookSecret)
	h("POST /v1/tenants/{id}/webhooks/{webhook}/test", s.testWebhook)
	h("GET /v1/tenants/{id}/webhooks/{webhook}/deliveries", s.listWebhookDeliveries)
	h("POST /v1/tenants/{id}/webhooks/{webhook}/deliveries/{delivery}/redeliver", s.redeliverWebhook)
	h("GET /v1/tenants/{id}/schedule", s.listSchedule)
	h("POST /v1/tenants/{id}/schedule", s.createScheduled)
	h("DELETE /v1/tenants/{id}/schedule/{action}", s.cancelScheduled)
	h("GET /v1/tenants/{id}/children", s.listChildren)
	h("GET /v1/tenants/{id}/entitlements", s.getEntitlements)
	h("PUT /v1/tenants/{id}/plan-revision", s.setPlanRevision)
	h("POST /v1/tenants/{id}/move", s.moveRegion)
	h("POST /v1/tenants/{id}/clone", s.cloneTenant)
	h("GET /v1/tenants/{id}/health", s.tenantHealth)
	h("POST /v1/tenants/{id}/maintenance", s.startMaintenance)
	h("DELETE /v1/tenants/{id}/maintenance", s.endMaintenance)
	h("GET /v1/tenant-templates", s.listTemplates)
	h("GET /v1/tenant-templates/{template}", s.getTemplate)
	h("PUT /v1/tenant-templates/{template}", s.putTemplate)
	h("DELETE /v1/tenant-templates/{template}", s.deleteTemplate)

	h("GET /v1/tenants/{id}/members", s.listMembers)
	h("POST /v1/tenants/{id}/members", s.addMember)
	h("GET /v1/tenants/{id}/members/{member}", s.getMember)
	h("PATCH /v1/tenants/{id}/members/{member}", s.updateMember)
	h("DELETE /v1/tenants/{id}/members/{member}", s.removeMember)

	h("GET /v1/tenants/{id}/api-keys", s.listTenantAPIKeys)
	h("POST /v1/tenants/{id}/api-keys", s.createTenantAPIKey)
	h("DELETE /v1/tenants/{id}/api-keys/{key}", s.revokeTenantAPIKey)
	h("GET /v1/tenants/{id}/domains", s.listDomains)
	h("POST /v1/tenants/{id}/domains", s.addDomain)
	h("POST /v1/tenants/{id}/domains/{hostname}/verify", s.verifyDomain)
	h("DELETE /v1/tenants/{id}/domains/{hostname}", s.removeDomain)
	h("GET /v1/tenants/{id}/domains/{hostname}/certificate", s.domainCertificate)
	h("GET /v1/domains/resolve", s.resolveDomain)
	h("GET /v1/audit", s.listAudit)
	h("GET /v1/actions", s.listActions)
	h("GET /v1/event-schemas", s.listEventSchemas)
	h("GET /v1/event-schemas/{type}", s.getEventSchema)
	h("GET /v1/event-schemas/{type}/{version}", s.getEventSchema)
	h("GET /v1/oauth-clients", s.listOAuthClients)
	h("POST /v1/oauth-clients", s.createOAuthClient)
	h("GET /v1/oauth-clients/{client}", s.getOAuthClient)
	h("PUT /v1/oauth-clients/{client}", s.updateOAuthClient)
	h("DELETE /v1/oauth-clients/{client}", s.deleteOAuthClient)
	h("POST /v1/oauth-clients/{client}/rotate-secret", s.rotateOAuthClientSecret)
	h("GET /v1/signing-keys", s.listSigningKeys)
	h("POST /v1/signing-keys/rotate", s.rotateSigningKey)
	h("DELETE /v1/signing-keys/{kid}", s.retireSigningKey)
	h("GET /v1/api-keys", s.listPlatformAPIKeys)
	h("POST /v1/api-keys", s.createPlatformAPIKey)
	h("DELETE /v1/api-keys/{key}", s.revokePlatformAPIKey)

	h("GET /v1/tenants/{id}/usage", s.getUsage)
	h("POST /v1/tenants/{id}/usage/{metric}", s.recordUsage)
	h("GET /v1/tenants/{id}/usage/{metric}/history", s.usageHistory)
	h("POST /v1/tenants/{id}/usage/{metric}/grants", s.reserveUsage)
	h("POST /v1/tenants/{id}/usage/{metric}/grants/{grant}/release", s.releaseUsage)

	h("GET /v1/plans", s.listPlans)
	h("POST /v1/plans", s.createPlan)
	h("GET /v1/plans/{id}", s.getPlan)
	h("PATCH /v1/plans/{id}", s.updatePlan)
	h("DELETE /v1/plans/{id}", s.deletePlan)
	h("GET /v1/plans/{id}/revisions", s.listPlanRevisions)
	h("GET /v1/regions", s.listRegions)
	h("GET /v1/rollouts", s.listRollouts)
	h("GET /v1/rollouts/{feature}", s.getRollout)
	h("PUT /v1/rollouts/{feature}", s.putRollout)
	h("DELETE /v1/rollouts/{feature}", s.deleteRollout)

	h("GET /v1/events", s.listEvents)
	h("GET /v1/dead-letters", s.listDeadLetters)
	h("GET /v1/dead-letters/{id}", s.getDeadLetter)
	h("POST /v1/dead-letters/{id}/replay", s.replayDeadLetter)
	h("POST /v1/events/replay", s.replayEvents)
	h("DELETE /v1/dead-letters/{id}", s.deleteDeadLetter)
	h("GET /v1/plugins", s.listPlugins)
	h("POST /v1/admin/reload", s.reloadConfig)
	h("GET /v1/me", s.me)
	h("GET /v1/me/memberships", s.myMemberships)
	h("POST /v1/me/password", s.changeMyPassword)
	h("GET /v1/me/mfa", s.myMFA)
	h("POST /v1/me/mfa/totp", s.beginTOTP)
	h("POST /v1/me/mfa/totp/confirm", s.confirmTOTP)
	h("POST /v1/me/mfa/recovery-codes", s.regenerateRecoveryCodes)
	h("POST /v1/me/mfa/disable", s.disableMyMFA)
	h("GET /v1/me/export", s.exportMe)
	h("POST /v1/me/impersonation-consent", s.grantImpersonationConsent)
	h("GET /v1/me/passkeys", s.listPasskeys)
	h("POST /v1/me/passkeys/register/begin", s.beginPasskeyRegistration)
	h("POST /v1/me/passkeys/register/finish", s.finishPasskeyRegistration)
	h("DELETE /v1/me/passkeys/{passkey}", s.deletePasskey)
	h("POST /v1/me/email", s.requestEmailChange)
	h("GET /v1/me/sessions", s.listMySessions)
	h("DELETE /v1/me/sessions/{session}", s.revokeMySession)

	h("GET /v1/users", s.listUsers)
	h("POST /v1/users", s.createUser)
	h("GET /v1/users/{id}", s.getUser)
	h("PATCH /v1/users/{id}", s.updateUser)
	h("DELETE /v1/users/{id}", s.deleteUser)
	h("POST /v1/users/{id}/disable", s.userAction(s.Tenants.DisableUser))
	h("POST /v1/users/{id}/enable", s.userAction(s.Tenants.EnableUser))
	h("POST /v1/users/{id}/password", s.setUserPassword)
	h("POST /v1/users/{id}/invitation", s.resendInvitation)
	h("DELETE /v1/users/{id}/sessions", s.revokeSessions)
	h("GET /v1/users/{id}/sessions", s.listUserSessions)
	h("DELETE /v1/users/{id}/sessions/{session}", s.revokeUserSession)
	h("GET /v1/users/{id}/memberships", s.userMemberships)
	h("DELETE /v1/users/{id}/mfa", s.resetUserMFA)
	h("GET /v1/users/{id}/export", s.exportUser)
	h("POST /v1/users/{id}/erase", s.eraseUser)
	h("POST /v1/users/{id}/impersonate", s.impersonateUser)
	s.mountPluginRoutes(v1)

	root := http.NewServeMux()
	root.HandleFunc("GET /healthz", routed("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}))
	root.HandleFunc("GET /readyz", routed("GET /readyz", s.ready))
	root.Handle("GET /metrics", promhttp.HandlerFor(s.Metrics.Registry, promhttp.HandlerOpts{}))
	if s.OpenAPI != nil {
		root.HandleFunc("GET /openapi.yaml", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/yaml")
			_, _ = w.Write(s.OpenAPI)
		})
	}
	if s.UI != nil {
		root.Handle("/ui/", http.StripPrefix("/ui", s.UI))
		root.Handle("GET /{$}", http.RedirectHandler("/ui/", http.StatusFound))
	}
	s.mountAuth(root)
	s.mountPublicPluginRoutes(root)
	root.HandleFunc("GET /v1/domains/check", routed("GET /v1/domains/check", s.checkDomain))
	root.Handle("/v1/", s.auth(s.idempotency(v1)))
	return s.requestID(s.instrument(clientInfo(root)))
}

func (s *Server) mountPluginRoutes(mux *http.ServeMux) {
	byInstance := map[string]*http.ServeMux{}
	for _, r := range s.Plugins.Routes() {
		if r.Public {
			continue
		}
		sub, ok := byInstance[r.Instance]
		if !ok {
			sub = http.NewServeMux()
			byInstance[r.Instance] = sub
			prefix := "/v1/plugins/" + r.Instance
			mux.Handle(prefix+"/", http.StripPrefix(prefix, sub))
		}
		res := sdk.Resource{Type: "plugin", ID: r.Instance}
		h := r.Handler
		sub.Handle(r.Pattern, routed("plugin "+r.Instance+" "+r.Pattern, func(w http.ResponseWriter, req *http.Request) {
			if s.authorize(w, req, sdk.ActionPluginsRoute, res) {
				h.ServeHTTP(w, req)
			}
		}))
	}
}

// mountPublicPluginRoutes mounts unauthenticated plugin routes under
// /v1/plugins/{instance}/public/ on the root mux, outside the auth chain.
func (s *Server) mountPublicPluginRoutes(root *http.ServeMux) {
	byInstance := map[string]*http.ServeMux{}
	for _, r := range s.Plugins.Routes() {
		if !r.Public {
			continue
		}
		sub, ok := byInstance[r.Instance]
		if !ok {
			sub = http.NewServeMux()
			byInstance[r.Instance] = sub
			prefix := "/v1/plugins/" + r.Instance + "/public"
			root.Handle(prefix+"/", http.StripPrefix(prefix, http.MaxBytesHandler(sub, maxBodyBytes)))
		}
		sub.Handle(r.Pattern, routed("plugin-public "+r.Instance+" "+r.Pattern, r.Handler.ServeHTTP))
	}
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	// The endpoint is unauthenticated: report only ok/fail and keep error
	// details (hosts, URLs, IdP responses) in the log.
	status, checks := http.StatusOK, map[string]string{}
	check := func(name string, err error) {
		checks[name] = "ok"
		if err != nil {
			checks[name], status = "fail", http.StatusServiceUnavailable
			s.Log.Warn("readiness check failed", "check", name, "err", err)
		}
	}
	_, err := s.Store.LastEventSeq(ctx)
	check("store", err)
	for name, err := range s.Plugins.Health(ctx) {
		check("plugin:"+name, err)
	}
	writeJSON(w, status, map[string]any{"checks": checks})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	p, _ := sdk.PrincipalFrom(r.Context())
	writeJSON(w, http.StatusOK, p)
}

// authorize checks the caller's permission and writes 403 if denied.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request, action sdk.Action, res sdk.Resource) bool {
	p, _ := sdk.PrincipalFrom(r.Context())
	if err := s.Authz.Authorize(r.Context(), p, action, res); err != nil {
		s.writeErr(w, r, err)
		return false
	}
	return s.checkMaintenance(w, r, p, action, res)
}

func tenantResource(t sdk.Tenant) sdk.Resource {
	return sdk.Resource{Type: "tenant", ID: t.ID, TenantID: t.ID}
}

// loadTenant resolves {id} and authorizes action on it.
func (s *Server) loadTenant(w http.ResponseWriter, r *http.Request, action sdk.Action) (sdk.Tenant, bool) {
	t, err := s.Tenants.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeErr(w, r, err)
		return sdk.Tenant{}, false
	}
	if !s.authorize(w, r, action, tenantResource(t)) {
		return sdk.Tenant{}, false
	}
	return t, true
}

// --- middleware --------------------------------------------------------------

type ctxKey int

const (
	routeKey ctxKey = iota
	requestIDKey
)

// routeInfo is filled in by the matched handler so the outer middleware can
// label metrics with the route pattern instead of the raw path.
type routeInfo struct{ pattern string }

func routed(pattern string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ri, ok := r.Context().Value(routeKey).(*routeInfo); ok {
			ri.pattern = pattern
		}
		// Name the request span (if tracing is on) after the route, not the
		// URL, so spans group by endpoint.
		if span := trace.SpanFromContext(r.Context()); span.IsRecording() {
			span.SetName(pattern)
			span.SetAttributes(attribute.String("http.route", pattern))
		}
		h(w, r)
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (s *Server) instrument(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ri := &routeInfo{pattern: "unmatched"}
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), routeKey, ri)))
		d := time.Since(start)
		s.Metrics.HTTPRequests.WithLabelValues(r.Method, ri.pattern, strconv.Itoa(rec.status)).Inc()
		s.Metrics.HTTPDuration.WithLabelValues(r.Method, ri.pattern).Observe(d.Seconds())
		s.Log.Debug("http request", "method", r.Method, "path", r.URL.Path, "status", rec.status,
			"duration", d, "request_id", r.Header.Get("X-Request-ID"))
	})
}

func (s *Server) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" || len(id) > 128 {
			b := make([]byte, 12)
			_, _ = rand.Read(b)
			id = hex.EncodeToString(b)
			r.Header.Set("X-Request-ID", id)
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
	})
}

// --- helpers -------------------------------------------------------------------

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error(), "")
		return false
	}
	return true
}

// ifMatch parses an If-Match header carrying a resource version.
func ifMatch(r *http.Request) (*int64, error) {
	v := r.Header.Get("If-Match")
	if v == "" {
		return nil, nil
	}
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return nil, &tenant.ValidationError{Field: "If-Match", Message: "must be a resource version"}
	}
	return &n, nil
}

func writeVersioned(w http.ResponseWriter, status int, version int64, v any) {
	w.Header().Set("ETag", `"`+strconv.FormatInt(version, 10)+`"`)
	writeJSON(w, status, v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// nonNil makes empty lists encode as [] rather than null.
func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// queryLimit parses the "limit" query parameter.
func queryLimit(r *http.Request, def, hi int) (int, error) {
	v := r.URL.Query().Get("limit")
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > hi {
		return 0, &tenant.ValidationError{Field: "limit", Message: "must be an integer between 1 and " + strconv.Itoa(hi)}
	}
	return n, nil
}
