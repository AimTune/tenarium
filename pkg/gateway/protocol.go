package gateway

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Mode selects how a check request describes the original request and how
// denials are answered.
type Mode string

const (
	// ModeAuto accepts every shape: X-Forwarded-* (Traefik), X-Original-*
	// (NGINX), else the Envoy shape (Host header, path after the endpoint
	// prefix). Denials use their real status codes.
	ModeAuto Mode = "check"
	// ModeEnvoy is Envoy ext_authz in HTTP service mode: the check
	// request keeps the original method and Host, and its path is the
	// configured path_prefix followed by the original path and query.
	// Forwarding headers are ignored.
	ModeEnvoy Mode = "envoy"
	// ModeNGINX is NGINX auth_request: the subrequest carries
	// X-Original-URI, X-Original-Method and X-Original-Host (or
	// X-Forwarded-Host), set with proxy_set_header. NGINX only accepts
	// 2xx, 401 and 403 from the auth endpoint, so every other denial is
	// answered with 403 and the real status in X-Tenarium-Status.
	ModeNGINX Mode = "nginx"
	// ModeTraefik is Traefik ForwardAuth: X-Forwarded-Method,
	// X-Forwarded-Proto, X-Forwarded-Host and X-Forwarded-Uri.
	ModeTraefik Mode = "traefik"
)

// Modes lists the protocol modes; ServeHTTP mounts each at "/<mode>".
var Modes = []Mode{ModeAuto, ModeEnvoy, ModeNGINX, ModeTraefik}

// ServeHTTP dispatches "/check", "/envoy", "/nginx" and "/traefik" (and
// anything below them, which Envoy needs because it appends the original
// path) to Handler. Other paths get 404. It does not clean paths the way
// http.ServeMux does: "/envoy//a/../b" must reach the handler unchanged.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.EscapedPath()
	for _, m := range Modes {
		prefix := "/" + string(m)
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			g.Handler(m, prefix).ServeHTTP(w, r)
			return
		}
	}
	http.NotFound(w, r)
}

// Match reports whether ServeHTTP handles path.
func Match(path string) bool {
	for _, m := range Modes {
		prefix := "/" + string(m)
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

// Handler returns the check endpoint for mode. prefix is the path the
// handler is mounted at; in Envoy and auto mode the rest of the path is
// the original path.
func (g *Gateway) Handler(mode Mode, prefix string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		res := g.Check(r.Context(), OriginalRequest(r, mode, prefix))
		g.opts.Metrics.observe(mode, res, time.Since(start))
		WriteResult(w, mode, res)
	})
}

// OriginalRequest extracts the original request from a check request.
func OriginalRequest(r *http.Request, mode Mode, prefix string) Request {
	or := Request{Header: r.Header}
	h := r.Header
	suffix := func() string {
		p := strings.TrimPrefix(r.URL.EscapedPath(), prefix)
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		if r.URL.RawQuery != "" {
			p += "?" + r.URL.RawQuery
		}
		return p
	}
	switch mode {
	case ModeEnvoy:
		or.Method, or.Host, or.URI = r.Method, r.Host, suffix()
		or.Scheme = first(h.Get("X-Forwarded-Proto"))
	case ModeTraefik:
		or.Method = h.Get("X-Forwarded-Method")
		or.Scheme = first(h.Get("X-Forwarded-Proto"))
		or.Host = firstOf(first(h.Get("X-Forwarded-Host")), r.Host)
		or.URI = firstOf(h.Get("X-Forwarded-Uri"), "/")
	case ModeNGINX:
		or.Method = firstOf(h.Get("X-Original-Method"), r.Method)
		or.Scheme = firstOf(h.Get("X-Original-Proto"), first(h.Get("X-Forwarded-Proto")))
		or.Host = firstOf(h.Get("X-Original-Host"), first(h.Get("X-Forwarded-Host")), r.Host)
		or.URI = firstOf(h.Get("X-Original-URI"), h.Get("X-Original-URL"), "/")
	default: // ModeAuto
		or.Method = firstOf(h.Get("X-Forwarded-Method"), h.Get("X-Original-Method"), r.Method)
		or.Scheme = firstOf(first(h.Get("X-Forwarded-Proto")), h.Get("X-Original-Proto"))
		or.Host = firstOf(first(h.Get("X-Forwarded-Host")), h.Get("X-Original-Host"), r.Host)
		or.URI = firstOf(h.Get("X-Forwarded-Uri"), h.Get("X-Original-URI"), h.Get("X-Original-URL"))
		if or.URI == "" {
			or.URI = suffix()
		}
	}
	return or
}

// first returns the first element of a comma separated header value.
func first(v string) string {
	v, _, _ = strings.Cut(v, ",")
	return strings.TrimSpace(v)
}

func firstOf(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

// WriteResult answers a check in mode's dialect. Allowed checks get 200
// with the result headers and an empty body; denials get a Tenarium style
// JSON error, X-Tenarium-Status and X-Tenarium-Error.
func WriteResult(w http.ResponseWriter, mode Mode, res Result) {
	wh := w.Header()
	for k, vs := range res.Headers {
		wh[k] = vs
	}
	wh.Set("Cache-Control", "no-store")
	if res.Allowed {
		w.WriteHeader(http.StatusOK)
		return
	}
	status := res.Status
	wh.Set(HeaderStatus, strconv.Itoa(status))
	wh.Set(HeaderError, res.Code)
	if mode == ModeNGINX && status != http.StatusUnauthorized && status != http.StatusForbidden {
		status = http.StatusForbidden
	}
	if status == http.StatusUnauthorized {
		wh.Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	}
	wh.Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": res.Code, "message": res.Message}})
}
