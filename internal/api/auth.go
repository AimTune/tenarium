package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/AimTune/tenarium/internal/authz"
	"github.com/AimTune/tenarium/internal/plugin"
	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
)

// auth runs the authenticator chain: the built-in API key authenticator
// followed by plugin authenticators (OIDC, LDAP, ...). The resulting
// principal is stored in the request context for handlers and hooks.
func (s *Server) auth(next http.Handler) http.Handler {
	var chain []plugin.AuthenticatorRef
	if len(s.APIKeys) > 0 {
		chain = append(chain, plugin.AuthenticatorRef{Name: "core/api-key", Authenticator: newAPIKeyAuth(s.APIKeys)})
	}
	if s.Issuer != nil {
		chain = append(chain, plugin.AuthenticatorRef{
			Name:          authz.UserTokenAuthenticator,
			Authenticator: &tokenAuthenticator{issuer: s.Issuer, tenants: s.Tenants},
		})
	}
	chain = append(chain, plugin.AuthenticatorRef{
		Name:          authz.ServiceKeyAuthenticator,
		Authenticator: &keyAuthenticator{tenants: s.Tenants},
	})
	chain = append(chain, s.Plugins.Authenticators()...)
	// allow_anonymous (development only) treats requests that carry no
	// credentials as an anonymous caller; invalid credentials still fail.
	anon := &sdk.Principal{Subject: "anonymous", Kind: "user", Authenticator: "none"}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		noCredentials := true
		for _, a := range chain {
			p, err := callAuthenticator(r.Context(), a.Authenticator, r)
			if errors.Is(err, sdk.ErrNoCredentials) {
				continue
			}
			noCredentials = false
			if err != nil || p == nil {
				s.Log.Debug("authentication failed", "authenticator", a.Name, "err", err)
				break
			}
			p.Authenticator = a.Name
			// Principals from external identity providers are linked to their
			// Tenarium user, so disabling the user takes effect there too.
			if err := s.Tenants.LinkExternalPrincipal(r.Context(), p); err != nil {
				s.Log.Debug("external principal refused", "authenticator", a.Name, "err", err)
				break
			}
			next.ServeHTTP(w, r.WithContext(sdk.WithPrincipal(r.Context(), p)))
			return
		}
		if noCredentials && s.AllowAnonymous {
			next.ServeHTTP(w, r.WithContext(sdk.WithPrincipal(r.Context(), anon)))
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="tenarium"`)
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing or invalid credentials", "")
	})
}

func callAuthenticator(ctx context.Context, a sdk.Authenticator, r *http.Request) (p *sdk.Principal, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			p, err = nil, fmt.Errorf("authenticator panic: %v", rec)
		}
	}()
	return a.Authenticate(ctx, r)
}

type apiKeyAuth struct{ keys [][]byte }

func newAPIKeyAuth(keys []string) *apiKeyAuth {
	a := &apiKeyAuth{}
	for _, k := range keys {
		a.keys = append(a.keys, []byte(k))
	}
	return a
}

func (a *apiKeyAuth) Name() string { return "api-key" }

func (a *apiKeyAuth) Authenticate(_ context.Context, r *http.Request) (*sdk.Principal, error) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return nil, sdk.ErrNoCredentials
	}
	for i, k := range a.keys {
		if subtle.ConstantTimeCompare([]byte(token), k) == 1 {
			return &sdk.Principal{Subject: fmt.Sprintf("api-key-%d", i), Kind: "service", Roles: []string{"admin"}}, nil
		}
	}
	// Not ours: a JWT for an OIDC authenticator also uses Bearer.
	return nil, sdk.ErrNoCredentials
}

// idempotencyTTL is how long an Idempotency-Key is remembered.
const idempotencyTTL = 24 * time.Hour

// idempotency makes POST requests carrying an Idempotency-Key safe to
// retry: the first response (if not a 5xx) is stored and replayed for later
// requests with the same key, caller and body. Reusing a key with a
// different body is an error. Concurrent first requests with the same key
// are not deduplicated; unique constraints (e.g. slugs) still apply.
func (s *Server) idempotency(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Idempotency-Key")
		if key == "" || r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}
		if len(key) > 255 {
			writeError(w, http.StatusBadRequest, "invalid_idempotency_key", "Idempotency-Key must be at most 255 characters", "")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_body", err.Error(), "")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))

		subject := ""
		if p, ok := sdk.PrincipalFrom(r.Context()); ok {
			subject = p.Authenticator + ":" + p.Subject
		}
		storeKey := hashHex(subject, r.Method, r.URL.Path, key)
		reqHash := hashHex(string(body))

		rec, err := s.Store.GetIdempotency(r.Context(), storeKey)
		switch {
		case err == nil && time.Since(rec.CreatedAt) < idempotencyTTL:
			if rec.RequestHash != reqHash {
				writeError(w, http.StatusUnprocessableEntity, "idempotency_key_reused",
					"Idempotency-Key was already used with a different request", "")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Idempotent-Replayed", "true")
			w.WriteHeader(rec.StatusCode)
			_, _ = w.Write(rec.Body)
			return
		case err != nil && !errors.Is(err, store.ErrNotFound):
			s.writeErr(w, r, err)
			return
		}

		cw := &capturingWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(cw, r)
		if cw.status >= 500 {
			return
		}
		err = s.Store.PutIdempotency(context.WithoutCancel(r.Context()), store.IdempotencyRecord{
			Key: storeKey, RequestHash: reqHash, StatusCode: cw.status, Body: cw.buf.Bytes(), CreatedAt: time.Now().UTC(),
		})
		if err != nil && !errors.Is(err, store.ErrAlreadyExists) {
			s.Log.Warn("store idempotency record", "err", err)
		}
	})
}

type capturingWriter struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
}

func (c *capturingWriter) WriteHeader(code int) {
	c.status = code
	c.ResponseWriter.WriteHeader(code)
}

func (c *capturingWriter) Write(b []byte) (int, error) {
	c.buf.Write(b)
	return c.ResponseWriter.Write(b)
}

func hashHex(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
