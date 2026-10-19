package tenantmw

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
)

// Options configure Middleware.
type Options struct {
	// AllowedStatuses are the tenant statuses that may use the
	// application (default: active). Other statuses are refused with 403,
	// deleted tenants with 404.
	AllowedStatuses []Status
	// Optional lets requests without any tenant reference through without
	// a tenant in the context instead of answering 404.
	Optional bool
	// ErrorHandler writes rejections. The default writes a Tenarium style
	// JSON error with the status from StatusCode.
	ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)
}

// Middleware resolves the request's tenant with resolver, loads it from
// source and stores it in the request context (see FromContext). It
// rejects requests with:
//
//   - 404 when no tenant is referenced (unless Options.Optional) or the
//     tenant is unknown or deleted;
//   - 403 when the tenant's status is not allowed, or when a Tenarium
//     access token belongs to a different tenant than the one addressed
//     by host, header or path;
//   - 401 when a Tenarium access token is invalid;
//   - 503 when the source fails.
func Middleware(resolver *Resolver, source Source, opts Options) func(http.Handler) http.Handler {
	allowed := opts.AllowedStatuses
	if len(allowed) == 0 {
		allowed = []Status{StatusActive}
	}
	onErr := opts.ErrorHandler
	if onErr == nil {
		onErr = WriteError
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			res, err := resolver.Resolve(r)
			if errors.Is(err, ErrNoTenant) && opts.Optional {
				next.ServeHTTP(w, r)
				return
			}
			if err != nil {
				onErr(w, r, err)
				return
			}
			t, err := load(r.Context(), source, res)
			if err != nil {
				onErr(w, r, err)
				return
			}
			if t.Status == StatusDeleted {
				onErr(w, r, ErrNotFound)
				return
			}
			if !slices.Contains(allowed, t.Status) {
				onErr(w, r, &StatusError{Status: t.Status})
				return
			}
			ctx := NewContext(r.Context(), t)
			if res.Token != nil {
				ctx = context.WithValue(ctx, claimsKey, res.Token.Claims)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// load fetches the primary tenant and enforces the token mismatch rule.
func load(ctx context.Context, source Source, res Resolution) (*Tenant, error) {
	t, err := source.Tenant(ctx, res.Primary.Ref)
	if err != nil {
		return nil, err
	}
	if res.Token == nil || res.Addressed == nil {
		return t, nil
	}
	tokenID := res.Token.Ref
	if res.Primary.Claims == nil {
		// The addressed tenant won; it must be the token's tenant.
		if t.ID != tokenID {
			return nil, ErrTenantMismatch
		}
		return t, nil
	}
	// The token won; the addressed tenant must be the same one.
	if a := res.Addressed.Ref; a != tokenID && a != t.Slug {
		addressed, err := source.Tenant(ctx, a)
		if errors.Is(err, ErrNotFound) || err == nil && addressed.ID != tokenID {
			return nil, ErrTenantMismatch
		} else if err != nil {
			return nil, err
		}
	}
	return t, nil
}

// StatusError reports a tenant whose status is not allowed. It matches
// ErrInactive.
type StatusError struct{ Status Status }

func (e *StatusError) Error() string        { return "tenantmw: tenant is " + string(e.Status) }
func (e *StatusError) Is(target error) bool { return target == ErrInactive }

// StatusCode maps errors of this package to HTTP status codes.
func StatusCode(err error) int {
	switch {
	case errors.Is(err, ErrNoTenant), errors.Is(err, ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrInvalidToken):
		return http.StatusUnauthorized
	case errors.Is(err, ErrInactive), errors.Is(err, ErrTenantMismatch), errors.Is(err, ErrFeatureDisabled):
		return http.StatusForbidden
	case errors.Is(err, ErrQuotaExceeded):
		return http.StatusTooManyRequests
	default:
		return http.StatusServiceUnavailable
	}
}

func errorCode(err error) string {
	switch {
	case errors.Is(err, ErrNoTenant):
		return "tenant_required"
	case errors.Is(err, ErrNotFound):
		return "tenant_not_found"
	case errors.Is(err, ErrInvalidToken):
		return "unauthorized"
	case errors.Is(err, ErrInactive):
		return "tenant_inactive"
	case errors.Is(err, ErrTenantMismatch):
		return "tenant_mismatch"
	case errors.Is(err, ErrFeatureDisabled):
		return "feature_disabled"
	case errors.Is(err, ErrQuotaExceeded):
		return "quota_exceeded"
	default:
		return "tenant_unavailable"
	}
}

// WriteError writes err as {"error":{"code","message"}} with the status
// from StatusCode. Messages of upstream failures are not exposed.
func WriteError(w http.ResponseWriter, _ *http.Request, err error) {
	code := StatusCode(err)
	msg := err.Error()
	if code == http.StatusServiceUnavailable {
		msg = "tenant state unavailable"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": errorCode(err), "message": msg}})
}

// RequireFeature rejects requests whose tenant (from Middleware) does not
// have feature enabled with 403. Requests without a tenant get 404.
func RequireFeature(feature string) func(http.Handler) http.Handler {
	return RequireFeatureWith(feature, WriteError)
}

// RequireFeatureWith is RequireFeature with a custom error writer.
func RequireFeatureWith(feature string, onErr func(http.ResponseWriter, *http.Request, error)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t := FromContext(r.Context())
			switch {
			case t == nil:
				onErr(w, r, ErrNoTenant)
			case !t.HasFeature(feature):
				onErr(w, r, ErrFeatureDisabled)
			default:
				next.ServeHTTP(w, r)
			}
		})
	}
}
