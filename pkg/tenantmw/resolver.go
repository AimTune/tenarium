package tenantmw

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
)

// Match is a tenant reference found in a request.
type Match struct {
	// Source names the resolver source: "subdomain", "header", "path",
	// "token" or "domain" (or a custom name).
	Source string
	// Ref is a tenant ID or slug.
	Ref string
	// Claims are set for matches from an access token.
	Claims *Claims
}

// Extractor finds a tenant reference in a request. It returns ok=false when
// the request carries none; an error aborts resolution.
type Extractor interface {
	Extract(r *http.Request) (m Match, ok bool, err error)
}

// ExtractorFunc adapts a function to Extractor.
type ExtractorFunc func(r *http.Request) (Match, bool, error)

func (f ExtractorFunc) Extract(r *http.Request) (Match, bool, error) { return f(r) }

// ResolverOption adds a source to a Resolver. Sources are tried in the order
// the options are given.
type ResolverOption func(*Resolver)

// Resolver finds the tenant reference of a request by trying its sources in
// order; the first match wins.
type Resolver struct {
	extractors []Extractor
}

// NewResolver returns a Resolver trying the given sources in order.
func NewResolver(opts ...ResolverOption) *Resolver {
	r := &Resolver{}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Resolution is the outcome of Resolver.Resolve.
type Resolution struct {
	// Primary is the winning match (the first source that matched).
	Primary Match
	// Token is the match from an access token, if any.
	Token *Match
	// Addressed is the first match not coming from a token: the tenant the
	// request addresses through its host, header or path.
	Addressed *Match
}

// Resolve tries the sources in order and returns the first match as
// Primary. When a token source is configured, resolution continues until
// both the token's tenant and the addressed tenant are known so that
// Middleware can reject a token used against another tenant. It returns
// ErrNoTenant when nothing matched.
func (rs *Resolver) Resolve(r *http.Request) (Resolution, error) {
	var res Resolution
	tokensLeft := 0
	for _, e := range rs.extractors {
		if _, ok := e.(tokenExtractor); ok {
			tokensLeft++
		}
	}
	for _, e := range rs.extractors {
		_, isToken := e.(tokenExtractor)
		if isToken {
			tokensLeft--
		}
		if res.Addressed != nil && (res.Token != nil || tokensLeft == 0 && !isToken) {
			break
		}
		if !isToken && res.Addressed != nil {
			continue
		}
		if isToken && res.Token != nil {
			continue
		}
		m, ok, err := e.Extract(r)
		if err != nil {
			return Resolution{}, err
		}
		if !ok || m.Ref == "" {
			continue
		}
		if res.Primary.Ref == "" {
			res.Primary = m
		}
		if isToken {
			res.Token = &m
		} else {
			res.Addressed = &m
		}
	}
	if res.Primary.Ref == "" {
		return Resolution{}, ErrNoTenant
	}
	return res, nil
}

// tokenExtractor marks extractors whose matches come from access tokens.
type tokenExtractor struct{ ExtractorFunc }

// With adds a custom extractor.
func With(e Extractor) ResolverOption {
	return func(r *Resolver) { r.extractors = append(r.extractors, e) }
}

// FromSubdomain matches "<slug>.<baseDomain>" hosts: with baseDomain
// "app.example.com", host "acme.app.example.com" resolves to slug "acme".
// Only a single label is accepted; the port is ignored.
func FromSubdomain(baseDomain string) ResolverOption {
	suffix := "." + strings.Trim(strings.ToLower(baseDomain), ".")
	return With(ExtractorFunc(func(r *http.Request) (Match, bool, error) {
		host := requestHost(r)
		label, ok := strings.CutSuffix(host, suffix)
		if !ok || label == "" || strings.Contains(label, ".") {
			return Match{}, false, nil
		}
		return Match{Source: "subdomain", Ref: label}, true, nil
	}))
}

// FromHeader takes the tenant ID or slug from a request header such as
// "X-Tenant-ID".
func FromHeader(name string) ResolverOption {
	return With(ExtractorFunc(func(r *http.Request) (Match, bool, error) {
		v := strings.TrimSpace(r.Header.Get(name))
		return Match{Source: "header", Ref: v}, v != "", nil
	}))
}

// FromPathPrefix matches paths of the form "/t/{slug}/...".
func FromPathPrefix() ResolverOption { return FromPath("/t/") }

// FromPath matches paths of the form "<prefix>{id-or-slug}[/...]"; prefix
// must start and end with "/".
func FromPath(prefix string) ResolverOption {
	return With(ExtractorFunc(func(r *http.Request) (Match, bool, error) {
		rest, ok := strings.CutPrefix(r.URL.Path, prefix)
		if !ok {
			return Match{}, false, nil
		}
		ref, _, _ := strings.Cut(rest, "/")
		return Match{Source: "path", Ref: ref}, ref != "", nil
	}))
}

// FromToken takes the tenant from the tid claim of a Tenarium access token
// sent as "Authorization: Bearer <token>". Requests without a bearer token,
// with a non-JWT bearer (e.g. an API key) or with a token of another
// issuer do not match; a Tenarium token that fails verification yields
// ErrInvalidToken. Platform tokens (no tid) do not match either.
func FromToken(v *Verifier) ResolverOption {
	return With(tokenExtractor{func(r *http.Request) (Match, bool, error) {
		raw, ok := bearer(r)
		if !ok {
			return Match{}, false, nil
		}
		c, err := v.Verify(r.Context(), raw)
		if errors.Is(err, ErrForeignToken) {
			return Match{}, false, nil
		} else if err != nil {
			return Match{}, false, err
		}
		return Match{Source: "token", Ref: c.TenantID, Claims: c}, c.TenantID != "", nil
	}})
}

// DomainResolver maps a custom hostname to a tenant. Client implements it
// with GET /v1/domains/resolve; wrap it in CachingDomains to avoid one API
// call per request.
type DomainResolver interface {
	ResolveDomain(ctx context.Context, host string) (Domain, error)
}

// FromCustomDomain resolves the request host through Tenarium's custom
// domain registry. Unknown hosts (ErrNotFound) do not match.
func FromCustomDomain(d DomainResolver) ResolverOption {
	return With(ExtractorFunc(func(r *http.Request) (Match, bool, error) {
		host := requestHost(r)
		if host == "" {
			return Match{}, false, nil
		}
		dom, err := d.ResolveDomain(r.Context(), host)
		if errors.Is(err, ErrNotFound) {
			return Match{}, false, nil
		} else if err != nil {
			return Match{}, false, err
		}
		return Match{Source: "domain", Ref: dom.TenantID}, dom.TenantID != "", nil
	}))
}

func requestHost(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

func bearer(r *http.Request) (string, bool) {
	scheme, tok, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	tok = strings.TrimSpace(tok)
	return tok, tok != ""
}
