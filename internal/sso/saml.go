package sso

import (
	"crypto/subtle"
	"encoding/xml"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/internal/tenant"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

// Each tenant is its own SAML service provider:
//
//	entity ID / metadata: <public_url>/v1/auth/sso/saml/<tenant id>/metadata
//	ACS (HTTP-POST):      <public_url>/v1/auth/sso/saml/<tenant id>/acs
//
// Requests are not signed and encrypted assertions are not supported, so no
// SP key is needed; assertions must be signed by the IdP.

func (h *Handler) samlBase(tenantID string) string {
	return h.cfg.PublicURL + "/v1/auth/sso/saml/" + tenantID
}

func (h *Handler) serviceProvider(conn store.SSOConnection) (*saml.ServiceProvider, error) {
	md, err := samlsp.ParseMetadata([]byte(conn.SAMLMetadata))
	if err != nil {
		return nil, err
	}
	b := h.samlBase(conn.TenantID)
	meta, _ := url.Parse(b + "/metadata")
	acs, _ := url.Parse(b + "/acs")
	return &saml.ServiceProvider{
		EntityID: meta.String(), MetadataURL: *meta, AcsURL: *acs, IDPMetadata: md,
		AuthnNameIDFormat: saml.UnspecifiedNameIDFormat, AllowIDPInitiated: false,
	}, nil
}

// samlCookie carries the state across the IdP's cross-site POST, which
// needs SameSite=None (and therefore Secure) on https deployments.
func (h *Handler) samlCookie(value string, maxAge int) *http.Cookie {
	secure := strings.HasPrefix(h.cfg.PublicURL, "https://")
	same := http.SameSiteLaxMode
	if secure {
		same = http.SameSiteNoneMode
	}
	return &http.Cookie{Name: cookieName, Value: value, Path: "/v1/auth/sso", MaxAge: maxAge,
		HttpOnly: true, Secure: secure, SameSite: same}
}

func (h *Handler) startSAML(w http.ResponseWriter, r *http.Request, conn store.SSOConnection, t sdk.Tenant, ret string) {
	sp, err := h.serviceProvider(conn)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "idp_unavailable", "the identity provider metadata is invalid")
		return
	}
	req, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(saml.HTTPRedirectBinding), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "idp_unavailable", "the identity provider has no redirect sign-in endpoint")
		return
	}
	// The request ID rides in the Verifier field: ParseResponse checks the
	// response answers this request.
	st := state{TenantID: t.ID, Issuer: conn.Issuer, State: random(), Verifier: req.ID, ReturnTo: ret}
	signed, err := h.issuer.SignClaims(stateAudience, stateTTL, st)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	u, err := req.Redirect(st.State, sp)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	http.SetCookie(w, h.samlCookie(signed, int(stateTTL.Seconds())))
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// SAMLMetadata serves a tenant's service provider metadata for the IdP.
func (h *Handler) SAMLMetadata(w http.ResponseWriter, r *http.Request) {
	conn, _, err := h.tenants.FindSSO(r.Context(), r.PathValue("tenant"), "")
	if err != nil || conn.Protocol != tenant.SSOProtocolSAML {
		writeErr(w, http.StatusNotFound, "sso_not_configured", "no SAML connection for this tenant")
		return
	}
	sp, err := h.serviceProvider(conn)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "idp_unavailable", "the identity provider metadata is invalid")
		return
	}
	b, err := xml.MarshalIndent(sp.Metadata(), "", "  ")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = w.Write(b)
}

// SAMLACS receives the IdP's POSTed response.
func (h *Handler) SAMLACS(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_state", "sign-in session expired or missing; start again")
		return
	}
	http.SetCookie(w, h.samlCookie("", -1))
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "invalid form")
		return
	}
	var st state
	if err := h.issuer.VerifyClaims(c.Value, stateAudience, &st); err != nil ||
		subtle.ConstantTimeCompare([]byte(st.State), []byte(r.PostForm.Get("RelayState"))) != 1 ||
		st.TenantID != r.PathValue("tenant") {
		writeErr(w, http.StatusBadRequest, "invalid_state", "sign-in session is invalid; start again")
		return
	}
	pair, err := h.finishSAML(r, st)
	if err != nil {
		code := "sso_failed"
		switch {
		case errors.Is(err, tenant.ErrSSORejected):
			code = "sso_rejected"
		case errors.Is(err, errProvider):
			code = "idp_error"
		}
		h.log.Info("saml sign-in failed", "tenant", st.TenantID, "err", err)
		redirectFragment(w, r, st.ReturnTo, url.Values{"error": {code}})
		return
	}
	redirectFragment(w, r, st.ReturnTo, sessionFragment(pair))
}

func (h *Handler) finishSAML(r *http.Request, st state) (tenant.TokenPair, error) {
	conn, _, err := h.tenants.FindSSO(r.Context(), st.TenantID, "")
	if err != nil || conn.Protocol != tenant.SSOProtocolSAML || conn.Issuer != st.Issuer {
		return tenant.TokenPair{}, tenant.ErrSSORejected
	}
	sp, err := h.serviceProvider(conn)
	if err != nil {
		return tenant.TokenPair{}, errProvider
	}
	a, err := sp.ParseResponse(r, []string{st.Verifier})
	if err != nil {
		var ie *saml.InvalidResponseError
		if errors.As(err, &ie) {
			h.log.Info("invalid SAML response", "tenant", st.TenantID, "detail", ie.PrivateErr)
		}
		return tenant.TokenPair{}, errProvider
	}
	id := samlIdentity(a, conn)
	return h.tenants.SSOSession(r.Context(), st.TenantID, id)
}

// samlIdentity reads the email (configured attribute, common attribute
// names, or an email-shaped NameID) and name from an assertion.
func samlIdentity(a *saml.Assertion, conn store.SSOConnection) tenant.SSOIdentity {
	attrs := map[string]string{}
	for _, st := range a.AttributeStatements {
		for _, at := range st.Attributes {
			if len(at.Values) > 0 {
				attrs[at.Name] = at.Values[0].Value
				if at.FriendlyName != "" {
					attrs[at.FriendlyName] = at.Values[0].Value
				}
			}
		}
	}
	first := func(names ...string) string {
		for _, n := range names {
			if v := attrs[n]; n != "" && v != "" {
				return v
			}
		}
		return ""
	}
	id := tenant.SSOIdentity{Issuer: conn.Issuer}
	if a.Subject != nil && a.Subject.NameID != nil {
		id.Subject = a.Subject.NameID.Value
	}
	id.Email = first(conn.SAMLEmailAttribute, "email", "mail", "emailAddress",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "urn:oid:0.9.2342.19200300.100.1.3")
	if id.Email == "" && strings.Contains(id.Subject, "@") {
		id.Email = id.Subject
	}
	id.Name = first(conn.SAMLNameAttribute, "displayName", "name",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "urn:oid:2.16.840.1.113730.3.1.241",
		"cn", "commonName", "urn:oid:2.5.4.3")
	return id
}
