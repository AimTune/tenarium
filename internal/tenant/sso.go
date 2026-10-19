package tenant

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/AimTune/tenarium/internal/identity"
	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/google/uuid"
)

// SSO event types.
const (
	EventSSOUpdated = "sso.updated"
	EventSSODeleted = "sso.deleted"
)

var (
	// ErrSSORequired refuses password logins for users of a domain whose
	// tenant enforces single sign-on.
	ErrSSORequired = errors.New("your organization requires single sign-on")
	// ErrSSORejected covers identities an SSO connection does not accept
	// (foreign email domain, unverified email, no membership).
	ErrSSORejected = errors.New("this identity cannot sign in to the tenant")
)

// SSOInput configures a tenant's OIDC connection. ClientSecret may be
// omitted on update to keep the current one.
type SSOInput struct {
	Issuer        string   `json:"issuer"`
	ClientID      string   `json:"client_id"`
	ClientSecret  string   `json:"client_secret,omitempty"`
	Domains       []string `json:"domains"`
	Enforce       bool     `json:"enforce"`
	AutoProvision bool     `json:"auto_provision"`
	DefaultRole   string   `json:"default_role,omitempty"`
	Enabled       *bool    `json:"enabled,omitempty"`
	// Protocol is "oidc" (default) or "saml". For SAML give the identity
	// provider'"'"'s metadata as XML or a URL to fetch it from; Issuer,
	// ClientID and ClientSecret are not used.
	Protocol           string `json:"protocol,omitempty"`
	SAMLMetadata       string `json:"saml_metadata,omitempty"`
	SAMLMetadataURL    string `json:"saml_metadata_url,omitempty"`
	SAMLEmailAttribute string `json:"saml_email_attribute,omitempty"`
	SAMLNameAttribute  string `json:"saml_name_attribute,omitempty"`
}

// SSOIdentity is what an identity provider asserted about a user.
type SSOIdentity struct {
	Issuer, Subject, Email, Name string
	// EmailVerified is nil when the provider sent no claim.
	EmailVerified *bool
}

// AllowPrivateSSOIssuers lets issuers live on internal addresses
// (development and tests).
func (s *Service) AllowPrivateSSOIssuers(allow bool) { s.ssoAllowPrivate = allow }

// PutSSO creates or replaces a tenant's SSO connection. Its email domains
// must be verified custom domains of the tenant, so a tenant can only
// assert identities of domains it controls.
func (s *Service) PutSSO(ctx context.Context, tenantRef string, in SSOInput) (store.SSOConnection, error) {
	t, err := s.Get(ctx, tenantRef)
	if err != nil {
		return store.SSOConnection{}, err
	}
	if !t.IsLive() {
		return store.SSOConnection{}, transitionErr("configure SSO for", t.Status)
	}
	now := s.now()
	c := store.SSOConnection{
		TenantID: t.ID, Issuer: strings.TrimRight(strings.TrimSpace(in.Issuer), "/"), ClientID: strings.TrimSpace(in.ClientID),
		ClientSecret: in.ClientSecret, Enforce: in.Enforce, AutoProvision: in.AutoProvision,
		DefaultRole: in.DefaultRole, Enabled: in.Enabled == nil || *in.Enabled, CreatedAt: now, UpdatedAt: now,
		Protocol: strings.ToLower(in.Protocol), SAMLMetadata: in.SAMLMetadata, SAMLMetadataURL: in.SAMLMetadataURL,
		SAMLEmailAttribute: in.SAMLEmailAttribute, SAMLNameAttribute: in.SAMLNameAttribute,
	}
	if prev, err := s.store.GetSSOConnection(ctx, t.ID); err == nil {
		c.CreatedAt = prev.CreatedAt
		if c.SAMLMetadata == "" && c.SAMLMetadataURL == "" {
			c.SAMLMetadata, c.SAMLMetadataURL = prev.SAMLMetadata, prev.SAMLMetadataURL
		}
		if c.ClientSecret == "" {
			c.ClientSecret = prev.ClientSecret
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		return store.SSOConnection{}, err
	}
	if c.DefaultRole == "" {
		c.DefaultRole = "member"
	}
	if err := s.validateSSO(ctx, t, &c, in.Domains); err != nil {
		return store.SSOConnection{}, err
	}
	if err := s.store.PutSSOConnection(ctx, c); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			return store.SSOConnection{}, invalid("domains", "a domain is used by another tenant's SSO connection")
		}
		return store.SSOConnection{}, err
	}
	return c, s.RecordEvent(ctx, EventSSOUpdated, t.ID, "tenants/"+t.ID+"/sso", c)
}

func (s *Service) validateSSO(ctx context.Context, t sdk.Tenant, c *store.SSOConnection, domains []string) error {
	switch c.Protocol {
	case "", SSOProtocolOIDC:
		c.Protocol = SSOProtocolOIDC
		c.SAMLMetadata, c.SAMLMetadataURL, c.SAMLEmailAttribute, c.SAMLNameAttribute = "", "", "", ""
		if err := s.validateOIDC(c); err != nil {
			return err
		}
	case SSOProtocolSAML:
		c.ClientID, c.ClientSecret = "", ""
		if err := s.loadSAMLMetadata(ctx, c); err != nil {
			return err
		}
	default:
		return invalid("protocol", "must be oidc or saml")
	}
	switch {
	case len(domains) == 0:
		return invalid("domains", "at least one email domain is required")
	case s.checkRole(ctx, t.ID, "default_role", c.DefaultRole) != nil:
		return invalid("default_role", "must be one of %v", s.memberRoles)
	}
	c.Domains = nil
	for _, d := range domains {
		d = NormalizeHostname(d)
		dom, err := s.store.GetDomain(ctx, d)
		if errors.Is(err, store.ErrNotFound) || (err == nil && (dom.TenantID != t.ID || !dom.Verified)) {
			return invalid("domains", "%s must first be added and verified as a domain of this tenant", d)
		} else if err != nil {
			return err
		}
		if !slices.Contains(c.Domains, d) {
			c.Domains = append(c.Domains, d)
		}
	}
	slices.Sort(c.Domains)
	return nil
}

func (s *Service) GetSSO(ctx context.Context, tenantRef string) (store.SSOConnection, error) {
	t, err := s.Get(ctx, tenantRef)
	if err != nil {
		return store.SSOConnection{}, err
	}
	return s.store.GetSSOConnection(ctx, t.ID)
}

func (s *Service) DeleteSSO(ctx context.Context, tenantRef string) error {
	t, err := s.Get(ctx, tenantRef)
	if err != nil {
		return err
	}
	c, err := s.store.GetSSOConnection(ctx, t.ID)
	if err != nil {
		return err
	}
	if err := s.store.DeleteSSOConnection(ctx, t.ID); err != nil {
		return err
	}
	return s.RecordEvent(ctx, EventSSODeleted, t.ID, "tenants/"+t.ID+"/sso", c)
}

// FindSSO returns the enabled connection to use for a tenant (ID or slug)
// or, if tenantRef is empty, for an email's domain.
func (s *Service) FindSSO(ctx context.Context, tenantRef, email string) (store.SSOConnection, sdk.Tenant, error) {
	var (
		c   store.SSOConnection
		err error
	)
	if tenantRef != "" {
		t, terr := s.Get(ctx, tenantRef)
		if terr != nil {
			return c, sdk.Tenant{}, terr
		}
		c, err = s.store.GetSSOConnection(ctx, t.ID)
	} else {
		c, err = s.store.FindSSOConnection(ctx, emailDomain(email))
	}
	if err != nil {
		return c, sdk.Tenant{}, err
	}
	if !c.Enabled {
		return c, sdk.Tenant{}, store.ErrNotFound
	}
	t, err := s.store.GetTenant(ctx, c.TenantID)
	if err != nil || t.Status != sdk.StatusActive {
		return c, sdk.Tenant{}, store.ErrNotFound
	}
	return c, t, nil
}

func emailDomain(email string) string {
	_, d, _ := strings.Cut(normalizeEmail(email), "@")
	return d
}

// ssoEnforced reports whether password login is refused for an email.
func (s *Service) ssoEnforced(ctx context.Context, email string) (bool, error) {
	c, err := s.store.FindSSOConnection(ctx, emailDomain(email))
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil && c.Enabled && c.Enforce, err
}

// SSOSession signs in an identity asserted by a tenant's provider: it
// finds (or provisions) the user and membership and issues a session
// scoped to the tenant. Platform roles are never granted through SSO.
func (s *Service) SSOSession(ctx context.Context, tenantID string, id SSOIdentity) (TokenPair, error) {
	c, err := s.store.GetSSOConnection(ctx, tenantID)
	if err != nil || !c.Enabled {
		return TokenPair{}, ErrSSORejected
	}
	email := normalizeEmail(id.Email)
	if email == "" || !slices.Contains(c.Domains, emailDomain(email)) || (id.EmailVerified != nil && !*id.EmailVerified) {
		return TokenPair{}, ErrSSORejected
	}
	t, err := s.store.GetTenant(ctx, tenantID)
	if err != nil || t.Status != sdk.StatusActive {
		return TokenPair{}, ErrSSORejected
	}
	u, err := s.ssoUser(ctx, c, email, id)
	if err != nil {
		return TokenPair{}, err
	}
	m, err := s.ssoMembership(ctx, c, t, u)
	if err != nil {
		return TokenPair{}, err
	}
	now := s.now()
	if err := s.store.RecordLoginSuccess(ctx, u.ID, now); err != nil {
		return TokenPair{}, err
	}
	refresh, hash := identity.NewToken()
	if err := s.store.CreateRefreshToken(ctx, store.RefreshToken{
		Hash: hash, UserID: u.ID, TenantID: t.ID, Family: uuid.NewString(),
		ExpiresAt: now.Add(s.userOpts.RefreshTTL), CreatedAt: now,
		UserAgent: clientFrom(ctx).UserAgent, IP: clientFrom(ctx).IP,
	}); err != nil {
		return TokenPair{}, err
	}
	return s.issue(ctx, u, t.ID, s.EffectiveRoles(ctx, m), refresh)
}

func (s *Service) ssoUser(ctx context.Context, c store.SSOConnection, email string, id SSOIdentity) (sdk.User, error) {
	u, err := s.store.GetUserByEmail(ctx, email)
	switch {
	case errors.Is(err, store.ErrNotFound):
		if !c.AutoProvision {
			return sdk.User{}, ErrSSORejected
		}
		now := s.now()
		u = sdk.User{
			ID: uuid.Must(uuid.NewV7()).String(), Email: email, Name: strings.TrimSpace(id.Name),
			Status: sdk.UserActive, EmailVerified: true, Directory: "sso",
			Attributes: map[string]string{"sso_issuer": id.Issuer, "sso_subject": id.Subject},
			Version:    1, CreatedAt: now, UpdatedAt: now,
		}
		if err := validateUser(&u); err != nil {
			return sdk.User{}, ErrSSORejected
		}
		err = s.store.InTx(ctx, func(tx store.Tx) error {
			if err := tx.CreateUser(ctx, u); err != nil {
				return err
			}
			return s.appendUserEvent(ctx, tx, sdk.EventUserCreated, u, nil)
		})
		if err != nil {
			return sdk.User{}, err
		}
		s.notify()
		return u, nil
	case err != nil:
		return sdk.User{}, err
	case u.Status == sdk.UserDisabled:
		return sdk.User{}, ErrSSORejected
	case u.Status == sdk.UserInvited:
		// The provider of the email's domain vouches for the address.
		if err := s.store.InTx(ctx, func(tx store.Tx) error { return s.activateUser(ctx, tx, u) }); err != nil {
			return sdk.User{}, err
		}
		s.notify()
		return s.store.GetUser(ctx, u.ID)
	}
	return u, nil
}

func (s *Service) ssoMembership(ctx context.Context, c store.SSOConnection, t sdk.Tenant, u sdk.User) (sdk.Member, error) {
	ms, err := s.store.ListMembershipsOfUser(ctx, u.ID)
	if err != nil {
		return sdk.Member{}, err
	}
	for _, m := range ms {
		if m.TenantID != t.ID {
			continue
		}
		switch m.Status {
		case sdk.MemberActive:
			return m, nil
		case sdk.MemberInvited:
			prev := m
			m.Status, m.Version, m.UpdatedAt = sdk.MemberActive, m.Version+1, s.now()
			err := s.store.InTx(ctx, func(tx store.Tx) error {
				if err := tx.UpdateMember(ctx, m, prev.Version); err != nil {
					return err
				}
				return s.appendEvent(ctx, tx, sdk.EventMemberUpdated, t.ID, "tenants/"+t.ID+"/members/"+m.ID,
					sdk.MemberEventData{Member: m, Previous: &prev})
			})
			s.notify()
			return m, err
		default:
			return sdk.Member{}, ErrSSORejected // suspended by an admin
		}
	}
	if !c.AutoProvision {
		return sdk.Member{}, ErrSSORejected
	}
	return s.AddMember(ctx, t.ID, MemberInput{UserID: u.ID, Role: c.DefaultRole})
}
