package tenant

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/AimTune/tenarium/internal/netguard"
	"github.com/AimTune/tenarium/internal/store"
	"github.com/crewjam/saml/samlsp"
)

// SSO protocols.
const (
	SSOProtocolOIDC = "oidc"
	SSOProtocolSAML = "saml"
)

// maxMetadata bounds fetched SAML metadata.
const maxMetadata = 1 << 20

func (s *Service) checkProviderURL(field, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	switch {
	case err != nil || u.Host == "" || u.User != nil || u.Fragment != "":
		return nil, invalid(field, "must be an absolute URL")
	case u.Scheme != "https" && !(u.Scheme == "http" && s.ssoAllowPrivate):
		return nil, invalid(field, "must use https")
	}
	if !s.ssoAllowPrivate {
		if err := netguard.CheckHost(u.Hostname()); err != nil {
			return nil, invalid(field, "%v", err)
		}
	}
	return u, nil
}

func (s *Service) validateOIDC(c *store.SSOConnection) error {
	u, err := s.checkProviderURL("issuer", c.Issuer)
	switch {
	case err != nil:
		return err
	case u.RawQuery != "":
		return invalid("issuer", "must be the provider's issuer URL")
	case c.ClientID == "":
		return invalid("client_id", "required")
	case c.ClientSecret == "":
		return invalid("client_secret", "required")
	}
	return nil
}

// loadSAMLMetadata fetches (if a URL is given) and parses the identity
// provider's metadata; its entity ID becomes the connection's issuer.
func (s *Service) loadSAMLMetadata(ctx context.Context, c *store.SSOConnection) error {
	if c.SAMLMetadataURL != "" && c.SAMLMetadata == "" {
		u, err := s.checkProviderURL("saml_metadata_url", c.SAMLMetadataURL)
		if err != nil {
			return err
		}
		client := netguard.NewClient(netguard.Options{Timeout: 10 * time.Second, AllowPrivate: s.ssoAllowPrivate, FollowRedirects: true})
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return invalid("saml_metadata_url", "%v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			return invalid("saml_metadata_url", "could not fetch metadata: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return invalid("saml_metadata_url", "metadata request answered %s", resp.Status)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadata))
		if err != nil {
			return invalid("saml_metadata_url", "could not read metadata: %v", err)
		}
		c.SAMLMetadata = string(b)
	}
	if c.SAMLMetadata == "" {
		return invalid("saml_metadata", "saml_metadata or saml_metadata_url is required")
	}
	md, err := samlsp.ParseMetadata([]byte(c.SAMLMetadata))
	if err != nil {
		return invalid("saml_metadata", "invalid metadata: %v", err)
	}
	if md.EntityID == "" || len(md.IDPSSODescriptors) == 0 {
		return invalid("saml_metadata", "not identity provider metadata")
	}
	c.Issuer = md.EntityID
	return nil
}
