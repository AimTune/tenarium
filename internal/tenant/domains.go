package tenant

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"

	"github.com/AimTune/tenarium/internal/identity"
	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
)

// Domain event types.
const (
	EventDomainAdded    = "domain.added"
	EventDomainVerified = "domain.verified"
	EventDomainRemoved  = "domain.removed"
)

// ChallengePrefix is the DNS label holding the verification TXT record:
// _tenarium-challenge.<hostname> TXT <token>.
const ChallengePrefix = "_tenarium-challenge."

var hostLabelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// NormalizeHostname lowercases a hostname and strips a trailing dot and port.
func NormalizeHostname(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.TrimSuffix(h, ".")
}

func (s *Service) validateHostname(h string) error {
	if len(h) > 253 || net.ParseIP(h) != nil {
		return invalid("hostname", "must be a DNS name")
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return invalid("hostname", "must be a fully qualified domain name")
	}
	for _, l := range labels {
		if !hostLabelRe.MatchString(l) {
			return invalid("hostname", "invalid label %q", l)
		}
	}
	for _, r := range s.reservedDomains {
		if h == r || strings.HasSuffix(h, "."+r) {
			return invalid("hostname", "%s is reserved", r)
		}
	}
	return nil
}

// AddDomain registers a hostname for a tenant. It must then be verified by
// publishing the returned token as a TXT record.
func (s *Service) AddDomain(ctx context.Context, tenantRef, hostname string) (store.Domain, error) {
	t, err := s.Get(ctx, tenantRef)
	if err != nil {
		return store.Domain{}, err
	}
	if !t.IsLive() {
		return store.Domain{}, transitionErr("add domains to", t.Status)
	}
	h := NormalizeHostname(hostname)
	if err := s.validateHostname(h); err != nil {
		return store.Domain{}, err
	}
	token, _ := identity.NewToken()
	d := store.Domain{Hostname: h, TenantID: t.ID, Token: "tenarium-verification=" + token[:32], CreatedAt: s.now()}
	err = s.store.InTx(ctx, func(tx store.Tx) error {
		if err := tx.CreateDomain(ctx, d); err != nil {
			if errors.Is(err, store.ErrAlreadyExists) {
				return fmt.Errorf("domain %s: %w", h, err)
			}
			return err
		}
		return s.appendEvent(ctx, tx, EventDomainAdded, t.ID, "domains/"+h, d)
	})
	if err != nil {
		return store.Domain{}, err
	}
	s.notify()
	return d, nil
}

func (s *Service) tenantDomain(ctx context.Context, tenantRef, hostname string) (store.Domain, error) {
	t, err := s.Get(ctx, tenantRef)
	if err != nil {
		return store.Domain{}, err
	}
	d, err := s.store.GetDomain(ctx, NormalizeHostname(hostname))
	if err != nil || d.TenantID != t.ID {
		return store.Domain{}, store.ErrNotFound
	}
	return d, nil
}

// ErrVerificationFailed means the TXT record was not found.
var ErrVerificationFailed = errors.New("verification TXT record not found")

// VerifyDomain checks the TXT record and marks the domain verified.
func (s *Service) VerifyDomain(ctx context.Context, tenantRef, hostname string) (store.Domain, error) {
	d, err := s.tenantDomain(ctx, tenantRef, hostname)
	if err != nil {
		return store.Domain{}, err
	}
	if d.Verified {
		return d, nil
	}
	records, err := s.lookupTXT(ctx, ChallengePrefix+d.Hostname)
	if err != nil || !slices.Contains(records, d.Token) {
		return store.Domain{}, fmt.Errorf("%w: publish TXT %s%s = %q", ErrVerificationFailed, ChallengePrefix, d.Hostname, d.Token)
	}
	now := s.now()
	err = s.store.InTx(ctx, func(tx store.Tx) error {
		if err := tx.MarkDomainVerified(ctx, d.Hostname, now); err != nil {
			return err
		}
		d.Verified, d.VerifiedAt = true, &now
		return s.appendEvent(ctx, tx, EventDomainVerified, d.TenantID, "domains/"+d.Hostname, d)
	})
	if err != nil {
		return store.Domain{}, err
	}
	s.notify()
	return d, nil
}

func (s *Service) RemoveDomain(ctx context.Context, tenantRef, hostname string) error {
	d, err := s.tenantDomain(ctx, tenantRef, hostname)
	if err != nil {
		return err
	}
	err = s.store.InTx(ctx, func(tx store.Tx) error {
		if err := tx.DeleteDomain(ctx, d.Hostname); err != nil {
			return err
		}
		return s.appendEvent(ctx, tx, EventDomainRemoved, d.TenantID, "domains/"+d.Hostname, d)
	})
	if err != nil {
		return err
	}
	s.notify()
	return nil
}

func (s *Service) ListDomains(ctx context.Context, tenantRef string) ([]store.Domain, error) {
	t, err := s.Get(ctx, tenantRef)
	if err != nil {
		return nil, err
	}
	return s.store.ListDomains(ctx, t.ID)
}

// ResolveDomain returns the live tenant a verified hostname belongs to.
func (s *Service) ResolveDomain(ctx context.Context, hostname string) (sdk.Tenant, error) {
	d, err := s.store.GetDomain(ctx, NormalizeHostname(hostname))
	if err != nil || !d.Verified {
		return sdk.Tenant{}, store.ErrNotFound
	}
	t, err := s.store.GetTenant(ctx, d.TenantID)
	if err != nil || !t.IsLive() {
		return sdk.Tenant{}, store.ErrNotFound
	}
	return t, nil
}
