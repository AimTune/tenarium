package tenant

import (
	"context"
	"errors"
	"slices"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
)

// ErrForeignIdentity refuses profile changes to users whose email domain
// the tenant does not own: users are platform-wide, and one tenant's
// identity provider must not rename another tenant's people.
var ErrForeignIdentity = errors.New("the user's email domain is not a verified domain of this tenant")

// OwnsEmailDomain reports whether email's domain is a verified domain of
// the tenant.
func (s *Service) OwnsEmailDomain(ctx context.Context, tenantID, email string) (bool, error) {
	d, err := s.store.GetDomain(ctx, NormalizeHostname(emailDomain(email)))
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil && d.TenantID == tenantID && d.Verified, err
}

// SetMemberName renames a member's user, if the tenant owns the user's
// email domain.
func (s *Service) SetMemberName(ctx context.Context, tenantRef, memberID, name string) error {
	m, err := s.GetMember(ctx, tenantRef, memberID)
	if err != nil {
		return err
	}
	u, err := s.store.GetUser(ctx, m.UserID)
	if err != nil || u.Name == name {
		return err
	}
	owns, err := s.OwnsEmailDomain(ctx, m.TenantID, u.Email)
	if err != nil {
		return err
	}
	if !owns {
		return ErrForeignIdentity
	}
	_, err = s.UpdateUser(ctx, u.ID, UserUpdate{Name: &name}, nil)
	return err
}

// MemberUser returns the user behind a membership (zero if not linked).
func (s *Service) MemberUser(ctx context.Context, m sdk.Member) sdk.User {
	if m.UserID == "" {
		return sdk.User{}
	}
	u, _ := s.store.GetUser(ctx, m.UserID)
	return u
}

// DefaultMemberRole is the role given to members without an explicit one
// (e.g. removed from every role group): "member" if configured, otherwise
// the last (least privileged) role.
func (s *Service) DefaultMemberRole() string {
	if slices.Contains(s.memberRoles, "member") {
		return "member"
	}
	return s.memberRoles[len(s.memberRoles)-1]
}
