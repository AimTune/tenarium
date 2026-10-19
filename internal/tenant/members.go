package tenant

import (
	"context"
	"errors"
	"fmt"
	"net/mail"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/google/uuid"
)

// MetricMembers is the limit name that caps the number of members.
const MetricMembers = "members"

// MemberInput adds a member. The user is found by UserID or Email; an
// unknown email creates an invited user who receives a setup email. The
// membership becomes active once the user is.
type MemberInput struct {
	Email  string `json:"email,omitempty"`
	UserID string `json:"user_id,omitempty"`
	// Name is used when a new user is created.
	Name string `json:"name,omitempty"`
	Role string `json:"role"`
}

type MemberUpdate struct {
	Role *string `json:"role,omitempty"`
	// Active false suspends the membership; true lifts a suspension.
	Active *bool `json:"active,omitempty"`
}

func (s *Service) ListMembers(ctx context.Context, tenantIDOrSlug string) ([]sdk.Member, error) {
	t, err := s.Get(ctx, tenantIDOrSlug)
	if err != nil {
		return nil, err
	}
	return s.store.ListMembers(ctx, t.ID)
}

func (s *Service) GetMember(ctx context.Context, tenantIDOrSlug, memberID string) (sdk.Member, error) {
	t, err := s.Get(ctx, tenantIDOrSlug)
	if err != nil {
		return sdk.Member{}, err
	}
	return s.store.GetMember(ctx, t.ID, memberID)
}

// AddMember adds or invites a member, enforcing the "members" limit.
func (s *Service) AddMember(ctx context.Context, tenantIDOrSlug string, in MemberInput) (sdk.Member, error) {
	t, err := s.Get(ctx, tenantIDOrSlug)
	if err != nil {
		return sdk.Member{}, err
	}
	if !t.IsLive() {
		return sdk.Member{}, transitionErr("add members to", t.Status)
	}
	if err := s.checkRole(ctx, t.ID, "role", in.Role); err != nil {
		return sdk.Member{}, err
	}
	if in.UserID == "" {
		if _, err := mail.ParseAddress(in.Email); err != nil {
			return sdk.Member{}, invalid("email", "must be a plain email address")
		}
	}
	ent, err := s.entitlementsOf(ctx, t)
	if err != nil {
		return sdk.Member{}, err
	}
	// Cheap pre-check so a full tenant does not create and invite a user
	// for nothing; the authoritative check runs in the transaction.
	if limit, ok := ent.Limit(MetricMembers); ok {
		if ms, err := s.store.ListMembers(ctx, t.ID); err == nil && int64(len(ms)) >= limit {
			return sdk.Member{}, &QuotaError{Metric: MetricMembers, Limit: limit, Current: int64(len(ms))}
		}
	}
	u, err := s.ensureMemberUser(ctx, in)
	if err != nil {
		return sdk.Member{}, err
	}
	now := s.now()
	m := sdk.Member{
		ID:        uuid.Must(uuid.NewV7()).String(),
		TenantID:  t.ID,
		UserID:    u.ID,
		Email:     u.Email,
		Role:      in.Role,
		Status:    sdk.MemberInvited,
		InvitedBy: actor(ctx),
		Version:   1,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if u.Status == sdk.UserActive {
		m.Status = sdk.MemberActive
	}
	if err := s.validateMember(&m); err != nil {
		return sdk.Member{}, err
	}
	if m, err = s.runMemberHooks(ctx, sdk.HookBeforeMemberAdd, t, m); err != nil {
		return sdk.Member{}, err
	}
	err = s.store.InTx(ctx, func(tx store.Tx) error {
		// Locking the tenant serialises concurrent adds, so the count below
		// cannot be stale, and catches a deletion that started meanwhile.
		cur, err := tx.GetTenant(ctx, t.ID)
		if err != nil {
			return err
		}
		if !cur.IsLive() {
			return transitionErr("add members to", cur.Status)
		}
		if limit, ok := ent.Limit(MetricMembers); ok {
			n, err := tx.CountMembers(ctx, t.ID)
			if err != nil {
				return err
			}
			if int64(n) >= limit {
				return &QuotaError{Metric: MetricMembers, Limit: limit, Current: int64(n)}
			}
		}
		if err := tx.CreateMember(ctx, m); err != nil {
			if errors.Is(err, store.ErrAlreadyExists) {
				return fmt.Errorf("member %q: %w", m.Email, err)
			}
			return err
		}
		return s.appendEvent(ctx, tx, sdk.EventMemberAdded, t.ID, "tenants/"+t.ID+"/members/"+m.ID, sdk.MemberEventData{Member: m})
	})
	if err != nil {
		return sdk.Member{}, err
	}
	s.notify()
	return m, nil
}

func (s *Service) UpdateMember(ctx context.Context, tenantIDOrSlug, memberID string, in MemberUpdate) (sdk.Member, error) {
	t, err := s.Get(ctx, tenantIDOrSlug)
	if err != nil {
		return sdk.Member{}, err
	}
	prev, err := s.store.GetMember(ctx, t.ID, memberID)
	if err != nil {
		return sdk.Member{}, err
	}
	next := prev
	if in.Role != nil {
		if err := s.checkRole(ctx, t.ID, "role", *in.Role); err != nil {
			return sdk.Member{}, err
		}
		next.Role = *in.Role
	}
	if in.Active != nil {
		switch {
		case !*in.Active:
			next.Status = sdk.MemberSuspended
		case prev.Status == sdk.MemberSuspended:
			next.Status = sdk.MemberInvited
			if u, err := s.store.GetUser(ctx, prev.UserID); err == nil && u.Status == sdk.UserActive {
				next.Status = sdk.MemberActive
			}
		}
	}
	if err := s.validateMember(&next); err != nil {
		return sdk.Member{}, err
	}
	if next, err = s.runMemberHooks(ctx, sdk.HookBeforeMemberUpdate, t, next); err != nil {
		return sdk.Member{}, err
	}
	next.Version = prev.Version + 1
	next.UpdatedAt = s.now()
	err = s.store.InTx(ctx, func(tx store.Tx) error {
		if err := tx.UpdateMember(ctx, next, prev.Version); err != nil {
			return err
		}
		return s.appendEvent(ctx, tx, sdk.EventMemberUpdated, t.ID, "tenants/"+t.ID+"/members/"+next.ID,
			sdk.MemberEventData{Member: next, Previous: &prev})
	})
	if err != nil {
		return sdk.Member{}, err
	}
	s.notify()
	return next, nil
}

func (s *Service) RemoveMember(ctx context.Context, tenantIDOrSlug, memberID string) error {
	t, err := s.Get(ctx, tenantIDOrSlug)
	if err != nil {
		return err
	}
	m, err := s.store.GetMember(ctx, t.ID, memberID)
	if err != nil {
		return err
	}
	if _, err := s.runMemberHooks(ctx, sdk.HookBeforeMemberRemove, t, m); err != nil {
		return err
	}
	groups, err := s.store.ListGroups(ctx, t.ID)
	if err != nil {
		return err
	}
	err = s.store.InTx(ctx, func(tx store.Tx) error {
		if err := s.removeFromGroups(ctx, tx, m, groups); err != nil {
			return err
		}
		if err := tx.DeleteMember(ctx, t.ID, m.ID); err != nil {
			return err
		}
		return s.appendEvent(ctx, tx, sdk.EventMemberRemoved, t.ID, "tenants/"+t.ID+"/members/"+m.ID, sdk.MemberEventData{Member: m})
	})
	if err != nil {
		return err
	}
	s.notify()
	return nil
}

// runMemberHooks lets hooks adjust Role and UserID (add/update only).
func (s *Service) runMemberHooks(ctx context.Context, point sdk.HookPoint, t sdk.Tenant, m sdk.Member) (sdk.Member, error) {
	if s.hooks == nil {
		return m, nil
	}
	tc := t.Clone()
	proposed := m
	req := &sdk.HookRequest{Point: point, Tenant: &tc, Member: &proposed}
	if err := s.hooks.RunHooks(ctx, req); err != nil {
		return sdk.Member{}, err
	}
	if point == sdk.HookBeforeMemberRemove || req.Member == nil {
		return m, nil
	}
	// Hooks may only change the role: who the member is comes from the
	// user record.
	out := m
	out.Role = req.Member.Role
	if err := s.validateMember(&out); err != nil {
		return sdk.Member{}, fmt.Errorf("hook produced invalid member: %w", err)
	}
	return out, nil
}
