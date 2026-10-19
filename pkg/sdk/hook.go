package sdk

import (
	"context"
	"errors"
	"fmt"
)

// HookPoint identifies where in a tenant operation a hook runs. Hooks run
// synchronously, before anything is persisted, in ascending priority order.
type HookPoint string

const (
	// HookBeforeTenantCreate may mutate Tenant (e.g. set default labels or
	// settings) or reject the creation.
	HookBeforeTenantCreate HookPoint = "tenant.before_create"
	// HookBeforeTenantUpdate may mutate Tenant or reject the update.
	HookBeforeTenantUpdate HookPoint = "tenant.before_update"
	// The remaining points are validation-only; mutations are ignored.
	HookBeforeTenantSuspend HookPoint = "tenant.before_suspend"
	HookBeforeTenantResume  HookPoint = "tenant.before_resume"
	HookBeforeTenantDelete  HookPoint = "tenant.before_delete"

	// HookBeforeMemberAdd and HookBeforeMemberUpdate may change Member.Role
	// or reject the change. HookBeforeMemberRemove is validation-only. For
	// member hooks, Tenant is the member's tenant.
	HookBeforeMemberAdd    HookPoint = "member.before_add"
	HookBeforeMemberUpdate HookPoint = "member.before_update"
	HookBeforeMemberRemove HookPoint = "member.before_remove"

	// HookBeforeUserCreate and HookBeforeUserUpdate may change User.Name,
	// Roles and Attributes, or reject the change (e.g. allow only some email
	// domains). Tenant is nil for user hooks.
	HookBeforeUserCreate HookPoint = "user.before_create"
	HookBeforeUserUpdate HookPoint = "user.before_update"
)

// HookPoints lists every hook point.
var HookPoints = []HookPoint{
	HookBeforeTenantCreate, HookBeforeTenantUpdate, HookBeforeTenantSuspend,
	HookBeforeTenantResume, HookBeforeTenantDelete, HookBeforeMemberAdd, HookBeforeMemberUpdate, HookBeforeMemberRemove,
	HookBeforeUserCreate, HookBeforeUserUpdate,
}

// HookRequest carries the proposed change.
type HookRequest struct {
	Point HookPoint `json:"point"`
	// Tenant is the proposed state. Identity and lifecycle fields (ID,
	// Status, Version, timestamps) are restored by the core after hooks run,
	// so hooks cannot bypass the state machine.
	Tenant *Tenant `json:"tenant"`
	// Previous is the persisted state; nil for create.
	Previous *Tenant `json:"previous,omitempty"`
	// Member is set for member hooks.
	Member *Member `json:"member,omitempty"`
	// User is set for user hooks.
	User *User `json:"user,omitempty"`
}

// HookHandler inspects and optionally mutates a HookRequest. Return an error
// created with Reject to refuse the operation with a client-visible reason;
// any other error is treated as an internal failure.
type HookHandler func(ctx context.Context, req *HookRequest) error

type HookOptions struct {
	// Priority orders hooks at the same point; lower runs first. Default 0.
	Priority int
}

type HookOption func(*HookOptions)

func WithPriority(p int) HookOption {
	return func(o *HookOptions) { o.Priority = p }
}

// RejectError is a business-rule rejection returned by a hook.
type RejectError struct {
	Reason string
}

func (e *RejectError) Error() string { return "rejected: " + e.Reason }

// Reject builds a RejectError.
func Reject(format string, args ...any) error {
	return &RejectError{Reason: fmt.Sprintf(format, args...)}
}

// IsReject reports whether err (or something it wraps) is a RejectError.
func IsReject(err error) (*RejectError, bool) {
	var re *RejectError
	ok := errors.As(err, &re)
	return re, ok
}
