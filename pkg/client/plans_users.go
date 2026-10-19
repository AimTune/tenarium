package client

import (
	"context"
	"iter"
	"net/http"
	"net/url"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// PlansService manages plans (/v1/plans).
type PlansService struct{ c *Client }

// CreatePlanRequest creates a plan.
type CreatePlanRequest struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Features    map[string]bool  `json:"features,omitempty"`
	Limits      map[string]int64 `json:"limits,omitempty"`
}

// UpdatePlanRequest is a partial update; Features and Limits replace the
// whole map when non-nil.
type UpdatePlanRequest struct {
	Name        *string           `json:"name,omitempty"`
	Description *string           `json:"description,omitempty"`
	Features    *map[string]bool  `json:"features,omitempty"`
	Limits      *map[string]int64 `json:"limits,omitempty"`
	// Grandfather pins the tenants on the plan to its current revision.
	Grandfather bool `json:"grandfather,omitempty"`
}

// List returns all plans.
func (s *PlansService) List(ctx context.Context, opts ...CallOption) ([]sdk.Plan, error) {
	var out struct {
		Items []sdk.Plan `json:"items"`
	}
	err := s.c.do(ctx, http.MethodGet, "/v1/plans", nil, nil, &out, opts...)
	return out.Items, err
}

// Create creates a plan.
func (s *PlansService) Create(ctx context.Context, req CreatePlanRequest, opts ...CallOption) (sdk.Plan, error) {
	var p sdk.Plan
	err := s.c.do(ctx, http.MethodPost, "/v1/plans", nil, req, &p, append([]CallOption{autoIdempotency()}, opts...)...)
	return p, err
}

// Get returns a plan.
func (s *PlansService) Get(ctx context.Context, id string, opts ...CallOption) (sdk.Plan, error) {
	return s.plan(ctx, http.MethodGet, id, nil, opts)
}

// Update applies a partial update; use IfMatch(p.Version) for optimistic locking.
func (s *PlansService) Update(ctx context.Context, id string, req UpdatePlanRequest, opts ...CallOption) (sdk.Plan, error) {
	return s.plan(ctx, http.MethodPatch, id, req, opts)
}

// Delete deletes a plan.
func (s *PlansService) Delete(ctx context.Context, id string, opts ...CallOption) error {
	if err := checkIDs(id); err != nil {
		return err
	}
	err := s.c.do(ctx, http.MethodDelete, "/v1/plans/"+esc(id), nil, nil, nil, opts...)
	return err
}

func (s *PlansService) plan(ctx context.Context, method, id string, body any, opts []CallOption) (sdk.Plan, error) {
	var p sdk.Plan
	if err := checkIDs(id); err != nil {
		return p, err
	}
	err := s.c.do(ctx, method, "/v1/plans/"+esc(id), nil, body, &p, opts...)
	return p, err
}

// UsersService manages platform users (/v1/users). User arguments accept
// an ID or an email address.
type UsersService struct{ c *Client }

// CreateUserRequest creates a user.
type CreateUserRequest struct {
	Email      string            `json:"email"`
	Name       string            `json:"name,omitempty"`
	Roles      []string          `json:"roles,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	// Password activates the user immediately (no invitation).
	Password string `json:"password,omitempty"`
	// SendInvitation emails a setup link to a user created without a
	// password. The server defaults to true.
	SendInvitation *bool `json:"send_invitation,omitempty"`
}

// UpdateUserRequest is a partial user update.
type UpdateUserRequest struct {
	Email         *string            `json:"email,omitempty"`
	Name          *string            `json:"name,omitempty"`
	Roles         *[]string          `json:"roles,omitempty"`
	Attributes    *map[string]string `json:"attributes,omitempty"`
	EmailVerified *bool              `json:"email_verified,omitempty"`
}

// UserListOptions filter and paginate user lists.
type UserListOptions struct {
	// Query searches email and name.
	Query  string
	Status sdk.UserStatus
	After  string
	Limit  int
}

// List returns one page of users.
func (s *UsersService) List(ctx context.Context, o UserListOptions, opts ...CallOption) (Page[sdk.User], error) {
	q := url.Values{}
	setStr(q, "q", o.Query)
	setStr(q, "status", string(o.Status))
	setStr(q, "after", o.After)
	setLimit(q, o.Limit)
	var p Page[sdk.User]
	err := s.c.do(ctx, http.MethodGet, "/v1/users", q, nil, &p, opts...)
	return p, err
}

// All iterates over every user matching o.
func (s *UsersService) All(ctx context.Context, o UserListOptions, opts ...CallOption) iter.Seq2[sdk.User, error] {
	return paginate(ctx, o.After, func(ctx context.Context, after string) (Page[sdk.User], error) {
		o.After = after
		return s.List(ctx, o, opts...)
	})
}

// Create creates a user.
func (s *UsersService) Create(ctx context.Context, req CreateUserRequest, opts ...CallOption) (sdk.User, error) {
	var u sdk.User
	err := s.c.do(ctx, http.MethodPost, "/v1/users", nil, req, &u, append([]CallOption{autoIdempotency()}, opts...)...)
	return u, err
}

// Get returns a user by ID or email.
func (s *UsersService) Get(ctx context.Context, id string, opts ...CallOption) (sdk.User, error) {
	return s.user(ctx, http.MethodGet, id, "", nil, opts)
}

// Update applies a partial update; use IfMatch(u.Version) for optimistic locking.
func (s *UsersService) Update(ctx context.Context, id string, req UpdateUserRequest, opts ...CallOption) (sdk.User, error) {
	return s.user(ctx, http.MethodPatch, id, "", req, opts)
}

// Delete deletes a user.
func (s *UsersService) Delete(ctx context.Context, id string, opts ...CallOption) error {
	return s.noContent(ctx, http.MethodDelete, id, "", nil, opts)
}

// Disable blocks sign-in and revokes the user's sessions.
func (s *UsersService) Disable(ctx context.Context, id string, opts ...CallOption) (sdk.User, error) {
	return s.user(ctx, http.MethodPost, id, "/disable", nil, opts)
}

// Enable re-enables a disabled user.
func (s *UsersService) Enable(ctx context.Context, id string, opts ...CallOption) (sdk.User, error) {
	return s.user(ctx, http.MethodPost, id, "/enable", nil, opts)
}

// SetPassword sets a user's password as an administrator.
func (s *UsersService) SetPassword(ctx context.Context, id, password string, opts ...CallOption) error {
	body := struct {
		Password string `json:"password"`
	}{password}
	return s.noContent(ctx, http.MethodPost, id, "/password", body, opts)
}

// ResendInvitation sends a new invitation email to an invited user.
func (s *UsersService) ResendInvitation(ctx context.Context, id string, opts ...CallOption) error {
	return s.noContent(ctx, http.MethodPost, id, "/invitation", nil, opts)
}

// RevokeSessions signs the user out everywhere (refresh tokens are revoked).
func (s *UsersService) RevokeSessions(ctx context.Context, id string, opts ...CallOption) error {
	return s.noContent(ctx, http.MethodDelete, id, "/sessions", nil, opts)
}

// Memberships lists the user's tenant memberships.
func (s *UsersService) Memberships(ctx context.Context, id string, opts ...CallOption) ([]sdk.Member, error) {
	if err := checkIDs(id); err != nil {
		return nil, err
	}
	var out struct {
		Items []sdk.Member `json:"items"`
	}
	err := s.c.do(ctx, http.MethodGet, "/v1/users/"+esc(id)+"/memberships", nil, nil, &out, opts...)
	return out.Items, err
}

func (s *UsersService) user(ctx context.Context, method, id, suffix string, body any, opts []CallOption) (sdk.User, error) {
	var u sdk.User
	if err := checkIDs(id); err != nil {
		return u, err
	}
	err := s.c.do(ctx, method, "/v1/users/"+esc(id)+suffix, nil, body, &u, opts...)
	return u, err
}

func (s *UsersService) noContent(ctx context.Context, method, id, suffix string, body any, opts []CallOption) error {
	if err := checkIDs(id); err != nil {
		return err
	}
	err := s.c.do(ctx, method, "/v1/users/"+esc(id)+suffix, nil, body, nil, opts...)
	return err
}
