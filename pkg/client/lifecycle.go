package client

import (
	"context"
	"net/http"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// MoveOptions moves a tenant to another region.
type MoveOptions struct {
	// Reprovision runs the provisioners in the new region inside a
	// maintenance window that ends when they succeed.
	Reprovision bool `json:"reprovision,omitempty"`
}

// Move changes a tenant's region (platform-only: tenants:move).
func (s *TenantsService) Move(ctx context.Context, id, region string, o MoveOptions, opts ...CallOption) (sdk.Tenant, error) {
	body := struct {
		Region      string `json:"region"`
		Reprovision bool   `json:"reprovision,omitempty"`
	}{region, o.Reprovision}
	return s.tenant(ctx, http.MethodPost, id, "/move", body, opts)
}

// CloneTenantRequest names the copy of a tenant.
type CloneTenantRequest struct {
	Slug     string `json:"slug"`
	Name     string `json:"name"`
	ParentID string `json:"parent_id,omitempty"`
	// Members also copies the source's active memberships.
	Members bool `json:"members,omitempty"`
}

// Clone creates a tenant with the source's configuration and custom roles.
func (s *TenantsService) Clone(ctx context.Context, id string, req CloneTenantRequest, opts ...CallOption) (sdk.Tenant, error) {
	return s.tenant(ctx, http.MethodPost, id, "/clone", req, opts)
}

// SetPlanRevision pins the tenant to a revision of its plan (0 unpins).
func (s *TenantsService) SetPlanRevision(ctx context.Context, id string, revision int64, opts ...CallOption) (sdk.Tenant, error) {
	body := struct {
		Revision int64 `json:"revision"`
	}{revision}
	return s.tenant(ctx, http.MethodPut, id, "/plan-revision", body, opts)
}

// StartMaintenance makes the tenant read-only for its own users, until
// EndMaintenance or until (if non-zero).
func (s *TenantsService) StartMaintenance(ctx context.Context, id, message string, until time.Time, opts ...CallOption) (sdk.Tenant, error) {
	body := struct {
		Message string     `json:"message,omitempty"`
		Until   *time.Time `json:"until,omitempty"`
	}{Message: message}
	if !until.IsZero() {
		body.Until = &until
	}
	return s.tenant(ctx, http.MethodPost, id, "/maintenance", body, opts)
}

// EndMaintenance ends the tenant's maintenance window.
func (s *TenantsService) EndMaintenance(ctx context.Context, id string, opts ...CallOption) (sdk.Tenant, error) {
	return s.tenant(ctx, http.MethodDelete, id, "/maintenance", nil, opts)
}

// Health is a tenant's health score and the factors behind it.
type Health struct {
	TenantID string `json:"tenant_id"`
	Score    int    `json:"score"`
	Grade    string `json:"grade"`
	Factors  []struct {
		Name   string `json:"name"`
		Impact int    `json:"impact"`
		Detail string `json:"detail"`
	} `json:"factors"`
}

// Health returns the tenant's health score.
func (s *TenantsService) Health(ctx context.Context, id string, opts ...CallOption) (Health, error) {
	var h Health
	if err := checkIDs(id); err != nil {
		return h, err
	}
	err := s.c.do(ctx, http.MethodGet, "/v1/tenants/"+esc(id)+"/health", nil, nil, &h, opts...)
	return h, err
}

// PlanRevision is a snapshot of a plan's features and limits.
type PlanRevision struct {
	PlanID    string           `json:"plan_id"`
	Revision  int64            `json:"revision"`
	Features  map[string]bool  `json:"features,omitempty"`
	Limits    map[string]int64 `json:"limits,omitempty"`
	CreatedAt time.Time        `json:"created_at"`
}

// Revisions lists a plan's recorded revisions, newest first.
func (s *PlansService) Revisions(ctx context.Context, id string, opts ...CallOption) ([]PlanRevision, error) {
	var out struct {
		Items []PlanRevision `json:"items"`
	}
	if err := checkIDs(id); err != nil {
		return nil, err
	}
	err := s.c.do(ctx, http.MethodGet, "/v1/plans/"+esc(id)+"/revisions", nil, nil, &out, opts...)
	return out.Items, err
}

// RolloutsService manages feature rollouts (/v1/rollouts; platform-only).
type RolloutsService struct{ c *Client }

// Rollout enables a feature for a stable percentage of matching tenants.
type Rollout struct {
	Feature    string            `json:"feature,omitempty"`
	Percentage int               `json:"percentage"`
	Plans      []string          `json:"plans,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	Regions    []string          `json:"regions,omitempty"`
	Include    []string          `json:"include,omitempty"`
	Exclude    []string          `json:"exclude,omitempty"`
	Enabled    bool              `json:"enabled"`
	UpdatedAt  time.Time         `json:"updated_at,omitempty"`
}

// List returns all rollouts.
func (s *RolloutsService) List(ctx context.Context, opts ...CallOption) ([]Rollout, error) {
	var out struct {
		Items []Rollout `json:"items"`
	}
	err := s.c.do(ctx, http.MethodGet, "/v1/rollouts", nil, nil, &out, opts...)
	return out.Items, err
}

// Get returns the rollout of a feature.
func (s *RolloutsService) Get(ctx context.Context, feature string, opts ...CallOption) (Rollout, error) {
	var r Rollout
	if err := checkIDs(feature); err != nil {
		return r, err
	}
	err := s.c.do(ctx, http.MethodGet, "/v1/rollouts/"+esc(feature), nil, nil, &r, opts...)
	return r, err
}

// Put creates or replaces the rollout of feature.
func (s *RolloutsService) Put(ctx context.Context, feature string, r Rollout, opts ...CallOption) (Rollout, error) {
	var out Rollout
	if err := checkIDs(feature); err != nil {
		return out, err
	}
	err := s.c.do(ctx, http.MethodPut, "/v1/rollouts/"+esc(feature), nil, r, &out, opts...)
	return out, err
}

// Delete removes the rollout of feature.
func (s *RolloutsService) Delete(ctx context.Context, feature string, opts ...CallOption) error {
	if err := checkIDs(feature); err != nil {
		return err
	}
	return s.c.do(ctx, http.MethodDelete, "/v1/rollouts/"+esc(feature), nil, nil, nil, opts...)
}

// TemplatesService manages tenant templates (/v1/tenant-templates).
type TemplatesService struct{ c *Client }

// TemplateRole is a custom role a template creates.
type TemplateRole struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Actions     []string `json:"actions"`
}

// TenantTemplate presets new tenants.
type TenantTemplate struct {
	ID          string            `json:"id,omitempty"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Plan        string            `json:"plan,omitempty"`
	AddOns      []string          `json:"add_ons,omitempty"`
	Region      string            `json:"region,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Settings    map[string]any    `json:"settings,omitempty"`
	Features    map[string]bool   `json:"features,omitempty"`
	Limits      map[string]int64  `json:"limits,omitempty"`
	Branding    *sdk.Branding     `json:"branding,omitempty"`
	Roles       []TemplateRole    `json:"roles,omitempty"`
	UpdatedAt   time.Time         `json:"updated_at,omitempty"`
}

// List returns all templates.
func (s *TemplatesService) List(ctx context.Context, opts ...CallOption) ([]TenantTemplate, error) {
	var out struct {
		Items []TenantTemplate `json:"items"`
	}
	err := s.c.do(ctx, http.MethodGet, "/v1/tenant-templates", nil, nil, &out, opts...)
	return out.Items, err
}

// Get returns a template.
func (s *TemplatesService) Get(ctx context.Context, id string, opts ...CallOption) (TenantTemplate, error) {
	var t TenantTemplate
	if err := checkIDs(id); err != nil {
		return t, err
	}
	err := s.c.do(ctx, http.MethodGet, "/v1/tenant-templates/"+esc(id), nil, nil, &t, opts...)
	return t, err
}

// Put creates or replaces a template.
func (s *TemplatesService) Put(ctx context.Context, id string, t TenantTemplate, opts ...CallOption) (TenantTemplate, error) {
	var out TenantTemplate
	if err := checkIDs(id); err != nil {
		return out, err
	}
	err := s.c.do(ctx, http.MethodPut, "/v1/tenant-templates/"+esc(id), nil, t, &out, opts...)
	return out, err
}

// Delete removes a template.
func (s *TemplatesService) Delete(ctx context.Context, id string, opts ...CallOption) error {
	if err := checkIDs(id); err != nil {
		return err
	}
	return s.c.do(ctx, http.MethodDelete, "/v1/tenant-templates/"+esc(id), nil, nil, nil, opts...)
}
