package tenant

import (
	"context"
	"errors"
	"maps"
	"net/mail"
	"regexp"
	"slices"
	"unicode/utf8"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/google/uuid"
)

// Slugs are DNS labels so they can be used in subdomains, schema names, etc.
var slugRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Label keys follow the Kubernetes style: optional prefix + name.
var labelKeyRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?/)?[A-Za-z0-9]([A-Za-z0-9._-]{0,61}[A-Za-z0-9])?$`)

// Feature, limit and metric names: lowercase identifiers with . _ : -
var keyRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{0,63}$`)

const (
	maxNameLen       = 200
	maxLabels        = 64
	maxLabelValueLen = 256
	maxKeys          = 256
)

func (s *Service) validateTenant(t *sdk.Tenant) error {
	if !slugRe.MatchString(t.Slug) {
		return invalid("slug", "must be 1-63 lowercase letters, digits or '-', starting and ending alphanumeric")
	}
	// Tenants are looked up by "ID or slug"; a UUID-shaped slug would be
	// ambiguous or unreachable.
	if _, err := uuid.Parse(t.Slug); err == nil {
		return invalid("slug", "must not look like a UUID")
	}
	if t.Name == "" || utf8.RuneCountInString(t.Name) > maxNameLen {
		return invalid("name", "must be 1-%d characters", maxNameLen)
	}
	if t.Plan != "" && !slugRe.MatchString(t.Plan) {
		return invalid("plan", "invalid plan id %q", t.Plan)
	}
	if len(t.Labels) > maxLabels {
		return invalid("labels", "at most %d labels allowed", maxLabels)
	}
	for k, v := range t.Labels {
		if !labelKeyRe.MatchString(k) {
			return invalid("labels", "invalid key %q", k)
		}
		if len(v) > maxLabelValueLen {
			return invalid("labels", "value of %q exceeds %d bytes", k, maxLabelValueLen)
		}
	}
	if err := validateEntitlementKeys(t.Features, t.Limits); err != nil {
		return err
	}
	if err := s.validatePlacement(t); err != nil {
		return err
	}
	if err := validateBranding(t.Branding); err != nil {
		return err
	}
	if s.settingsSchema != nil {
		settings := t.Settings
		if settings == nil {
			settings = map[string]any{}
		}
		if err := s.settingsSchema.Validate(settings); err != nil {
			return invalid("settings", "%v", err)
		}
	}
	return nil
}

func validateEntitlementKeys(features map[string]bool, limits map[string]int64) error {
	if len(features) > maxKeys || len(limits) > maxKeys {
		return invalid("features", "at most %d features and %d limits", maxKeys, maxKeys)
	}
	for k := range features {
		if !keyRe.MatchString(k) {
			return invalid("features", "invalid feature name %q", k)
		}
	}
	for k, v := range limits {
		if !keyRe.MatchString(k) {
			return invalid("limits", "invalid limit name %q", k)
		}
		if v < 0 {
			return invalid("limits", "limit %q must not be negative", k)
		}
	}
	return nil
}

func validatePlan(p *sdk.Plan) error {
	if !slugRe.MatchString(p.ID) {
		return invalid("id", "must be 1-63 lowercase letters, digits or '-'")
	}
	if p.Name == "" || utf8.RuneCountInString(p.Name) > maxNameLen {
		return invalid("name", "must be 1-%d characters", maxNameLen)
	}
	return validateEntitlementKeys(p.Features, p.Limits)
}

func (s *Service) validateMember(m *sdk.Member) error {
	addr, err := mail.ParseAddress(m.Email)
	if err != nil || addr.Address != m.Email {
		return invalid("email", "must be a plain email address")
	}
	if len(m.UserID) > 256 {
		return invalid("user_id", "too long")
	}
	return nil
}

// mergePatch applies an RFC 7386 JSON merge patch to dst: null deletes a
// key, objects merge recursively, anything else replaces.
func mergePatch(dst, patch map[string]any) map[string]any {
	if dst == nil {
		dst = map[string]any{}
	}
	for k, pv := range patch {
		if pv == nil {
			delete(dst, k)
			continue
		}
		if pm, ok := pv.(map[string]any); ok {
			dm, _ := dst[k].(map[string]any)
			dst[k] = mergePatch(maps.Clone(dm), pm)
			continue
		}
		dst[k] = pv
	}
	return dst
}

const maxAddOns = 20

func (s *Service) validatePlacement(t *sdk.Tenant) error {
	if len(t.AddOns) > maxAddOns {
		return invalid("add_ons", "at most %d add-ons", maxAddOns)
	}
	for i, a := range t.AddOns {
		if !slugRe.MatchString(a) {
			return invalid("add_ons", "invalid plan id %q", a)
		}
		if a == t.Plan || slices.Contains(t.AddOns[:i], a) {
			return invalid("add_ons", "%q is already applied", a)
		}
	}
	regions := s.live.Load().regions
	if len(regions) == 0 {
		if t.Region != "" && !slugRe.MatchString(t.Region) {
			return invalid("region", "invalid region %q", t.Region)
		}
		return nil
	}
	// Tenants created before regions were configured may have none; Create
	// and MoveRegion require one.
	if t.Region != "" && !slices.Contains(regions, t.Region) {
		return invalid("region", "must be one of %v", regions)
	}
	return nil
}

// checkAddOns requires every add-on to be a defined plan: unlike the base
// plan, an add-on is meaningless without one.
func (s *Service) checkAddOns(ctx context.Context, ids []string) error {
	for _, id := range ids {
		if _, err := s.store.GetPlan(ctx, id); errors.Is(err, store.ErrNotFound) {
			return invalid("add_ons", "unknown plan %q", id)
		} else if err != nil {
			return err
		}
	}
	return nil
}
