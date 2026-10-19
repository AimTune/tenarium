package tenant

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// Regions returns the allowed regions (empty: any).
func (s *Service) Regions() []string { return slices.Clone(s.live.Load().regions) }

// MoveInput moves a tenant to another region.
type MoveInput struct {
	Region string `json:"region"`
	// Reprovision runs the provisioners again in the new region: the
	// tenant enters a maintenance window and the provisioning state, and
	// the window ends when the region-scoped provisioners there succeed.
	Reprovision bool `json:"reprovision,omitempty"`
}

// MoveRegion changes a tenant's region and emits tenant.region_changed,
// which reaches plugin instances scoped to the old and the new region.
// Without reprovisioning Tenarium only records the placement and
// subscribers do the migration; with it, the new region's provisioners
// run (see MoveInput). Copying data between regions is up to the data
// stores or the old region's plugins.
func (s *Service) MoveRegion(ctx context.Context, idOrSlug string, in MoveInput) (sdk.Tenant, error) {
	if in.Region == "" {
		return sdk.Tenant{}, invalid("region", "required")
	}
	if in.Reprovision && !s.provisioned {
		return sdk.Tenant{}, invalid("reprovision", "no provisioner plugins are configured")
	}
	now := s.now()
	return s.mutate(ctx, idOrSlug, nil, "", sdk.EventTenantRegionChanged, func(t *sdk.Tenant) error {
		switch {
		case !t.IsLive():
			return transitionErr("move", t.Status)
		case t.Region == in.Region:
			return stateErr("tenant is already in region %q", in.Region)
		case in.Reprovision && t.Status != sdk.StatusActive:
			return transitionErr("move and reprovision", t.Status)
		}
		t.Region = in.Region
		if in.Reprovision {
			t.Status, t.StatusReason = sdk.StatusProvisioning, "moving to "+in.Region
			t.Maintenance = &sdk.Maintenance{Message: "moving to region " + in.Region, StartedAt: now, MoveTo: in.Region}
		}
		return nil
	})
}

// liveSettings are the settings a configuration reload can change while
// running; they are replaced as a whole.
type liveSettings struct {
	regions       []string
	defaultRegion string
	metrics       map[string]MetricPolicy
}

// SetRegions replaces the allowed regions and the default region.
// Existing tenants keep their region even if it is no longer listed.
func (s *Service) SetRegions(regions []string, defaultRegion string) error {
	if defaultRegion != "" && len(regions) > 0 && !slices.Contains(regions, defaultRegion) {
		return fmt.Errorf("default region %q is not in regions", defaultRegion)
	}
	for {
		cur := s.live.Load()
		next := *cur
		next.regions, next.defaultRegion = slices.Clone(regions), defaultRegion
		if s.live.CompareAndSwap(cur, &next) {
			return nil
		}
	}
}

// SetMetricPolicies replaces the usage policies. Counters already in a
// period keep it until the next increment, which uses the new policy.
func (s *Service) SetMetricPolicies(p map[string]MetricPolicy) error {
	if err := ValidateMetricPolicies(p); err != nil {
		return err
	}
	for {
		cur := s.live.Load()
		next := *cur
		next.metrics = maps.Clone(p)
		if s.live.CompareAndSwap(cur, &next) {
			return nil
		}
	}
}
