package gcstenant

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// deletedAtLayout formats tenarium-deleted-at as a valid label value
// (lowercase, no colons).
const deletedAtLayout = "2006-01-02t15-04-05z"

// maxAttempts bounds read-modify-write retries after a failed
// metageneration/generation precondition.
const maxAttempts = 3

func (p *Plugin) provisionBucket(ctx context.Context, name string, t sdk.Tenant, quota string) error {
	for attempt := 1; ; attempt++ {
		err := p.provisionBucketOnce(ctx, name, t, quota)
		if isPrecondition(err) && attempt < maxAttempts {
			continue // the bucket changed concurrently: read it again
		}
		return err
	}
}

func (p *Plugin) provisionBucketOnce(ctx context.Context, name string, t sdk.Tenant, quota string) error {
	b, created, err := p.ensureBucket(ctx, name, t, quota)
	if err != nil {
		return err
	}
	// Check ownership before changing anything else about the bucket.
	if p.cfg.Ownership == OwnershipObject {
		if err := p.provisionMarker(ctx, name, "", t, quota, created); err != nil {
			return err
		}
	} else if err := p.claimBucket(ctx, b, t, created); err != nil {
		return err
	}
	if !created && p.cfg.Location != "" && !strings.EqualFold(b.Location, p.cfg.Location) {
		p.log.Warn("bucket location differs from the configured location and cannot be changed",
			"bucket", name, "location", b.Location, "configured", p.cfg.Location)
	}

	patch, err := p.bucketPatch(b, t, quota)
	if err != nil || len(patch) == 0 {
		return err
	}
	nb, err := p.gcs.patchBucket(ctx, name, b.Metageneration, patch)
	if isPrecondition(err) {
		return err
	} else if err != nil {
		return fmt.Errorf("update bucket %s: %w", name, err)
	}
	if p.cfg.Ownership == OwnershipLabels && nb.Labels[LabelTenantID] != LabelValue(t.ID) {
		// fake-gcs-server and some other emulators drop bucket labels.
		return fmt.Errorf("the storage endpoint did not persist the ownership label of bucket %s; it does not support bucket labels, use ownership: object", name)
	}
	return nil
}

// ensureBucket returns the bucket, creating it with the configured
// settings if it does not exist. created reports whether this call created
// it (and so it is known to be empty).
func (p *Plugin) ensureBucket(ctx context.Context, name string, t sdk.Tenant, quota string) (*bucket, bool, error) {
	b, err := p.gcs.getBucket(ctx, name)
	if err == nil {
		return b, false, nil
	}
	if !isNotFound(err) {
		return nil, false, bucketErr(name, err)
	}
	labels, err := p.customLabels(t)
	if err != nil {
		return nil, false, err
	}
	if p.cfg.Ownership == OwnershipLabels {
		labels[LabelTenantID] = LabelValue(t.ID)
		if quota != "" {
			labels[LabelQuotaGB] = quota
		}
	}
	req := map[string]any{"name": name}
	if len(labels) > 0 {
		req["labels"] = labels
	}
	if p.cfg.Location != "" {
		req["location"] = p.cfg.Location
	}
	if p.cfg.StorageClass != "" {
		req["storageClass"] = p.cfg.StorageClass
	}
	if p.cfg.Versioning {
		req["versioning"] = map[string]any{"enabled": true}
	}
	if rules, changed := p.lifecycleRules(nil); changed {
		req["lifecycle"] = map[string]any{"rule": rules}
	}
	if iam := p.iamConfiguration(nil); iam != nil {
		req["iamConfiguration"] = iam
	}

	created := true
	switch err := p.gcs.createBucket(ctx, p.cfg.Project, req); statusOf(err) {
	case 0:
		if err != nil {
			return nil, false, fmt.Errorf("create bucket %s: %w", name, err)
		}
	case http.StatusConflict: // created concurrently, or taken by someone else
		created = false
	default:
		return nil, false, fmt.Errorf("create bucket %s: %w", name, err)
	}
	b, err = p.gcs.getBucket(ctx, name)
	if err != nil {
		return nil, false, bucketErr(name, err)
	}
	return b, created, nil
}

func bucketErr(name string, err error) error {
	if statusOf(err) == http.StatusForbidden {
		return fmt.Errorf("bucket %s exists but is not accessible; bucket names are global, so it probably belongs to another project (use a more specific name_template): %w", name, err)
	}
	return fmt.Errorf("bucket %s: %w", name, err)
}

// claimBucket checks that an existing bucket may be used by t (ownership:
// labels). Buckets labeled for another tenant or retained from a deleted
// one are refused. Unlabeled buckets are adopted only when they are empty:
// those are left by a Provision that stopped before labeling the bucket.
func (p *Plugin) claimBucket(ctx context.Context, b *bucket, t sdk.Tenant, created bool) error {
	switch owner := b.Labels[LabelTenantID]; {
	case owner == LabelValue(t.ID):
		return nil
	case owner != "":
		return fmt.Errorf("bucket %s already exists and belongs to another tenant (%s)", b.Name, owner)
	case b.Labels[LabelDeletedAt] != "":
		return fmt.Errorf("bucket %s holds data retained from deleted tenant %s (deleted at %s); remove or rename it before provisioning a tenant with this name",
			b.Name, b.Labels[LabelDeletedTenantID], b.Labels[LabelDeletedAt])
	}
	if created {
		return nil
	}
	empty, err := p.isEmpty(ctx, b.Name, "")
	if err != nil {
		return err
	}
	if !empty {
		return fmt.Errorf("bucket %s already exists, is not empty and is not managed by tenarium", b.Name)
	}
	return nil
}

// customLabels renders the configured labels for t.
func (p *Plugin) customLabels(t sdk.Tenant) (map[string]string, error) {
	out := make(map[string]string, len(p.labels)+2)
	for k, tmpl := range p.labels {
		var b strings.Builder
		if err := tmpl.Execute(&b, t); err != nil {
			return nil, fmt.Errorf("labels.%s: %w", k, err)
		}
		out[k] = sanitizeLabelValue(b.String())
	}
	return out, nil
}

// bucketPatch returns the PATCH body that brings b to the configured state,
// or nil when it already is.
func (p *Plugin) bucketPatch(b *bucket, t sdk.Tenant, quota string) (map[string]any, error) {
	want, err := p.customLabels(t)
	if err != nil {
		return nil, err
	}
	labels := map[string]any{}
	if p.cfg.Ownership == OwnershipLabels {
		want[LabelTenantID] = LabelValue(t.ID)
		if quota != "" {
			want[LabelQuotaGB] = quota
		} else if _, ok := b.Labels[LabelQuotaGB]; ok {
			labels[LabelQuotaGB] = nil // limit removed: remove the label
		}
	}
	for k, v := range want {
		if cur, ok := b.Labels[k]; !ok || cur != v {
			labels[k] = v
		}
	}

	patch := map[string]any{}
	if len(labels) > 0 {
		patch["labels"] = labels // PATCH merges labels; null removes one
	}
	if p.cfg.StorageClass != "" && b.StorageClass != p.cfg.StorageClass {
		patch["storageClass"] = p.cfg.StorageClass
	}
	if p.cfg.Versioning && !b.versioningEnabled() {
		patch["versioning"] = map[string]any{"enabled": true}
	}
	if rules, changed := p.lifecycleRules(b); changed {
		patch["lifecycle"] = map[string]any{"rule": rules}
	}
	if iam := p.iamConfiguration(b); iam != nil {
		patch["iamConfiguration"] = iam
	}
	if len(patch) > 0 && b.versioningEnabled() {
		// fake-gcs-server resets versioning on any PATCH that omits it;
		// restating the current value is a no-op on GCS.
		if _, ok := patch["versioning"]; !ok {
			patch["versioning"] = map[string]any{"enabled": true}
		}
	}
	return patch, nil
}

// iamConfiguration returns the iamConfiguration to send, or nil if b (nil
// for a new bucket) already matches the configuration.
func (p *Plugin) iamConfiguration(b *bucket) map[string]any {
	wantUBLA := p.cfg.UniformBucketLevelAccess != nil && *p.cfg.UniformBucketLevelAccess
	curUBLA, curPAP := false, ""
	if b != nil && b.IAMConfiguration != nil {
		curUBLA = b.IAMConfiguration.UniformBucketLevelAccess != nil && b.IAMConfiguration.UniformBucketLevelAccess.Enabled
		curPAP = b.IAMConfiguration.PublicAccessPrevention
	}
	needUBLA := wantUBLA && !curUBLA
	needPAP := p.cfg.PublicAccessPrevention != "" && curPAP != p.cfg.PublicAccessPrevention
	if !needUBLA && !needPAP {
		return nil
	}
	iam := map[string]any{}
	if wantUBLA || curUBLA {
		iam["uniformBucketLevelAccess"] = map[string]any{"enabled": true}
	}
	if pap := p.cfg.PublicAccessPrevention; pap != "" {
		iam["publicAccessPrevention"] = pap
	} else if curPAP != "" {
		iam["publicAccessPrevention"] = curPAP
	}
	return iam
}

// Lifecycle rules managed by lifecycle_expire_days are Delete rules whose
// only condition is "age" (objects older than N days) or
// "daysSinceNoncurrentTime" (noncurrent generations, with versioning).
// GCS rules have no IDs, so any rule of that exact shape is considered
// managed and replaced; every other rule is kept.
var managedConditions = []string{"age", "daysSinceNoncurrentTime"}

func isManagedRule(r map[string]any) bool {
	action, _ := r["action"].(map[string]any)
	cond, _ := r["condition"].(map[string]any)
	if action == nil || action["type"] != "Delete" || len(cond) != 1 {
		return false
	}
	for k := range cond {
		return slices.Contains(managedConditions, k)
	}
	return false
}

// lifecycleRules returns the full rule list for b (nil for a new bucket)
// and whether it differs from the current one.
func (p *Plugin) lifecycleRules(b *bucket) ([]map[string]any, bool) {
	days := p.cfg.LifecycleExpireDays
	if days <= 0 {
		return nil, false
	}
	want := map[string]int{"age": days}
	if p.cfg.Versioning {
		want["daysSinceNoncurrentTime"] = days
	}
	var cur []map[string]any
	if b != nil && b.Lifecycle != nil {
		cur = b.Lifecycle.Rule
	}
	have := map[string]int{}
	var rules []map[string]any
	for _, r := range cur {
		if !isManagedRule(r) {
			rules = append(rules, r)
			continue
		}
		for k, v := range r["condition"].(map[string]any) {
			n, _ := v.(float64)
			have[k] = int(n)
		}
	}
	if b != nil && maps.Equal(have, want) && len(rules)+len(want) == len(cur) {
		return nil, false
	}
	for _, k := range managedConditions {
		if n, ok := want[k]; ok {
			rules = append(rules, map[string]any{
				"action":    map[string]any{"type": "Delete"},
				"condition": map[string]any{k: n},
			})
		}
	}
	return rules, true
}

func (p *Plugin) deprovisionBucket(ctx context.Context, name string, t sdk.Tenant) error {
	for attempt := 1; ; attempt++ {
		err := p.deprovisionBucketOnce(ctx, name, t)
		if isPrecondition(err) && attempt < maxAttempts {
			continue
		}
		return err
	}
}

func (p *Plugin) deprovisionBucketOnce(ctx context.Context, name string, t sdk.Tenant) error {
	b, err := p.gcs.getBucket(ctx, name)
	if isNotFound(err) {
		return nil
	} else if err != nil {
		return bucketErr(name, err)
	}
	if p.cfg.Ownership == OwnershipObject {
		return p.deprovisionMarkedBucket(ctx, name, t)
	}

	switch owner := b.Labels[LabelTenantID]; {
	case owner == LabelValue(t.ID):
	case owner != "":
		p.log.Warn("not deprovisioning a bucket owned by another tenant",
			"bucket", name, "tenant_id", t.ID, "owner", owner)
		return nil
	case b.Labels[LabelDeletedAt] != "":
		if b.Labels[LabelDeletedTenantID] != LabelValue(t.ID) {
			p.log.Warn("not deprovisioning a bucket retained from another tenant",
				"bucket", name, "tenant_id", t.ID, "owner", b.Labels[LabelDeletedTenantID])
		}
		return nil // already retained
	default:
		// Unlabeled: only an empty bucket (left by an interrupted
		// Provision) is cleaned up; anything else is not ours.
		empty, err := p.isEmpty(ctx, name, "")
		if err != nil {
			return err
		}
		if !empty {
			p.log.Warn("not deprovisioning an unmanaged bucket", "bucket", name, "tenant_id", t.ID)
			return nil
		}
		if p.cfg.OnDeprovision == DeprovisionRetain {
			return nil
		}
	}

	if p.cfg.OnDeprovision == DeprovisionRetain {
		// Release ownership so the bucket can never be adopted again, while
		// recording who it belonged to.
		patch := map[string]any{"labels": map[string]any{
			LabelTenantID:        nil,
			LabelDeletedAt:       p.now().UTC().Format(deletedAtLayout),
			LabelDeletedTenantID: LabelValue(t.ID),
		}}
		if b.versioningEnabled() {
			patch["versioning"] = map[string]any{"enabled": true}
		}
		if _, err := p.gcs.patchBucket(ctx, name, b.Metageneration, patch); err != nil {
			if isPrecondition(err) {
				return err
			}
			return fmt.Errorf("release bucket %s: %w", name, err)
		}
		return nil
	}

	if err := p.removeAll(ctx, name, "", ""); err != nil {
		return err
	}
	return p.deleteBucket(ctx, name)
}

// deprovisionMarkedBucket deprovisions a bucket with ownership: object.
func (p *Plugin) deprovisionMarkedBucket(ctx context.Context, name string, t sdk.Tenant) error {
	state, err := p.deprovisionMarker(ctx, name, "", t)
	if err != nil {
		return err
	}
	switch state {
	case markerOther:
		return nil
	case markerOurs:
		if p.cfg.OnDeprovision == DeprovisionDelete {
			return p.deleteBucket(ctx, name)
		}
		return nil
	}
	// Unmarked: an empty bucket left by an interrupted Provision or Deprovision
	// is removed; retained or foreign data is left alone.
	if p.cfg.OnDeprovision != DeprovisionDelete {
		return nil
	}
	empty, err := p.isEmpty(ctx, name, "")
	if err != nil {
		return err
	}
	if !empty {
		p.log.Warn("not deprovisioning an unmanaged bucket", "bucket", name, "tenant_id", t.ID)
		return nil
	}
	return p.deleteBucket(ctx, name)
}

func (p *Plugin) deleteBucket(ctx context.Context, name string) error {
	if err := p.gcs.deleteBucket(ctx, name); err != nil && !isNotFound(err) {
		return fmt.Errorf("delete bucket %s: %w", name, err)
	}
	return nil
}
