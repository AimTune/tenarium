package s3tenant

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/lifecycle"
	"github.com/minio/minio-go/v7/pkg/tags"
)

// lifecycleRuleID identifies the rule managed by lifecycle_expire_days;
// other rules on the bucket are preserved.
const lifecycleRuleID = "tenarium-expire"

func (p *Plugin) provisionBucket(ctx context.Context, tg target, t sdk.Tenant, quota string) error {
	bucket := tg.Bucket
	exists, err := p.client.BucketExists(ctx, bucket)
	if err != nil {
		return fmt.Errorf("bucket %s: %w", bucket, err)
	}
	created := false
	if !exists {
		err := p.client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{
			Region: p.cfg.Region, ObjectLocking: p.cfg.ObjectLock,
		})
		switch errCode(err) {
		case "":
			if err != nil {
				return fmt.Errorf("create bucket %s: %w", bucket, err)
			}
			created = true
		case "BucketAlreadyOwnedByYou": // created concurrently
		default:
			return fmt.Errorf("create bucket %s: %w", bucket, err)
		}
	}

	// Check ownership before touching anything else about the bucket.
	cur, err := p.bucketTags(ctx, bucket)
	if err != nil {
		return err
	}
	if err := p.claimBucket(ctx, bucket, cur, t, created); err != nil {
		return err
	}
	want := maps.Clone(cur)
	want[TagTenantID] = t.ID
	if quota != "" {
		want[TagQuotaGB] = quota
	} else {
		delete(want, TagQuotaGB)
	}
	if !maps.Equal(cur, want) {
		if err := p.setBucketTags(ctx, bucket, want); err != nil {
			return err
		}
	}

	if p.cfg.Versioning {
		v, err := p.client.GetBucketVersioning(ctx, bucket)
		if err != nil {
			return fmt.Errorf("get versioning of %s: %w", bucket, err)
		}
		if !v.Enabled() {
			if err := p.client.EnableVersioning(ctx, bucket); err != nil {
				return fmt.Errorf("enable versioning of %s: %w", bucket, err)
			}
		}
	}
	if p.cfg.LifecycleExpireDays > 0 {
		if err := p.ensureLifecycle(ctx, bucket); err != nil {
			return err
		}
	}
	if p.policy != nil {
		policy, err := renderPolicy(p.policy, policyData{Tenant: t, Bucket: bucket})
		if err != nil {
			return fmt.Errorf("policy_template: %w", err)
		}
		if err := p.client.SetBucketPolicy(ctx, bucket, policy); err != nil {
			return fmt.Errorf("set policy of %s: %w", bucket, err)
		}
	}
	return nil
}

// claimBucket checks that an existing bucket may be used by t. Buckets
// tagged for another tenant or retained from a deleted one are refused.
// Untagged buckets are adopted only when they are empty: those are left by
// a Provision that stopped between creating and tagging the bucket.
func (p *Plugin) claimBucket(ctx context.Context, bucket string, cur map[string]string, t sdk.Tenant, created bool) error {
	switch owner := cur[TagTenantID]; {
	case owner == t.ID:
		return nil
	case owner != "":
		return fmt.Errorf("bucket %s already exists and belongs to another tenant (%s)", bucket, owner)
	case cur[TagDeletedAt] != "":
		return fmt.Errorf("bucket %s holds data retained from deleted tenant %s (deleted at %s); remove or rename it before provisioning a tenant with this name",
			bucket, cur[TagDeletedTenantID], cur[TagDeletedAt])
	}
	if created {
		return nil
	}
	empty, err := p.isEmpty(ctx, bucket, "")
	if err != nil {
		return err
	}
	if !empty {
		return fmt.Errorf("bucket %s already exists, is not empty and is not managed by tenarium", bucket)
	}
	return nil
}

func (p *Plugin) deprovisionBucket(ctx context.Context, tg target, t sdk.Tenant) error {
	bucket := tg.Bucket
	exists, err := p.client.BucketExists(ctx, bucket)
	if err != nil || !exists {
		return err
	}
	cur, err := p.bucketTags(ctx, bucket)
	if err != nil {
		return err
	}
	switch owner := cur[TagTenantID]; {
	case owner == t.ID:
	case owner != "":
		p.log.Warn("not deprovisioning a bucket owned by another tenant",
			"bucket", bucket, "tenant_id", t.ID, "owner", owner)
		return nil
	case cur[TagDeletedAt] != "":
		if cur[TagDeletedTenantID] != t.ID {
			p.log.Warn("not deprovisioning a bucket retained from another tenant",
				"bucket", bucket, "tenant_id", t.ID, "owner", cur[TagDeletedTenantID])
		}
		return nil // already retained
	default:
		// Unmarked: only an empty bucket (left by an interrupted Provision)
		// is cleaned up; anything else is not ours.
		empty, err := p.isEmpty(ctx, bucket, "")
		if err != nil {
			return err
		}
		if !empty {
			p.log.Warn("not deprovisioning an unmanaged bucket", "bucket", bucket, "tenant_id", t.ID)
			return nil
		}
		if p.cfg.OnDeprovision == DeprovisionRetain {
			return nil
		}
	}

	if p.cfg.OnDeprovision == DeprovisionRetain {
		// Release ownership so the bucket can never be adopted again, while
		// recording who it belonged to.
		next := maps.Clone(cur)
		delete(next, TagTenantID)
		next[TagDeletedAt] = p.now().UTC().Format(time.RFC3339)
		next[TagDeletedTenantID] = t.ID
		return p.setBucketTags(ctx, bucket, next)
	}

	if err := p.removeAll(ctx, bucket, "", ""); err != nil {
		return err
	}
	if err := p.client.RemoveBucket(ctx, bucket); err != nil && errCode(err) != "NoSuchBucket" {
		return fmt.Errorf("remove bucket %s: %w", bucket, err)
	}
	return nil
}

// bucketTags returns the tags of bucket (empty if it has none).
func (p *Plugin) bucketTags(ctx context.Context, bucket string) (map[string]string, error) {
	tg, err := p.client.GetBucketTagging(ctx, bucket)
	if errCode(err) == "NoSuchTagSet" {
		return map[string]string{}, nil
	} else if err != nil {
		return nil, fmt.Errorf("get tags of %s: %w", bucket, err)
	}
	m := tg.ToMap()
	if m == nil {
		m = map[string]string{}
	}
	return m, nil
}

func (p *Plugin) setBucketTags(ctx context.Context, bucket string, m map[string]string) error {
	tg, err := tags.MapToBucketTags(m)
	if err != nil {
		return fmt.Errorf("tags of %s: %w", bucket, err)
	}
	if err := p.client.SetBucketTagging(ctx, bucket, tg); err != nil {
		return fmt.Errorf("set tags of %s: %w", bucket, err)
	}
	return nil
}

// ensureLifecycle adds or updates the tenarium-expire rule, keeping other
// rules.
func (p *Plugin) ensureLifecycle(ctx context.Context, bucket string) error {
	cfg, err := p.client.GetBucketLifecycle(ctx, bucket)
	if errCode(err) == "NoSuchLifecycleConfiguration" || cfg == nil && err == nil {
		cfg = lifecycle.NewConfiguration()
	} else if err != nil {
		return fmt.Errorf("get lifecycle of %s: %w", bucket, err)
	}
	days := lifecycle.ExpirationDays(p.cfg.LifecycleExpireDays)
	noncurrent := lifecycle.ExpirationDays(0)
	if p.cfg.Versioning || p.cfg.ObjectLock {
		noncurrent = days
	}
	i := slices.IndexFunc(cfg.Rules, func(r lifecycle.Rule) bool { return r.ID == lifecycleRuleID })
	if i >= 0 {
		r := cfg.Rules[i]
		if r.Status == "Enabled" && r.Expiration.Days == days && r.NoncurrentVersionExpiration.NoncurrentDays == noncurrent {
			return nil
		}
		cfg.Rules = slices.Delete(cfg.Rules, i, i+1)
	}
	rule := lifecycle.Rule{
		ID:         lifecycleRuleID,
		Status:     "Enabled",
		Expiration: lifecycle.Expiration{Days: days},
	}
	rule.NoncurrentVersionExpiration.NoncurrentDays = noncurrent
	cfg.Rules = append(cfg.Rules, rule)
	if err := p.client.SetBucketLifecycle(ctx, bucket, cfg); err != nil {
		return fmt.Errorf("set lifecycle of %s: %w", bucket, err)
	}
	return nil
}

// versioned reports whether bucket has (or had) versioning enabled, so that
// deletion must remove every version.
func (p *Plugin) versioned(ctx context.Context, bucket string) (bool, error) {
	v, err := p.client.GetBucketVersioning(ctx, bucket)
	if errCode(err) == "NotImplemented" {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("get versioning of %s: %w", bucket, err)
	}
	return v.Status != "", nil
}

// isEmpty reports whether bucket holds no object (or object version) under
// prefix.
func (p *Plugin) isEmpty(ctx context.Context, bucket, prefix string) (bool, error) {
	versions, err := p.versioned(ctx, bucket)
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// One listed object is enough to know; cancel stops the listing.
	o, ok := <-p.client.ListObjects(ctx, bucket, minio.ListObjectsOptions{
		Prefix: prefix, Recursive: true, WithVersions: versions, MaxKeys: 1,
	})
	if !ok {
		return true, nil
	}
	if o.Err != nil {
		return false, fmt.Errorf("list %s/%s: %w", bucket, prefix, o.Err)
	}
	return false, nil
}

// removeAll deletes every object under prefix in bucket, including all
// versions and delete markers of versioned buckets, except the key skip.
func (p *Plugin) removeAll(ctx context.Context, bucket, prefix, skip string) error {
	versions, err := p.versioned(ctx, bucket)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	objects := p.client.ListObjects(ctx, bucket, minio.ListObjectsOptions{
		Prefix: prefix, Recursive: true, WithVersions: versions,
	})
	toRemove := make(chan minio.ObjectInfo)
	var listErr error
	go func() {
		defer close(toRemove)
		for o := range objects {
			if o.Err != nil {
				listErr = o.Err
				return
			}
			if o.Key == skip {
				continue
			}
			select {
			case toRemove <- o:
			case <-ctx.Done():
				return
			}
		}
	}()
	var errs []error
	for e := range p.client.RemoveObjects(ctx, bucket, toRemove, minio.RemoveObjectsOptions{}) {
		errs = append(errs, fmt.Errorf("remove %s/%s: %w", bucket, e.ObjectName, e.Err))
	}
	// RemoveObjects closes its error channel only after toRemove is closed,
	// so listErr is safe to read here.
	if listErr != nil {
		errs = append(errs, fmt.Errorf("list %s/%s: %w", bucket, prefix, listErr))
	}
	return errors.Join(errs...)
}
