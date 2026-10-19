package s3tenant

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/minio/minio-go/v7"
)

// retainedMarker is the content of "<prefix>/.tenarium-retained".
type retainedMarker struct {
	TenantID  string `json:"tenant_id"`
	DeletedAt string `json:"deleted_at"`
}

func (p *Plugin) provisionPrefix(ctx context.Context, tg target, t sdk.Tenant, quota string) error {
	key := tg.Prefix + ownerObject
	owner, meta, found, err := p.readObject(ctx, tg.Bucket, key)
	if err != nil {
		return err
	}
	if found && strings.TrimSpace(owner) != t.ID {
		return fmt.Errorf("prefix %s/%s already belongs to another tenant (%s)", tg.Bucket, tg.Prefix, strings.TrimSpace(owner))
	}
	if !found {
		if err := p.claimPrefix(ctx, tg); err != nil {
			return err
		}
	}
	if found && meta[quotaMetaKey] == quota {
		return nil
	}
	var md map[string]string
	if quota != "" {
		md = map[string]string{TagQuotaGB: quota}
	}
	if err := p.putMarker(ctx, tg.Bucket, key, "text/plain", []byte(t.ID), md); err != nil {
		return fmt.Errorf("write owner marker %s/%s: %w", tg.Bucket, key, err)
	}
	return nil
}

// putMarker writes a small marker object. The payload is protected by
// Content-MD5 instead of a streaming (aws-chunked) signature, which some
// S3-compatible stores do not accept over plain HTTP.
func (p *Plugin) putMarker(ctx context.Context, bucket, key, contentType string, body []byte, meta map[string]string) error {
	_, err := p.client.PutObject(ctx, bucket, key, bytes.NewReader(body), int64(len(body)), minio.PutObjectOptions{
		ContentType:          contentType,
		UserMetadata:         meta,
		SendContentMd5:       true,
		DisableContentSha256: true,
	})
	return err
}

// claimPrefix checks that an unmarked prefix may be used: it must not hold
// retained data or anything else.
func (p *Plugin) claimPrefix(ctx context.Context, tg target) error {
	raw, _, retained, err := p.readObject(ctx, tg.Bucket, tg.Prefix+retainedObject)
	if err != nil {
		return err
	}
	if retained {
		var m retainedMarker
		_ = json.Unmarshal([]byte(raw), &m)
		return fmt.Errorf("prefix %s/%s holds data retained from deleted tenant %s (deleted at %s); remove or move it before provisioning a tenant with this name",
			tg.Bucket, tg.Prefix, m.TenantID, m.DeletedAt)
	}
	empty, err := p.isEmpty(ctx, tg.Bucket, tg.Prefix)
	if err != nil {
		return err
	}
	if !empty {
		return fmt.Errorf("prefix %s/%s is not empty and is not managed by tenarium", tg.Bucket, tg.Prefix)
	}
	return nil
}

func (p *Plugin) deprovisionPrefix(ctx context.Context, tg target, t sdk.Tenant) error {
	key := tg.Prefix + ownerObject
	owner, _, found, err := p.readObject(ctx, tg.Bucket, key)
	if err != nil {
		return err
	}
	if !found {
		// Already deprovisioned (or retained), never provisioned, or data
		// not managed by tenarium: nothing to do either way.
		return nil
	}
	if owner = strings.TrimSpace(owner); owner != t.ID {
		p.log.Warn("not deprovisioning a prefix owned by another tenant",
			"bucket", tg.Bucket, "prefix", tg.Prefix, "tenant_id", t.ID, "owner", owner)
		return nil
	}

	if p.cfg.OnDeprovision == DeprovisionRetain {
		b, _ := json.Marshal(retainedMarker{TenantID: t.ID, DeletedAt: p.now().UTC().Format(time.RFC3339)})
		rkey := tg.Prefix + retainedObject
		if err := p.putMarker(ctx, tg.Bucket, rkey, "application/json", b, nil); err != nil {
			return fmt.Errorf("write retained marker %s/%s: %w", tg.Bucket, rkey, err)
		}
		if err := p.client.RemoveObject(ctx, tg.Bucket, key, minio.RemoveObjectOptions{}); err != nil {
			return fmt.Errorf("remove owner marker %s/%s: %w", tg.Bucket, key, err)
		}
		return nil
	}

	// The owner marker goes last so an interrupted run is retried.
	if err := p.removeAll(ctx, tg.Bucket, tg.Prefix, key); err != nil {
		return err
	}
	return p.removeAll(ctx, tg.Bucket, key, "")
}

// readObject returns the content and user metadata of a small object, and
// whether it exists.
func (p *Plugin) readObject(ctx context.Context, bucket, key string) (string, map[string]string, bool, error) {
	obj, err := p.client.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
	if err == nil {
		defer obj.Close()
		var info minio.ObjectInfo
		if info, err = obj.Stat(); err == nil {
			var b []byte
			if b, err = io.ReadAll(io.LimitReader(obj, 4096)); err == nil {
				return string(b), info.UserMetadata, true, nil
			}
		}
	}
	switch errCode(err) {
	case "NoSuchKey":
		return "", nil, false, nil
	case "NoSuchBucket":
		return "", nil, false, fmt.Errorf("shared bucket %s does not exist", bucket)
	}
	return "", nil, false, fmt.Errorf("read %s/%s: %w", bucket, key, err)
}
