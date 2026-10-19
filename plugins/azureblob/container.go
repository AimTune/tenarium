package azureblob

import (
	"context"
	"fmt"
	"maps"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// Provision creates or claims the tenant's container and applies metadata
// and public access. Every step is idempotent.
func (p *Plugin) Provision(ctx context.Context, t sdk.Tenant) error {
	name, err := p.containerName(t)
	if err != nil {
		return err
	}
	quota, err := p.quota(ctx, t)
	if err != nil {
		return err
	}
	props, exists, err := p.client.getContainer(ctx, name)
	if err != nil {
		return err
	}
	if !exists {
		created, err := p.create(ctx, name, t, quota)
		if err != nil || created {
			return err
		}
		// Created concurrently by someone else: check it like any other
		// existing container.
		if props, exists, err = p.client.getContainer(ctx, name); err != nil {
			return err
		} else if !exists {
			return fmt.Errorf("container %s disappeared while provisioning; retry", name)
		}
	}

	// Check ownership before touching anything else about the container.
	if err := p.claim(ctx, name, props.Metadata, t); err != nil {
		return err
	}
	want := maps.Clone(props.Metadata)
	want[MetaTenantID] = t.ID
	if quota != "" {
		want[MetaQuotaGB] = quota
	} else {
		delete(want, MetaQuotaGB)
	}
	if !maps.Equal(props.Metadata, want) {
		if err := p.client.setMetadata(ctx, name, want); err != nil {
			return err
		}
	}
	if props.PublicAccess != p.cfg.PublicAccess {
		if err := p.client.setPublicAccess(ctx, name, p.cfg.PublicAccess); err != nil {
			return err
		}
	}
	return nil
}

// create creates the container with its ownership marker in one request.
// It reports created=false if the container already exists. A container
// that is still being deleted (Azure deletes asynchronously) is waited for
// up to beingDeletedWait.
func (p *Plugin) create(ctx context.Context, name string, t sdk.Tenant, quota string) (bool, error) {
	meta := map[string]string{MetaTenantID: t.ID}
	if quota != "" {
		meta[MetaQuotaGB] = quota
	}
	deadline := time.Now().Add(p.beingDeletedWait)
	for {
		err := p.client.createContainer(ctx, name, meta, p.cfg.PublicAccess)
		switch errCode(err) {
		case "":
			if err != nil {
				return false, fmt.Errorf("create container %s: %w", name, err)
			}
			return true, nil
		case "ContainerAlreadyExists":
			return false, nil
		case "ContainerBeingDeleted":
			if !time.Now().Add(p.pollInterval).Before(deadline) {
				return false, fmt.Errorf("container %s is still being deleted by Azure (from a previous deprovision); retry provisioning later: %w", name, err)
			}
			p.log.Info("container is being deleted, waiting", "container", name, "tenant_id", t.ID)
			select {
			case <-ctx.Done():
				return false, ctx.Err()
			case <-time.After(p.pollInterval):
			}
		default:
			return false, fmt.Errorf("create container %s: %w", name, err)
		}
	}
}

// claim checks that an existing container may be used by t. Containers
// marked for another tenant or retained from a deleted one are refused.
// Unmarked containers are adopted only when they hold no blob.
func (p *Plugin) claim(ctx context.Context, name string, meta map[string]string, t sdk.Tenant) error {
	switch owner := meta[MetaTenantID]; {
	case owner == t.ID:
		return nil
	case owner != "":
		return fmt.Errorf("container %s already exists and belongs to another tenant (%s)", name, owner)
	case meta[MetaDeletedAt] != "":
		return fmt.Errorf("container %s holds data retained from deleted tenant %s (deleted at %s); remove or rename it before provisioning a tenant with this name",
			name, meta[MetaDeletedTenantID], meta[MetaDeletedAt])
	}
	empty, err := p.client.isEmpty(ctx, name)
	if err != nil {
		return err
	}
	if !empty {
		return fmt.Errorf("container %s already exists, is not empty and is not managed by tenarium", name)
	}
	return nil
}

// Deprovision applies on_deprovision. A tenant whose container does not
// exist is treated as already deprovisioned.
func (p *Plugin) Deprovision(ctx context.Context, t sdk.Tenant) error {
	if p.cfg.OnDeprovision == DeprovisionKeep {
		return nil
	}
	name, err := p.containerName(t)
	if err != nil {
		return err
	}
	props, exists, err := p.client.getContainer(ctx, name)
	if err != nil || !exists {
		return err
	}
	meta := props.Metadata
	switch owner := meta[MetaTenantID]; {
	case owner == t.ID:
	case owner != "":
		p.log.Warn("not deprovisioning a container owned by another tenant",
			"container", name, "tenant_id", t.ID, "owner", owner)
		return nil
	case meta[MetaDeletedAt] != "":
		if meta[MetaDeletedTenantID] != t.ID {
			p.log.Warn("not deprovisioning a container retained from another tenant",
				"container", name, "tenant_id", t.ID, "owner", meta[MetaDeletedTenantID])
		}
		return nil // already retained
	default:
		// Unmarked: only an empty container is cleaned up; anything else is
		// not ours.
		empty, err := p.client.isEmpty(ctx, name)
		if err != nil {
			return err
		}
		if !empty {
			p.log.Warn("not deprovisioning an unmanaged container", "container", name, "tenant_id", t.ID)
			return nil
		}
		if p.cfg.OnDeprovision == DeprovisionRetain {
			return nil
		}
	}

	if p.cfg.OnDeprovision == DeprovisionRetain {
		// Stop serving retained data anonymously before releasing it.
		if props.PublicAccess != PublicAccessNone {
			if err := p.client.setPublicAccess(ctx, name, PublicAccessNone); err != nil {
				return err
			}
		}
		next := maps.Clone(meta)
		delete(next, MetaTenantID)
		delete(next, MetaQuotaGB)
		next[MetaDeletedAt] = p.now().UTC().Format(time.RFC3339)
		next[MetaDeletedTenantID] = t.ID
		return p.client.setMetadata(ctx, name, next)
	}

	// Set Container Metadata cannot be made conditional on an ETag, but
	// Delete Container honors If-Unmodified-Since: if the container's
	// metadata changed since we checked ownership, the delete is refused.
	err = p.client.deleteContainer(ctx, name, props.LastModified)
	switch errCode(err) {
	case "":
		if err != nil {
			return fmt.Errorf("delete container %s: %w", name, err)
		}
		return nil
	case "ContainerNotFound", "ContainerBeingDeleted":
		return nil
	case "ConditionNotMet":
		return fmt.Errorf("container %s changed while deprovisioning; retry: %w", name, err)
	default:
		return fmt.Errorf("delete container %s: %w", name, err)
	}
}
