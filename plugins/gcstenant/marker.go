package gcstenant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// Owner marker objects are used in prefix mode ("<prefix>/.tenarium-owner")
// and in bucket mode with ownership: object (".tenarium-owner" at the
// bucket root). The marker's content is the tenant ID; its metadata holds
// tenarium-tenant-id and, with quota_from_limit, tenarium-quota-gb.

// retainedMarker is the content of the ".tenarium-retained" object.
type retainedMarker struct {
	TenantID  string `json:"tenant_id"`
	DeletedAt string `json:"deleted_at"`
}

// markerState is what deprovisionMarker found.
type markerState int

const (
	markerNone  markerState = iota // no owner marker
	markerOther                    // marker of another tenant
	markerOurs                     // marker of this tenant (now handled)
)

// where describes a bucket or prefix in messages.
func where(bkt, prefix string) string {
	if prefix == "" {
		return "bucket " + bkt
	}
	return "prefix " + bkt + "/" + prefix
}

// readMarker returns the live owner marker object and its (trimmed)
// content, or nil if there is none.
func (p *Plugin) readMarker(ctx context.Context, bkt, key string) (*object, string, error) {
	o, err := p.gcs.getObject(ctx, bkt, key)
	if isNotFound(err) {
		return nil, "", nil
	} else if err != nil {
		return nil, "", fmt.Errorf("read %s/%s: %w", bkt, key, err)
	}
	content, err := p.gcs.readObject(ctx, bkt, key, o.Generation)
	if isNotFound(err) { // deleted in between
		return nil, "", nil
	} else if err != nil {
		return nil, "", fmt.Errorf("read %s/%s: %w", bkt, key, err)
	}
	return o, strings.TrimSpace(string(content)), nil
}

// provisionMarker claims bkt/prefix for t by writing its owner marker, or
// checks and updates an existing one. fresh is true when the bucket was
// just created by this call, so it is known to be empty.
func (p *Plugin) provisionMarker(ctx context.Context, bkt, prefix string, t sdk.Tenant, quota string, fresh bool) error {
	key := prefix + ownerObject
	for attempt := 0; ; attempt++ {
		o, owner, err := p.readMarker(ctx, bkt, key)
		if err != nil {
			return err
		}
		// ifGenerationMatch=0 creates the marker only if it does not exist,
		// so two tenants racing for one name cannot both claim it.
		gen := "0"
		if o != nil {
			if owner != t.ID {
				return fmt.Errorf("%s already belongs to another tenant (%s)", where(bkt, prefix), owner)
			}
			if o.Metadata[LabelTenantID] == t.ID && o.Metadata[LabelQuotaGB] == quota {
				return nil
			}
			gen = o.Generation
		} else if !fresh {
			if err := p.claimUnmarked(ctx, bkt, prefix); err != nil {
				return err
			}
		}
		md := map[string]string{LabelTenantID: t.ID}
		if quota != "" {
			md[LabelQuotaGB] = quota
		}
		err = p.gcs.putObject(ctx, bkt, key, "text/plain", []byte(t.ID), md, gen)
		switch {
		case err == nil:
			return nil
		case isPrecondition(err) && attempt < 2:
			continue // changed concurrently: read again
		case isNotFound(err):
			return fmt.Errorf("bucket %s does not exist", bkt)
		}
		return fmt.Errorf("write owner marker %s/%s: %w", bkt, key, err)
	}
}

// claimUnmarked checks that an unmarked bucket or prefix may be adopted: it
// must not hold retained data or anything else.
func (p *Plugin) claimUnmarked(ctx context.Context, bkt, prefix string) error {
	rkey := prefix + retainedObject
	_, raw, err := p.readMarker(ctx, bkt, rkey)
	if err != nil {
		return err
	}
	if raw != "" {
		var m retainedMarker
		_ = json.Unmarshal([]byte(raw), &m)
		return fmt.Errorf("%s holds data retained from deleted tenant %s (deleted at %s); remove or move it before provisioning a tenant with this name",
			where(bkt, prefix), m.TenantID, m.DeletedAt)
	}
	empty, err := p.isEmpty(ctx, bkt, prefix)
	if err != nil {
		return err
	}
	if !empty {
		return fmt.Errorf("%s is not empty and is not managed by tenarium", where(bkt, prefix))
	}
	return nil
}

// deprovisionMarker applies on_deprovision (delete or retain) to a bucket
// or prefix marked by an owner object. It never touches data that is not
// marked for t.
func (p *Plugin) deprovisionMarker(ctx context.Context, bkt, prefix string, t sdk.Tenant) (markerState, error) {
	key := prefix + ownerObject
	o, owner, err := p.readMarker(ctx, bkt, key)
	if err != nil {
		return markerNone, err
	}
	if o == nil {
		// Already deprovisioned (or retained), never provisioned, or data
		// not managed by tenarium: nothing to do here either way.
		return markerNone, nil
	}
	if owner != t.ID {
		p.log.Warn("not deprovisioning data owned by another tenant",
			"bucket", bkt, "prefix", prefix, "tenant_id", t.ID, "owner", owner)
		return markerOther, nil
	}

	if p.cfg.OnDeprovision == DeprovisionRetain {
		b, _ := json.Marshal(retainedMarker{TenantID: t.ID, DeletedAt: p.now().UTC().Format(time.RFC3339)})
		rkey := prefix + retainedObject
		if err := p.gcs.putObject(ctx, bkt, rkey, "application/json", b, nil, ""); err != nil {
			return markerOurs, fmt.Errorf("write retained marker %s/%s: %w", bkt, rkey, err)
		}
		err := p.gcs.deleteObject(ctx, bkt, key, o.Generation, "")
		if err != nil && !isNotFound(err) {
			return markerOurs, fmt.Errorf("remove owner marker %s/%s: %w", bkt, key, err)
		}
		return markerOurs, nil
	}

	// The owner marker goes last so an interrupted run is retried.
	if err := p.removeAll(ctx, bkt, prefix, key); err != nil {
		return markerOurs, err
	}
	return markerOurs, p.removeKey(ctx, bkt, key)
}

// isEmpty reports whether bkt holds no object generation under prefix.
// Noncurrent generations count: they are data too.
func (p *Plugin) isEmpty(ctx context.Context, bkt, prefix string) (bool, error) {
	empty := true
	err := p.gcs.listObjects(ctx, bkt, prefix, 1, func(object) error {
		empty = false
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("list %s/%s: %w", bkt, prefix, err)
	}
	return empty, nil
}

// deleteWorkers is the number of concurrent object deletions.
const deleteWorkers = 8

// removeAll permanently deletes every generation (live and noncurrent) of
// every object under prefix in bkt, except those of the key skip.
func (p *Plugin) removeAll(ctx context.Context, bkt, prefix, skip string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan object)
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	for range deleteWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for o := range jobs {
				err := p.gcs.deleteObject(ctx, bkt, o.Name, o.Generation, "")
				if err != nil && !isNotFound(err) && !errors.Is(err, context.Canceled) {
					mu.Lock()
					errs = append(errs, fmt.Errorf("remove %s/%s#%s: %w", bkt, o.Name, o.Generation, err))
					mu.Unlock()
					cancel()
				}
			}
		}()
	}
	listErr := p.gcs.listObjects(ctx, bkt, prefix, 0, func(o object) error {
		if o.Name == skip {
			return nil
		}
		select {
		case jobs <- o:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	close(jobs)
	wg.Wait()
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	if listErr != nil {
		return fmt.Errorf("list %s/%s: %w", bkt, prefix, listErr)
	}
	return nil
}

// removeKey permanently deletes every generation of the object key.
func (p *Plugin) removeKey(ctx context.Context, bkt, key string) error {
	var gens []string
	err := p.gcs.listObjects(ctx, bkt, key, 0, func(o object) error {
		if o.Name == key {
			gens = append(gens, o.Generation)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("list %s/%s: %w", bkt, key, err)
	}
	for _, g := range gens {
		if err := p.gcs.deleteObject(ctx, bkt, key, g, ""); err != nil && !isNotFound(err) {
			return fmt.Errorf("remove %s/%s#%s: %w", bkt, key, g, err)
		}
	}
	return nil
}
