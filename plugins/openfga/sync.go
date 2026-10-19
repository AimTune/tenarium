package openfga

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// syncEvent mirrors tenant hierarchy and memberships into OpenFGA tuples.
// Delivery is at least once, so writes of existing tuples and deletes of
// missing ones count as success.
func (p *Plugin) syncEvent(ctx context.Context, e sdk.Event) error {
	if n := p.next.Load(); n != nil {
		return n.syncEvent(ctx, e)
	}
	switch e.Type {
	case sdk.EventTenantCreated, sdk.EventTenantDeleted:
		var d sdk.TenantEventData
		if err := json.Unmarshal(e.Data, &d); err != nil {
			return fmt.Errorf("decode %s: %w", e.Type, err)
		}
		if d.Tenant.ParentID == "" || d.Tenant.ID == "" {
			return nil
		}
		t := tupleKey{User: p.tenantObject(d.Tenant.ParentID), Relation: p.cfg.ParentRelation, Object: p.tenantObject(d.Tenant.ID)}
		if e.Type == sdk.EventTenantCreated {
			return p.writeTuple(ctx, t)
		}
		return p.deleteTuple(ctx, t)
	case sdk.EventMemberAdded, sdk.EventMemberUpdated, sdk.EventMemberRemoved:
		var d sdk.MemberEventData
		if err := json.Unmarshal(e.Data, &d); err != nil {
			return fmt.Errorf("decode %s: %w", e.Type, err)
		}
		var old, cur *tupleKey
		switch e.Type {
		case sdk.EventMemberAdded:
			cur = p.memberTuple(d.Member)
		case sdk.EventMemberUpdated:
			if d.Previous != nil {
				old = p.memberTuple(*d.Previous)
			}
			cur = p.memberTuple(d.Member)
		case sdk.EventMemberRemoved:
			old = p.memberTuple(d.Member)
			// A removed member's status may already be cleared; delete the
			// tuple its role would have produced regardless.
			if old == nil {
				m := d.Member
				m.Status = sdk.MemberActive
				old = p.memberTuple(m)
			}
		}
		if old != nil && (cur == nil || *old != *cur) {
			if err := p.deleteTuple(ctx, *old); err != nil {
				return err
			}
		}
		if cur != nil {
			return p.writeTuple(ctx, *cur)
		}
	}
	return nil
}

// memberTuple returns the tuple granted by an active membership, or nil.
func (p *Plugin) memberTuple(m sdk.Member) *tupleKey {
	if m.Status != sdk.MemberActive || m.TenantID == "" {
		return nil
	}
	rel := m.Role
	if len(p.cfg.Sync.Roles) > 0 {
		rel = p.cfg.Sync.Roles[m.Role]
	}
	if rel == "" {
		return nil
	}
	user, _, ok := p.memberUser.expand(map[string]string{
		"member.user_id": m.UserID, "member.email": m.Email, "member.id": m.ID, "member.tenant_id": m.TenantID,
	})
	if !ok {
		return nil
	}
	return &tupleKey{User: user, Relation: rel, Object: p.tenantObject(m.TenantID)}
}

type writeRequest struct {
	Writes               *tuples `json:"writes,omitempty"`
	Deletes              *tuples `json:"deletes,omitempty"`
	AuthorizationModelID string  `json:"authorization_model_id,omitempty"`
}

func (p *Plugin) writeTuple(ctx context.Context, t tupleKey) error {
	err := p.write(ctx, writeRequest{Writes: &tuples{TupleKeys: []tupleKey{t}}})
	if isIdempotentWriteError(err, "already exists") {
		return nil
	}
	return err
}

func (p *Plugin) deleteTuple(ctx context.Context, t tupleKey) error {
	err := p.write(ctx, writeRequest{Deletes: &tuples{TupleKeys: []tupleKey{t}}})
	if isIdempotentWriteError(err, "does not exist") {
		return nil
	}
	return err
}

func (p *Plugin) write(ctx context.Context, req writeRequest) error {
	req.AuthorizationModelID = p.cfg.AuthorizationModelID
	err := p.do(ctx, http.MethodPost, "/stores/"+url.PathEscape(p.cfg.StoreID)+"/write", req, nil)
	if err == nil {
		p.cache.purge()
	}
	return err
}

func isIdempotentWriteError(err error, phrase string) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.Status == http.StatusBadRequest && strings.Contains(ae.Message, phrase)
}
