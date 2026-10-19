package spicedb

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/AimTune/tenarium/pkg/sdk"
)

type relationship struct {
	Resource objectRef  `json:"resource"`
	Relation string     `json:"relation"`
	Subject  subjectRef `json:"subject"`
}

type update struct {
	Operation    string       `json:"operation"`
	Relationship relationship `json:"relationship"`
}

// syncEvent mirrors tenant hierarchy and memberships into relationships.
// TOUCH and DELETE are idempotent, so redelivery is harmless.
func (p *Plugin) syncEvent(ctx context.Context, e sdk.Event) error {
	if n := p.next.Load(); n != nil {
		return n.syncEvent(ctx, e)
	}
	var updates []update
	switch e.Type {
	case sdk.EventTenantCreated, sdk.EventTenantDeleted:
		var d sdk.TenantEventData
		if err := json.Unmarshal(e.Data, &d); err != nil {
			return fmt.Errorf("decode %s: %w", e.Type, err)
		}
		if d.Tenant.ParentID == "" || d.Tenant.ID == "" {
			return nil
		}
		rel := relationship{
			Resource: objectRef{ObjectType: p.cfg.TenantType, ObjectID: d.Tenant.ID},
			Relation: p.cfg.ParentRelation,
			Subject:  subjectRef{Object: objectRef{ObjectType: p.cfg.TenantType, ObjectID: d.Tenant.ParentID}},
		}
		op := "OPERATION_TOUCH"
		if e.Type == sdk.EventTenantDeleted {
			op = "OPERATION_DELETE"
		}
		updates = append(updates, update{op, rel})
	case sdk.EventMemberAdded, sdk.EventMemberUpdated, sdk.EventMemberRemoved:
		var d sdk.MemberEventData
		if err := json.Unmarshal(e.Data, &d); err != nil {
			return fmt.Errorf("decode %s: %w", e.Type, err)
		}
		var old, cur *relationship
		switch e.Type {
		case sdk.EventMemberAdded:
			cur = p.memberRel(d.Member)
		case sdk.EventMemberUpdated:
			if d.Previous != nil {
				old = p.memberRel(*d.Previous)
			}
			cur = p.memberRel(d.Member)
		case sdk.EventMemberRemoved:
			m := d.Member
			m.Status = sdk.MemberActive
			old = p.memberRel(m)
		}
		if old != nil && (cur == nil || *old != *cur) {
			updates = append(updates, update{"OPERATION_DELETE", *old})
		}
		if cur != nil {
			updates = append(updates, update{"OPERATION_TOUCH", *cur})
		}
	}
	if len(updates) == 0 {
		return nil
	}
	var resp struct {
		WrittenAt zedToken `json:"writtenAt"`
	}
	if err := p.do(ctx, "/v1/relationships/write", map[string]any{"updates": updates}, &resp); err != nil {
		return err
	}
	if resp.WrittenAt.Token != "" {
		t := resp.WrittenAt.Token
		p.lastWrite.Store(&t)
	}
	p.cache.purge()
	return nil
}

// memberRel returns the relationship granted by an active membership.
func (p *Plugin) memberRel(m sdk.Member) *relationship {
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
	s, _, ok := p.memberSubject.expand(map[string]string{
		"member.user_id": m.UserID, "member.email": m.Email, "member.id": m.ID, "member.tenant_id": m.TenantID,
	})
	if !ok {
		return nil
	}
	subject, err := parseSubject(s)
	if err != nil {
		return nil
	}
	return &relationship{
		Resource: objectRef{ObjectType: p.cfg.TenantType, ObjectID: m.TenantID},
		Relation: rel,
		Subject:  subject,
	}
}
