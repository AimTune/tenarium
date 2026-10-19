package grafanatenant

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// errNoOrg reports that the tenant's organization does not exist (yet).
var errNoOrg = errors.New("grafana organization does not exist")

// RoleFor returns the Grafana organization role of a Tenarium member role.
func (p *Plugin) RoleFor(memberRole string) string {
	if r, ok := p.roles[memberRole]; ok {
		return r
	}
	return p.cfg.DefaultRole
}

// syncMember mirrors a tenant membership change into the tenant's
// organization. Only Grafana users matching the member's email are touched,
// and never the plugin's own account.
func (p *Plugin) syncMember(ctx context.Context, e sdk.Event) error {
	var data sdk.MemberEventData
	if err := json.Unmarshal(e.Data, &data); err != nil {
		return fmt.Errorf("decode %s event: %w", e.Type, err)
	}
	m := data.Member
	t, err := p.host.GetTenant(ctx, cmp.Or(m.TenantID, e.TenantID))
	if errors.Is(err, sdk.ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	if !t.IsLive() {
		return nil
	}
	o, err := p.ownedOrg(ctx, t)
	if err != nil {
		return err
	}
	if o == nil {
		if t.Status == sdk.StatusProvisioning || t.Status == sdk.StatusFailed {
			// The organization is still being created; retry later.
			return fmt.Errorf("tenant %s: %w", t.ID, errNoOrg)
		}
		p.log.Debug("skipping member sync: organization missing", "tenant_id", t.ID, "event", e.ID)
		return nil
	}

	email := m.Email
	if email == "" && m.UserID != "" {
		if u, err := p.host.GetUser(ctx, m.UserID); err == nil {
			email = u.Email
		}
	}
	if e.Type == sdk.EventMemberRemoved || m.Status == sdk.MemberSuspended {
		return p.removeMember(ctx, o.ID, email)
	}
	if prev := data.Previous; prev != nil && prev.Email != "" && !strings.EqualFold(prev.Email, email) {
		if err := p.removeMember(ctx, o.ID, prev.Email); err != nil {
			return err
		}
	}
	return p.ensureMember(ctx, o.ID, m, email)
}

// ensureMember adds the member's Grafana user to the organization with the
// mapped role, creating the user when create_users is set.
func (p *Plugin) ensureMember(ctx context.Context, orgID int64, m sdk.Member, email string) error {
	if email == "" {
		return nil
	}
	role := p.RoleFor(m.Role)
	u, err := p.lookupUser(ctx, email)
	if err != nil {
		return err
	}
	if u == nil {
		if !p.cfg.CreateUsers {
			p.log.Info("no Grafana user for member; skipping (enable create_users or let the user sign in first)",
				"email", email, "org_id", orgID)
			return nil
		}
		if u, err = p.createUser(ctx, orgID, m, email); err != nil {
			return err
		}
	}
	self, err := p.self(ctx)
	if err != nil {
		return err
	}
	if u.ID == self {
		return nil
	}
	users, err := p.orgUsers(ctx, orgID)
	if err != nil {
		return err
	}
	var cur *orgUser
	for i := range users {
		if users[i].UserID == u.ID {
			cur = &users[i]
		}
	}
	switch {
	case cur == nil:
		if err := p.addOrgUser(ctx, orgID, u.Login, role); err != nil {
			return err
		}
	case cur.Role != role:
		err := p.setOrgUserRole(ctx, orgID, u.ID, role)
		if isLastAdmin(err) {
			p.log.Warn("cannot demote the organization's last admin", "email", email, "org_id", orgID)
			return nil
		} else if err != nil {
			return err
		}
	}
	if role == RoleAdmin {
		// Another admin now exists, so the plugin's account can leave.
		return p.removeCreator(ctx, orgID)
	}
	return nil
}

// createUser creates a Grafana user for the member in the organization. It
// gets a random password nobody knows: the user signs in through SSO
// (OAuth/LDAP/auth proxy matching by email) or resets the password.
func (p *Plugin) createUser(ctx context.Context, orgID int64, m sdk.Member, email string) (*user, error) {
	name := email
	if u, err := p.host.GetUser(ctx, cmp.Or(m.UserID, email)); err == nil && u.Name != "" {
		name = u.Name
	}
	pw, err := randomPassword()
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"name": name, "email": email, "login": email, "password": pw, "OrgId": orgID,
	}
	status, err := p.call(ctx, "create user", http.MethodPost, "/api/admin/users", 0, body, nil,
		http.StatusConflict, http.StatusPreconditionFailed)
	if err != nil {
		return nil, err
	}
	u, err := p.lookupUser(ctx, email)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, fmt.Errorf("grafana: user %s not found after creation (status %d)", email, status)
	}
	return u, nil
}

// randomPassword returns a password meeting Grafana's strong password
// policy (upper, lower, digit, symbol, length).
func randomPassword() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "Tn!" + hex.EncodeToString(b) + "Z9", nil
}

// removeMember removes the Grafana user with the given email from the
// organization. Unknown users, non-members and the plugin's own account are
// ignored; Grafana's refusal to remove the last admin is logged.
func (p *Plugin) removeMember(ctx context.Context, orgID int64, email string) error {
	if email == "" {
		return nil
	}
	u, err := p.lookupUser(ctx, email)
	if err != nil || u == nil {
		return err
	}
	self, err := p.self(ctx)
	if err != nil || u.ID == self {
		return err
	}
	users, err := p.orgUsers(ctx, orgID)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(users, func(ou orgUser) bool { return ou.UserID == u.ID }) {
		return nil
	}
	err = p.removeOrgUser(ctx, orgID, u.ID)
	if isLastAdmin(err) {
		p.log.Warn("cannot remove the organization's last admin", "email", email, "org_id", orgID)
		return nil
	}
	return err
}
