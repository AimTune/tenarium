package vault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// marker is the ownership record kept as custom_metadata of the KV key
// "<prefix>/.tenarium-owner".
type marker struct {
	TenantID        string
	Role            string // "<mount>/<role>"
	Key             string // "<mount>/<key>"
	DeletedTenantID string
	DeletedAt       string
}

func (m *marker) metadata() map[string]string {
	out := map[string]string{}
	for k, v := range map[string]string{
		MetaTenantID:        m.TenantID,
		MetaAppRoleRole:     m.Role,
		MetaTransitKey:      m.Key,
		MetaDeletedTenantID: m.DeletedTenantID,
		MetaDeletedAt:       m.DeletedAt,
	} {
		if v != "" {
			out[k] = v
		}
	}
	return out
}

func (p *Plugin) markerPath(tg target) string {
	return p.cfg.KV.Mount + "/metadata/" + tg.Prefix + "/" + ownerKey
}

// readMarker returns the tenant prefix's marker, or nil if there is none.
func (p *Plugin) readMarker(ctx context.Context, tg target) (*marker, error) {
	var out struct {
		Data struct {
			CustomMetadata map[string]string `json:"custom_metadata"`
		} `json:"data"`
	}
	err := p.client.do(ctx, http.MethodGet, p.markerPath(tg), nil, nil, &out)
	if isNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read ownership marker: %w", err)
	}
	cm := out.Data.CustomMetadata
	return &marker{
		TenantID:        cm[MetaTenantID],
		Role:            cm[MetaAppRoleRole],
		Key:             cm[MetaTransitKey],
		DeletedTenantID: cm[MetaDeletedTenantID],
		DeletedAt:       cm[MetaDeletedAt],
	}, nil
}

// writeMarker replaces the marker's custom_metadata.
func (p *Plugin) writeMarker(ctx context.Context, tg target, m *marker) error {
	body := map[string]any{"custom_metadata": m.metadata()}
	if err := p.client.do(ctx, http.MethodPost, p.markerPath(tg), nil, body, nil); err != nil {
		return fmt.Errorf("write ownership marker %s/%s/%s: %w", p.cfg.KV.Mount, tg.Prefix, ownerKey, err)
	}
	return nil
}

// listKeys lists the KV keys directly under dir ("" entries ending in "/"
// are sub-directories). A missing directory lists as empty.
func (p *Plugin) listKeys(ctx context.Context, dir string) ([]string, error) {
	var out struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	err := p.client.do(ctx, http.MethodGet, p.cfg.KV.Mount+"/metadata/"+dir+"/", url.Values{"list": {"true"}}, nil, &out)
	if isNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list %s/%s: %w", p.cfg.KV.Mount, dir, err)
	}
	return out.Data.Keys, nil
}

// exists reports whether GET path succeeds (false on 404).
func (p *Plugin) exists(ctx context.Context, path string, out any) (bool, error) {
	err := p.client.do(ctx, http.MethodGet, path, nil, nil, out)
	if isNotFound(err) {
		return false, nil
	}
	return err == nil, err
}

// del deletes path, treating 404 as success.
func (p *Plugin) del(ctx context.Context, path string) error {
	if err := p.client.do(ctx, http.MethodDelete, path, nil, nil, nil); err != nil && !isNotFound(err) {
		return err
	}
	return nil
}

// Provision creates or converges the tenant's Vault resources. Every step
// is idempotent.
func (p *Plugin) Provision(ctx context.Context, t sdk.Tenant) error {
	tg, err := p.target(t)
	if err != nil {
		return err
	}
	m, err := p.readMarker(ctx, tg)
	if err != nil {
		return err
	}
	switch {
	case m == nil:
		if err := p.claim(ctx, t, tg); err != nil {
			return err
		}
		// Nothing exists yet (claim checked), so the role and key can be
		// recorded before they are created.
		m = &marker{TenantID: t.ID, Role: p.roleRef(tg), Key: p.keyRef(tg)}
		if err := p.writeMarker(ctx, tg, m); err != nil {
			return err
		}
	case m.TenantID == "" && m.DeletedTenantID != "":
		return fmt.Errorf("kv path %s/%s holds data retained from deleted tenant %s (deleted at %s); remove it before provisioning a tenant with this path",
			p.cfg.KV.Mount, tg.Prefix, m.DeletedTenantID, m.DeletedAt)
	case m.TenantID != t.ID:
		return fmt.Errorf("kv path %s/%s already belongs to another tenant (%s)", p.cfg.KV.Mount, tg.Prefix, m.TenantID)
	}

	if err := p.ensurePolicy(ctx, t, tg); err != nil {
		return err
	}
	if tg.Role != "" {
		if err := p.ensureRole(ctx, tg, m); err != nil {
			return err
		}
	} else if m.Role != "" {
		// approle was disabled: remove the role created earlier.
		if err := p.del(ctx, p.rolePath(m.Role)); err != nil {
			return fmt.Errorf("delete approle role %s: %w", m.Role, err)
		}
		m.Role = ""
		if err := p.writeMarker(ctx, tg, m); err != nil {
			return err
		}
	}
	if tg.Key != "" {
		if err := p.ensureKey(ctx, tg, m); err != nil {
			return err
		}
	}
	return nil
}

// claim checks that an unmarked prefix and the tenant's role and key can be
// taken: none of them may exist, except a policy already marked for the
// tenant. Nothing is written before every check passed.
func (p *Plugin) claim(ctx context.Context, t sdk.Tenant, tg target) error {
	keys, err := p.listKeys(ctx, tg.Prefix)
	if err != nil {
		return err
	}
	if len(keys) > 0 {
		return fmt.Errorf("kv path %s/%s is not empty and is not managed by tenarium", p.cfg.KV.Mount, tg.Prefix)
	}
	cur, ok, err := p.readPolicy(ctx, tg.Policy)
	if err != nil {
		return err
	}
	if err := checkPolicyOwner(t, tg.Policy, cur, ok); err != nil {
		return err
	}
	if tg.Role != "" {
		ok, err := p.exists(ctx, p.rolePath(p.roleRef(tg)), nil)
		if err != nil {
			return fmt.Errorf("approle role %s: %w", tg.Role, err)
		}
		if ok {
			return fmt.Errorf("approle role %s already exists and is not managed by tenarium", p.roleRef(tg))
		}
	}
	if tg.Key != "" {
		ok, err := p.exists(ctx, p.keyPath(p.keyRef(tg)), nil)
		if err != nil {
			return fmt.Errorf("transit key %s: %w", tg.Key, err)
		}
		if ok {
			return fmt.Errorf("transit key %s already exists and is not managed by tenarium", p.keyRef(tg))
		}
	}
	return nil
}

func splitRef(ref string) (mount, name string) {
	i := strings.LastIndex(ref, "/")
	return ref[:i], ref[i+1:]
}

func (p *Plugin) rolePath(ref string) string {
	mount, name := splitRef(ref)
	return "auth/" + mount + "/role/" + name
}

func (p *Plugin) keyPath(ref string) string {
	mount, name := splitRef(ref)
	return mount + "/keys/" + name
}

func policyPath(name string) string { return "sys/policies/acl/" + name }

// policyOwner returns the tenant ID in a policy's header line, or "".
func policyOwner(hcl string) string {
	first, _, _ := strings.Cut(strings.TrimSpace(hcl), "\n")
	if id, ok := strings.CutPrefix(strings.TrimSpace(first), policyHeaderPrefix); ok {
		return strings.TrimSpace(id)
	}
	return ""
}

// checkPolicyOwner fails if an existing policy is not marked for t.
func checkPolicyOwner(t sdk.Tenant, name, cur string, exists bool) error {
	if !exists {
		return nil
	}
	switch owner := policyOwner(cur); owner {
	case t.ID:
		return nil
	case "":
		return fmt.Errorf("policy %s already exists and is not managed by tenarium (no %q header)", name, policyHeaderPrefix)
	default:
		return fmt.Errorf("policy %s already belongs to another tenant (%s)", name, owner)
	}
}

// readPolicy returns a policy's text and whether it exists.
func (p *Plugin) readPolicy(ctx context.Context, name string) (string, bool, error) {
	var out struct {
		Data struct {
			Policy string `json:"policy"`
		} `json:"data"`
	}
	ok, err := p.exists(ctx, policyPath(name), &out)
	if err != nil {
		return "", false, fmt.Errorf("read policy %s: %w", name, err)
	}
	return out.Data.Policy, ok, nil
}

func (p *Plugin) ensurePolicy(ctx context.Context, t sdk.Tenant, tg target) error {
	want, err := p.renderPolicy(t, tg)
	if err != nil {
		return err
	}
	cur, ok, err := p.readPolicy(ctx, tg.Policy)
	if err != nil {
		return err
	}
	if err := checkPolicyOwner(t, tg.Policy, cur, ok); err != nil {
		return err
	}
	if ok && cur == want {
		return nil
	}
	if err := p.client.do(ctx, http.MethodPut, policyPath(tg.Policy), nil, map[string]string{"policy": want}, nil); err != nil {
		return fmt.Errorf("write policy %s: %w", tg.Policy, err)
	}
	return nil
}

// extraData is the template data of policy.extra_rules.
type extraData struct {
	Tenant       sdk.Tenant
	KVMount      string
	Prefix       string
	Policy       string
	AppRoleMount string
	Role         string
	TransitMount string
	TransitKey   string
}

func (p *Plugin) renderExtra(t sdk.Tenant, tg target) (string, error) {
	d := extraData{Tenant: t, KVMount: p.cfg.KV.Mount, Prefix: tg.Prefix, Policy: tg.Policy, Role: tg.Role, TransitKey: tg.Key}
	if p.cfg.AppRole != nil {
		d.AppRoleMount = p.cfg.AppRole.Mount
	}
	if p.cfg.Transit != nil {
		d.TransitMount = p.cfg.Transit.Mount
	}
	var b strings.Builder
	if err := p.extra.Execute(&b, d); err != nil {
		return "", err
	}
	return b.String(), nil
}

func hclList(items []string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = `"` + s + `"`
	}
	return "[" + strings.Join(q, ", ") + "]"
}

// renderPolicy builds the tenant's ACL policy. All interpolated names are
// sanitized or validated mount paths, so they cannot break out of the HCL
// strings.
func (p *Plugin) renderPolicy(t sdk.Tenant, tg target) (string, error) {
	var b strings.Builder
	rule := func(path string, caps []string) {
		fmt.Fprintf(&b, "path %q {\n  capabilities = %s\n}\n\n", path, hclList(caps))
	}
	fmt.Fprintf(&b, "%s %s\n", policyHeaderPrefix, t.ID)
	fmt.Fprintf(&b, "# Managed by tenarium (%s); manual changes are overwritten.\n\n", PluginID)

	kv, prefix, caps := p.cfg.KV.Mount, tg.Prefix, p.cfg.Policy.Capabilities
	rule(kv+"/data/"+prefix+"/*", caps)
	rule(kv+"/metadata/"+prefix+"/*", caps)
	rule(kv+"/metadata/"+prefix, []string{"list"})
	if slices.Contains(caps, "delete") {
		for _, op := range []string{"delete", "undelete", "destroy"} {
			rule(kv+"/"+op+"/"+prefix+"/*", []string{"update"})
		}
	}
	// The ownership marker is tenarium's; exact paths take precedence over
	// the globs above.
	for _, op := range []string{"data", "metadata", "delete", "undelete", "destroy"} {
		rule(kv+"/"+op+"/"+prefix+"/"+ownerKey, []string{"deny"})
	}
	if tg.Key != "" {
		tm := p.cfg.Transit.Mount
		for _, op := range []string{"encrypt", "decrypt", "rewrap"} {
			rule(tm+"/"+op+"/"+tg.Key, []string{"update"})
		}
		rule(tm+"/datakey/+/"+tg.Key, []string{"update"})
	}
	if p.extra != nil {
		extra, err := p.renderExtra(t, tg)
		if err != nil {
			return "", fmt.Errorf("policy.extra_rules: %w", err)
		}
		b.WriteString(strings.TrimSpace(extra))
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n") + "\n", nil
}

func (p *Plugin) ensureRole(ctx context.Context, tg target, m *marker) error {
	ref := p.roleRef(tg)
	if m.Role != ref {
		ok, err := p.exists(ctx, p.rolePath(ref), nil)
		if err != nil {
			return fmt.Errorf("approle role %s: %w", ref, err)
		}
		if ok {
			return fmt.Errorf("approle role %s already exists and is not managed by tenarium for this tenant", ref)
		}
		if m.Role != "" {
			// The role template or mount changed: the old role stays
			// recorded nowhere, so remove it now to not leak access.
			if err := p.del(ctx, p.rolePath(m.Role)); err != nil {
				return fmt.Errorf("delete previous approle role %s: %w", m.Role, err)
			}
		}
		m.Role = ref
		if err := p.writeMarker(ctx, tg, m); err != nil {
			return err
		}
	}
	a := p.cfg.AppRole
	body := map[string]any{"token_policies": append([]string{tg.Policy}, a.TokenPolicies...)}
	for k, v := range map[string]string{"token_ttl": a.TokenTTL, "token_max_ttl": a.TokenMaxTTL, "secret_id_ttl": a.SecretIDTTL} {
		if v != "" {
			body[k] = v
		}
	}
	if err := p.client.do(ctx, http.MethodPost, p.rolePath(ref), nil, body, nil); err != nil {
		return fmt.Errorf("write approle role %s: %w", ref, err)
	}
	return nil
}

func (p *Plugin) ensureKey(ctx context.Context, tg target, m *marker) error {
	ref := p.keyRef(tg)
	var out struct {
		Data struct {
			Type string `json:"type"`
		} `json:"data"`
	}
	ok, err := p.exists(ctx, p.keyPath(ref), &out)
	if err != nil {
		return fmt.Errorf("transit key %s: %w", ref, err)
	}
	if m.Key != ref {
		if ok {
			return fmt.Errorf("transit key %s already exists and is not managed by tenarium for this tenant", ref)
		}
		// A previously recorded key (template or mount changed) is kept:
		// deleting it would destroy data encrypted with it. It stays in
		// Vault for an operator to handle.
		if m.Key != "" {
			p.log.Warn("transit key no longer matches the configuration; leaving the old key in place",
				"old_key", m.Key, "new_key", ref)
		}
		m.Key = ref
		if err := p.writeMarker(ctx, tg, m); err != nil {
			return err
		}
	}
	if ok {
		if out.Data.Type != "" && out.Data.Type != p.cfg.Transit.Type {
			return fmt.Errorf("transit key %s has type %s, configured type is %s; key types cannot be changed", ref, out.Data.Type, p.cfg.Transit.Type)
		}
		return nil
	}
	if err := p.client.do(ctx, http.MethodPost, p.keyPath(ref), nil, map[string]any{"type": p.cfg.Transit.Type}, nil); err != nil {
		return fmt.Errorf("create transit key %s: %w", ref, err)
	}
	return nil
}

// Deprovision applies on_deprovision. Resources are only removed when the
// marker (or, for policies, the header) names the tenant; a tenant that was
// never provisioned or is already deprovisioned is a no-op.
func (p *Plugin) Deprovision(ctx context.Context, t sdk.Tenant) error {
	if p.cfg.OnDeprovision == DeprovisionKeep {
		return nil
	}
	tg, err := p.target(t)
	if err != nil {
		return err
	}
	m, err := p.readMarker(ctx, tg)
	if err != nil {
		return err
	}
	owned := m != nil && m.TenantID == t.ID
	if m != nil && !owned {
		p.log.Warn("not deprovisioning vault resources marked for another tenant",
			"kv_mount", p.cfg.KV.Mount, "prefix", tg.Prefix, "tenant_id", t.ID,
			"owner", m.TenantID, "retained_from", m.DeletedTenantID)
	}

	// Revoke access first: the role, then the policy.
	if owned && m.Role != "" {
		if err := p.del(ctx, p.rolePath(m.Role)); err != nil {
			return fmt.Errorf("delete approle role %s: %w", m.Role, err)
		}
	}
	if err := p.deletePolicy(ctx, t, tg.Policy); err != nil {
		return err
	}
	if !owned {
		return nil
	}

	if p.cfg.OnDeprovision == DeprovisionRetain {
		r := &marker{Key: m.Key, DeletedTenantID: t.ID, DeletedAt: p.now().UTC().Format(time.RFC3339)}
		return p.writeMarker(ctx, tg, r)
	}

	if m.Key != "" {
		if err := p.deleteKey(ctx, m.Key); err != nil {
			return err
		}
	}
	// The marker goes last so an interrupted run is retried.
	if err := p.deleteTree(ctx, tg.Prefix, true); err != nil {
		return err
	}
	if err := p.del(ctx, p.markerPath(tg)); err != nil {
		return fmt.Errorf("delete ownership marker: %w", err)
	}
	return nil
}

// deletePolicy deletes the policy if its header names the tenant.
func (p *Plugin) deletePolicy(ctx context.Context, t sdk.Tenant, name string) error {
	cur, ok, err := p.readPolicy(ctx, name)
	if err != nil || !ok {
		return err
	}
	if owner := policyOwner(cur); owner != t.ID {
		p.log.Warn("not deleting a policy not managed by tenarium for this tenant",
			"policy", name, "tenant_id", t.ID, "owner", owner)
		return nil
	}
	if err := p.del(ctx, policyPath(name)); err != nil {
		return fmt.Errorf("delete policy %s: %w", name, err)
	}
	return nil
}

// deleteKey allows deletion of a transit key and deletes it.
func (p *Plugin) deleteKey(ctx context.Context, ref string) error {
	ok, err := p.exists(ctx, p.keyPath(ref), nil)
	if err != nil {
		return fmt.Errorf("transit key %s: %w", ref, err)
	}
	if !ok {
		return nil
	}
	if err := p.client.do(ctx, http.MethodPost, p.keyPath(ref)+"/config", nil, map[string]any{"deletion_allowed": true}, nil); err != nil {
		return fmt.Errorf("allow deletion of transit key %s: %w", ref, err)
	}
	if err := p.del(ctx, p.keyPath(ref)); err != nil {
		return fmt.Errorf("delete transit key %s: %w", ref, err)
	}
	return nil
}

// deleteTree deletes every KV key (all versions and metadata) under dir;
// at the top level the ownership marker is skipped.
func (p *Plugin) deleteTree(ctx context.Context, dir string, top bool) error {
	keys, err := p.listKeys(ctx, dir)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if top && k == ownerKey {
			continue
		}
		if sub, ok := strings.CutSuffix(k, "/"); ok {
			if sub == "" {
				continue
			}
			if err := p.deleteTree(ctx, dir+"/"+sub, false); err != nil {
				return err
			}
			continue
		}
		if err := p.del(ctx, p.cfg.KV.Mount+"/metadata/"+dir+"/"+k); err != nil {
			return fmt.Errorf("delete %s/%s/%s: %w", p.cfg.KV.Mount, dir, k, err)
		}
	}
	return nil
}

var errNotProvisioned = errors.New("vault resources for this tenant are not provisioned")

// ownedMarker returns the tenant's marker, or errNotProvisioned if the
// prefix is not marked for the tenant.
func (p *Plugin) ownedMarker(ctx context.Context, t sdk.Tenant, tg target) (*marker, error) {
	m, err := p.readMarker(ctx, tg)
	if err != nil {
		return nil, err
	}
	if m == nil || m.TenantID != t.ID {
		return nil, errNotProvisioned
	}
	return m, nil
}
