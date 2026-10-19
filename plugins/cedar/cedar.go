// Package cedar is an in-process sdk.Authorizer evaluating Cedar policies
// (https://www.cedarpolicy.com) with github.com/cedar-policy/cedar-go.
//
// Every request becomes a Cedar request:
//
//	principal: User::"<subject>" (Service::"<subject>" for services),
//	           in Role::"<role>" for each role and in Tenant::"<tenant_id>"
//	           when the caller is tenant-scoped
//	action:    Action::"tenants:update", in Action::"tenants:*" and Action::"*:update"
//	resource:  Tenant::"<id>" for tenants, otherwise <Type>::"<id>" in
//	           Tenant::"<tenant_id>"; tenants are in their parent tenant,
//	           so `resource in Tenant::"<org>"` covers the whole subtree
//
// A matching forbid denies, a matching permit allows, and no match abstains
// (configurable). The core's tenant-scope rule is applied before any
// authorizer and cannot be relaxed by a policy.
package cedar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/AimTune/tenarium/pkg/sdk"
	cedar "github.com/cedar-policy/cedar-go"
)

func init() {
	sdk.Register("cedar", func() sdk.Plugin { return &Plugin{} })
}

type Config struct {
	// Policies is inline Cedar policy text.
	Policies string `json:"policies"`
	// PolicyFiles are files with Cedar policies, concatenated with Policies.
	PolicyFiles []string `json:"policy_files"`
	// EntitiesFile is an optional Cedar entities JSON file with static
	// entities, such as a role hierarchy (Role::"admin" in Role::"viewer").
	EntitiesFile string `json:"entities_file"`
	// ReloadInterval polls the files for changes, e.g. "10s". Empty or
	// "0s" disables reloading. A file that fails to parse keeps the
	// previous policies and makes Health report the error.
	ReloadInterval string `json:"reload_interval"`
	// OnNoMatch is the decision when no policy matched: "abstain"
	// (default) or "deny" (Cedar's own default-deny).
	OnNoMatch string `json:"on_no_match"`
	// FailMode is the decision when the request cannot be evaluated (for
	// example tenant lookups fail): "abstain" (default) or "deny".
	FailMode string `json:"fail_mode"`

	// PrincipalTypes maps principal kinds to entity types (default
	// user: User, service: Service; other kinds use the "user" type).
	PrincipalTypes map[string]string `json:"principal_types"`
	RoleType       string            `json:"role_type"`
	TenantType     string            `json:"tenant_type"`
	ActionType     string            `json:"action_type"`
	// ResourceTypes maps Tenarium resource types to entity types. Unmapped
	// types are converted to CamelCase ("signing_key" → SigningKey).
	ResourceTypes map[string]string `json:"resource_types"`
	// TenantCacheTTL caches tenant lookups, e.g. "10s"; "0s" disables.
	TenantCacheTTL string `json:"tenant_cache_ttl"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "policies": {"type": "string"},
    "policy_files": {"type": "array", "items": {"type": "string", "minLength": 1}},
    "entities_file": {"type": "string"},
    "reload_interval": {"type": "string"},
    "on_no_match": {"enum": ["abstain", "deny"]},
    "fail_mode": {"enum": ["abstain", "deny"]},
    "principal_types": {"type": "object", "additionalProperties": {"type": "string", "minLength": 1}},
    "role_type": {"type": "string", "minLength": 1},
    "tenant_type": {"type": "string", "minLength": 1},
    "action_type": {"type": "string", "minLength": 1},
    "resource_types": {"type": "object", "additionalProperties": {"type": "string", "minLength": 1}},
    "tenant_cache_ttl": {"type": "string"}
  },
  "anyOf": [
    {"required": ["policies"], "properties": {"policies": {"minLength": 1}}},
    {"required": ["policy_files"], "properties": {"policy_files": {"minItems": 1}}}
  ],
  "additionalProperties": false
}`)

// maxDepth bounds tenant ancestry walks.
const maxDepth = 32

var entityTypeRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)*$`)

// Result is a decision with a human-readable reason.
type Result struct {
	Decision sdk.Decision
	Reason   string
}

// state is an immutable snapshot of loaded policies and static entities.
type state struct {
	policies *cedar.PolicySet
	ids      []string
	static   cedar.EntityMap
	stamps   map[string]fileStamp
}

type fileStamp struct {
	mod  time.Time
	size int64
}

type Plugin struct {
	cfg       Config
	name      string
	host      sdk.Host
	log       *slog.Logger
	denyNoHit bool
	denyOnErr bool
	tenantTTL time.Duration
	reload    time.Duration

	state   atomic.Pointer[state]
	loadErr atomic.Pointer[error]
	stop    chan struct{}
	done    chan struct{}

	tenantMu sync.Mutex
	tenants  map[string]tenantEntry
	now      func() time.Time
	// next holds the configuration applied by Reconfigure.
	next atomic.Pointer[Plugin]
}

var (
	_ sdk.Authorizer    = (*Plugin)(nil)
	_ sdk.HealthChecker = (*Plugin)(nil)
	_ sdk.Stopper       = (*Plugin)(nil)
	_ sdk.Reconfigurer  = (*Plugin)(nil)
)

type tenantEntry struct {
	t       sdk.Tenant
	found   bool
	expires time.Time
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "cedar",
		Name:         "Cedar",
		Version:      "0.1.0",
		Description:  "Authorizes API actions with Cedar policies evaluated in-process.",
		ConfigSchema: configSchema,
	}
}

func (p *Plugin) Init(_ context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	if err := p.setup(); err != nil {
		return err
	}
	p.host = r.Host()
	p.log = r.Logger()
	p.name = r.InstanceName()
	p.now = time.Now
	r.Authorizer(p)
	// Polling runs whenever an interval is set, so policy files introduced
	// by Reconfigure are watched as well.
	if p.reload > 0 {
		p.stop, p.done = make(chan struct{}), make(chan struct{})
		go p.watch()
	}
	return nil
}

// setup applies defaults, validates p.cfg and loads the policies.
func (p *Plugin) setup() error {
	c := &p.cfg
	setDefault(&c.OnNoMatch, "abstain")
	setDefault(&c.FailMode, "abstain")
	setDefault(&c.RoleType, "Role")
	setDefault(&c.TenantType, "Tenant")
	setDefault(&c.ActionType, "Action")
	setDefault(&c.TenantCacheTTL, "10s")
	pt := map[string]string{"user": "User", "service": "Service"}
	for k, v := range c.PrincipalTypes {
		pt[k] = v
	}
	c.PrincipalTypes = pt
	if strings.TrimSpace(c.Policies) == "" && len(c.PolicyFiles) == 0 {
		return errors.New("policies or policy_files is required")
	}
	if err := oneOf("on_no_match", c.OnNoMatch, "abstain", "deny"); err != nil {
		return err
	}
	if err := oneOf("fail_mode", c.FailMode, "abstain", "deny"); err != nil {
		return err
	}
	types := map[string]string{"role_type": c.RoleType, "tenant_type": c.TenantType, "action_type": c.ActionType}
	for k, v := range c.PrincipalTypes {
		types["principal_types."+k] = v
	}
	for k, v := range c.ResourceTypes {
		types["resource_types."+k] = v
	}
	for field, v := range types {
		if !entityTypeRE.MatchString(v) {
			return fmt.Errorf("%s %q is not a valid Cedar entity type", field, v)
		}
	}
	var err error
	if p.tenantTTL, err = time.ParseDuration(c.TenantCacheTTL); err != nil || p.tenantTTL < 0 {
		return fmt.Errorf("tenant_cache_ttl %q: must be a non-negative duration", c.TenantCacheTTL)
	}
	if c.ReloadInterval != "" {
		if p.reload, err = time.ParseDuration(c.ReloadInterval); err != nil || p.reload < 0 {
			return fmt.Errorf("reload_interval %q: must be a non-negative duration", c.ReloadInterval)
		}
	}
	st, err := p.load()
	if err != nil {
		return err
	}
	p.state.Store(st)
	p.denyNoHit = c.OnNoMatch == "deny"
	p.denyOnErr = c.FailMode == "deny"
	p.tenants = map[string]tenantEntry{}
	return nil
}

// Reconfigure applies new policies, entities, decision settings, entity
// types and the tenant cache TTL without a restart; the tenant cache starts
// empty. Policies that fail to parse reject the change and keep the current
// ones. reload_interval is fixed at startup.
func (p *Plugin) Reconfigure(_ context.Context, decode func(v any) error) error {
	n := &Plugin{host: p.host, log: p.log, name: p.name, now: p.now}
	if err := decode(&n.cfg); err != nil {
		return err
	}
	if err := n.setup(); err != nil {
		return err
	}
	if n.reload != p.reload {
		return errors.New("reload_interval takes effect after a restart")
	}
	p.next.Store(n)
	return nil
}

func (p *Plugin) Name() string {
	if p.name == "" {
		return "cedar"
	}
	return p.name
}

// load parses all policy sources and the entities file.
func (p *Plugin) load() (*state, error) {
	st := &state{policies: cedar.NewPolicySet(), static: cedar.EntityMap{}, stamps: map[string]fileStamp{}}
	seen := map[string]string{}
	add := func(source string, text []byte) error {
		list, err := cedar.NewPolicyListFromBytes(source, text)
		if err != nil {
			return fmt.Errorf("%s: %w", source, err)
		}
		for i, pol := range list {
			id := fmt.Sprintf("%s#%d", source, i)
			if a, ok := pol.Annotations()["id"]; ok && a != "" {
				id = string(a)
			}
			if prev, dup := seen[id]; dup {
				return fmt.Errorf("%s: duplicate policy id %q (also in %s)", source, id, prev)
			}
			seen[id] = source
			st.policies.Add(cedar.PolicyID(id), pol)
			st.ids = append(st.ids, id)
		}
		return nil
	}
	if strings.TrimSpace(p.cfg.Policies) != "" {
		if err := add("inline", []byte(p.cfg.Policies)); err != nil {
			return nil, err
		}
	}
	for _, f := range p.cfg.PolicyFiles {
		data, stamp, err := readFile(f)
		if err != nil {
			return nil, err
		}
		st.stamps[f] = stamp
		if err := add(filepath.Base(f), data); err != nil {
			return nil, err
		}
	}
	if len(st.ids) == 0 {
		return nil, errors.New("no Cedar policies found")
	}
	if p.cfg.EntitiesFile != "" {
		data, stamp, err := readFile(p.cfg.EntitiesFile)
		if err != nil {
			return nil, err
		}
		st.stamps[p.cfg.EntitiesFile] = stamp
		if err := json.Unmarshal(data, &st.static); err != nil {
			return nil, fmt.Errorf("%s: %w", p.cfg.EntitiesFile, err)
		}
	}
	return st, nil
}

func readFile(name string) ([]byte, fileStamp, error) {
	fi, err := os.Stat(name)
	if err != nil {
		return nil, fileStamp{}, err
	}
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, fileStamp{}, err
	}
	return data, fileStamp{mod: fi.ModTime(), size: fi.Size()}, nil
}

func (p *Plugin) watch() {
	defer close(p.done)
	t := time.NewTicker(p.reload)
	defer t.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-t.C:
			p.reloadIfChanged()
		}
	}
}

// reloadIfChanged reloads when any file's modification time or size
// changed. On failure the previous policies stay in force.
func (p *Plugin) reloadIfChanged() bool {
	if n := p.next.Load(); n != nil {
		return n.reloadIfChanged()
	}
	cur := p.state.Load()
	changed := false
	for name, old := range cur.stamps {
		fi, err := os.Stat(name)
		if err != nil || !fi.ModTime().Equal(old.mod) || fi.Size() != old.size {
			changed = true
			break
		}
	}
	if !changed {
		return false
	}
	st, err := p.load()
	if err != nil {
		p.log.Error("cedar reload failed; keeping previous policies", "err", err)
		p.loadErr.Store(&err)
		return false
	}
	p.state.Store(st)
	p.loadErr.Store(nil)
	p.log.Info("cedar policies reloaded", "policies", len(st.ids))
	return true
}

// Health reports the last failed reload, if any.
func (p *Plugin) Health(ctx context.Context) error {
	if n := p.next.Load(); n != nil {
		return n.Health(ctx)
	}
	if e := p.loadErr.Load(); e != nil {
		return fmt.Errorf("cedar: reload failed: %w", *e)
	}
	return nil
}

// Stop ends file polling.
func (p *Plugin) Stop(ctx context.Context) error {
	if p.stop == nil {
		return nil
	}
	select {
	case <-p.stop:
	default:
		close(p.stop)
	}
	select {
	case <-p.done:
	case <-ctx.Done():
	}
	return nil
}

// Authorize implements sdk.Authorizer. It never returns an error: failures
// become the configured fail_mode decision, and denials are logged with
// their reason.
func (p *Plugin) Authorize(ctx context.Context, pr *sdk.Principal, action sdk.Action, res sdk.Resource) (sdk.Decision, error) {
	if n := p.next.Load(); n != nil {
		return n.Authorize(ctx, pr, action, res)
	}
	r := p.Check(ctx, pr, action, res)
	if r.Decision == sdk.Deny {
		subject := ""
		if pr != nil {
			subject = pr.Authenticator + ":" + pr.Subject
		}
		p.log.Info("cedar denied", "action", action, "resource_type", res.Type, "resource_id", res.ID,
			"tenant_id", res.TenantID, "subject", subject, "reason", r.Reason)
	} else {
		p.log.Debug("cedar decision", "action", action, "decision", r.Decision, "reason", r.Reason)
	}
	return r.Decision, nil
}

// Check returns the decision for a request with its reason.
func (p *Plugin) Check(ctx context.Context, pr *sdk.Principal, action sdk.Action, res sdk.Resource) Result {
	if n := p.next.Load(); n != nil {
		return n.Check(ctx, pr, action, res)
	}
	if pr == nil {
		return Result{sdk.Abstain, "no principal"}
	}
	st := p.state.Load()
	req, entities, err := p.request(ctx, st, pr, action, res)
	if err != nil {
		p.log.Warn("cedar request failed", "fail_mode", p.cfg.FailMode, "err", err)
		if p.denyOnErr {
			return Result{sdk.Deny, "cedar: " + err.Error() + " (fail_mode deny)"}
		}
		return Result{sdk.Abstain, "cedar: " + err.Error()}
	}
	decision, diag := cedar.Authorize(st.policies, entities, req)
	if len(diag.Errors) > 0 {
		msgs := make([]string, len(diag.Errors))
		for i, e := range diag.Errors {
			msgs[i] = e.String()
		}
		// Cedar skips policies that fail to evaluate; surface them.
		p.log.Warn("cedar policy errors", "action", action, "errors", msgs)
	}
	ids := make([]string, len(diag.Reasons))
	for i, r := range diag.Reasons {
		ids[i] = string(r.PolicyID)
	}
	slices.Sort(ids)
	switch {
	case decision == cedar.Allow:
		return Result{sdk.Allow, "cedar: permitted by " + strings.Join(ids, ", ")}
	case len(ids) > 0:
		return Result{sdk.Deny, "cedar: forbidden by " + strings.Join(ids, ", ")}
	case p.denyNoHit:
		return Result{sdk.Deny, "cedar: no policy permits " + string(action)}
	default:
		return Result{sdk.Abstain, "cedar: no policy matched " + string(action)}
	}
}

// overlay serves request entities first, then static ones.
type overlay struct {
	req, static cedar.EntityMap
}

func (o overlay) Get(uid cedar.EntityUID) (cedar.Entity, bool) {
	if e, ok := o.req[uid]; ok {
		return e, true
	}
	e, ok := o.static[uid]
	return e, ok
}

func (p *Plugin) request(ctx context.Context, st *state, pr *sdk.Principal, action sdk.Action, res sdk.Resource) (cedar.Request, cedar.EntityGetter, error) {
	ents := cedar.EntityMap{}
	tenantUID := func(id string) cedar.EntityUID {
		return cedar.NewEntityUID(cedar.EntityType(p.cfg.TenantType), cedar.String(id))
	}

	// Principal.
	ptype, ok := p.cfg.PrincipalTypes[pr.Kind]
	if !ok {
		ptype = p.cfg.PrincipalTypes["user"]
	}
	principal := cedar.NewEntityUID(cedar.EntityType(ptype), cedar.String(pr.Subject))
	var parents []cedar.EntityUID
	roles := make([]cedar.Value, 0, len(pr.Roles))
	for _, r := range pr.Roles {
		parents = append(parents, cedar.NewEntityUID(cedar.EntityType(p.cfg.RoleType), cedar.String(r)))
		roles = append(roles, cedar.String(r))
	}
	attrs := cedar.RecordMap{
		"subject":       cedar.String(pr.Subject),
		"kind":          cedar.String(pr.Kind),
		"authenticator": cedar.String(pr.Authenticator),
		"roles":         cedar.NewSet(roles...),
	}
	if pr.TenantID != "" {
		parents = append(parents, tenantUID(pr.TenantID))
		attrs["tenant_id"] = cedar.String(pr.TenantID)
		if err := p.addTenantChain(ctx, ents, pr.TenantID); err != nil {
			return cedar.Request{}, nil, err
		}
	}
	if len(pr.Claims) > 0 {
		attrs["claims"] = toRecord(pr.Claims)
	}
	ents[principal] = cedar.Entity{UID: principal, Parents: cedar.NewEntityUIDSet(parents...), Attributes: cedar.NewRecord(attrs)}

	// Action, with group parents "<resource>:*" and "*:<verb>".
	actType := cedar.EntityType(p.cfg.ActionType)
	actUID := cedar.NewEntityUID(actType, cedar.String(action))
	var actParents []cedar.EntityUID
	if resource, verb, ok := strings.Cut(string(action), ":"); ok {
		actParents = append(actParents,
			cedar.NewEntityUID(actType, cedar.String(resource+":*")),
			cedar.NewEntityUID(actType, cedar.String("*:"+verb)))
	}
	ents[actUID] = cedar.Entity{UID: actUID, Parents: cedar.NewEntityUIDSet(actParents...)}

	// Resource and its tenant chain. A tenant is its own entity from the
	// chain; other resources (and tenants about to be created) are in their
	// tenant.
	rtype := p.resourceType(res.Type)
	resUID := cedar.NewEntityUID(cedar.EntityType(rtype), cedar.String(res.ID))
	if rtype == p.cfg.TenantType && res.ID != "" {
		if err := p.addTenantChain(ctx, ents, res.ID); err != nil {
			return cedar.Request{}, nil, err
		}
	} else {
		rattrs := cedar.RecordMap{"type": cedar.String(res.Type), "id": cedar.String(res.ID)}
		var rparents []cedar.EntityUID
		if res.TenantID != "" {
			if err := p.addTenantChain(ctx, ents, res.TenantID); err != nil {
				return cedar.Request{}, nil, err
			}
			rattrs["tenant_id"] = cedar.String(res.TenantID)
			rparents = append(rparents, tenantUID(res.TenantID))
		}
		ents[resUID] = cedar.Entity{UID: resUID, Parents: cedar.NewEntityUIDSet(rparents...), Attributes: cedar.NewRecord(rattrs)}
	}

	req := cedar.Request{
		Principal: principal,
		Action:    actUID,
		Resource:  resUID,
		Context: cedar.NewRecord(cedar.RecordMap{
			"resource_type": cedar.String(res.Type),
			"tenant_scoped": cedar.Boolean(pr.TenantID != ""),
		}),
	}
	return req, overlay{req: ents, static: st.static}, nil
}

// addTenantChain adds the tenant and its ancestors as entities, each in
// its parent. Unknown tenants end the chain.
func (p *Plugin) addTenantChain(ctx context.Context, ents cedar.EntityMap, id string) error {
	for range maxDepth {
		uid := cedar.NewEntityUID(cedar.EntityType(p.cfg.TenantType), cedar.String(id))
		if _, done := ents[uid]; done {
			return nil
		}
		t, found, err := p.tenant(ctx, id)
		if err != nil {
			return fmt.Errorf("tenant %s: %w", id, err)
		}
		if !found {
			ents[uid] = cedar.Entity{UID: uid, Attributes: cedar.NewRecord(cedar.RecordMap{"id": cedar.String(id)})}
			return nil
		}
		labels := cedar.RecordMap{}
		for k, v := range t.Labels {
			labels[cedar.String(k)] = cedar.String(v)
		}
		attrs := cedar.RecordMap{
			"id":     cedar.String(t.ID),
			"slug":   cedar.String(t.Slug),
			"name":   cedar.String(t.Name),
			"status": cedar.String(t.Status),
			"plan":   cedar.String(t.Plan),
			"labels": cedar.NewRecord(labels),
		}
		var parents []cedar.EntityUID
		if t.ParentID != "" {
			attrs["parent_id"] = cedar.String(t.ParentID)
			parents = append(parents, cedar.NewEntityUID(cedar.EntityType(p.cfg.TenantType), cedar.String(t.ParentID)))
		}
		ents[uid] = cedar.Entity{UID: uid, Parents: cedar.NewEntityUIDSet(parents...), Attributes: cedar.NewRecord(attrs)}
		if t.ParentID == "" {
			return nil
		}
		id = t.ParentID
	}
	return nil
}

func (p *Plugin) tenant(ctx context.Context, id string) (sdk.Tenant, bool, error) {
	if p.tenantTTL > 0 {
		p.tenantMu.Lock()
		e, ok := p.tenants[id]
		p.tenantMu.Unlock()
		if ok && p.now().Before(e.expires) {
			return e.t, e.found, nil
		}
	}
	t, err := p.host.GetTenant(ctx, id)
	found := err == nil
	if err != nil && !errors.Is(err, sdk.ErrNotFound) {
		return sdk.Tenant{}, false, err
	}
	if p.tenantTTL > 0 {
		p.tenantMu.Lock()
		if len(p.tenants) >= 10000 {
			clear(p.tenants)
		}
		p.tenants[id] = tenantEntry{t: t, found: found, expires: p.now().Add(p.tenantTTL)}
		p.tenantMu.Unlock()
	}
	return t, found, nil
}

func (p *Plugin) resourceType(typ string) string {
	if t, ok := p.cfg.ResourceTypes[typ]; ok {
		return t
	}
	if typ == "tenant" {
		return p.cfg.TenantType
	}
	var b strings.Builder
	upper := true
	for _, r := range typ {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) || r > unicode.MaxASCII {
			upper = true
			continue
		}
		if upper {
			r = unicode.ToUpper(r)
			upper = false
		}
		b.WriteRune(r)
	}
	s := b.String()
	if s == "" || unicode.IsDigit(rune(s[0])) {
		s = "Resource" + s
	}
	return s
}

// toRecord converts JSON-like claims to a Cedar record. Values without a
// Cedar equivalent (null, fractional numbers) are dropped.
func toRecord(m map[string]any) cedar.Record {
	rm := cedar.RecordMap{}
	for k, v := range m {
		if cv, ok := toValue(v); ok {
			rm[cedar.String(k)] = cv
		}
	}
	return cedar.NewRecord(rm)
}

func toValue(v any) (cedar.Value, bool) {
	switch x := v.(type) {
	case string:
		return cedar.String(x), true
	case bool:
		return cedar.Boolean(x), true
	case float64:
		if x == float64(int64(x)) {
			return cedar.Long(int64(x)), true
		}
	case int:
		return cedar.Long(x), true
	case int64:
		return cedar.Long(x), true
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return cedar.Long(i), true
		}
	case []any:
		vals := make([]cedar.Value, 0, len(x))
		for _, e := range x {
			if cv, ok := toValue(e); ok {
				vals = append(vals, cv)
			}
		}
		return cedar.NewSet(vals...), true
	case []string:
		vals := make([]cedar.Value, len(x))
		for i, e := range x {
			vals[i] = cedar.String(e)
		}
		return cedar.NewSet(vals...), true
	case map[string]any:
		return toRecord(x), true
	}
	return nil, false
}

func setDefault(s *string, v string) {
	if *s == "" {
		*s = v
	}
}

func oneOf(field, v string, allowed ...string) error {
	if slices.Contains(allowed, v) {
		return nil
	}
	return fmt.Errorf("%s %q must be one of %q", field, v, allowed)
}
