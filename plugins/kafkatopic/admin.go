package kafkatopic

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/kmsg"
)

// aclBinding is one Kafka ACL.
type aclBinding struct {
	Type      kmsg.ACLResourceType
	Name      string
	Pattern   kmsg.ACLResourcePatternType
	Principal string
	Host      string
	Operation kmsg.ACLOperation
	Perm      kmsg.ACLPermissionType
}

func (b aclBinding) String() string {
	return fmt.Sprintf("%s %s on %s %s:%s from %s", b.Perm, b.Operation, b.Type, b.Pattern, b.Name, b.Host)
}

// aclFilter selects ACLs. Zero values match anything.
type aclFilter struct {
	Type      kmsg.ACLResourceType        // Unknown/Any: any type
	Name      *string                     // nil: any name
	Pattern   kmsg.ACLResourcePatternType // Unknown/Any: any pattern
	Principal *string                     // nil: any principal
	Perm      kmsg.ACLPermissionType      // Unknown/Any: any permission
}

// topicInfo is what the plugin needs to know about an existing topic.
type topicInfo struct {
	Partitions int32
}

// admin is the subset of Kafka administration the plugin uses. It is an
// interface so unit tests can run against an in-memory fake.
type admin interface {
	// ListTopics returns every non-internal topic.
	ListTopics(ctx context.Context) (map[string]topicInfo, error)
	// CreateTopic creates a topic; an existing topic is not an error.
	CreateTopic(ctx context.Context, name string, partitions int32, rf int16, configs map[string]string) error
	// SetPartitions raises the partition count of a topic to n.
	SetPartitions(ctx context.Context, name string, n int32) error
	// SetTopicConfigs incrementally sets topic configuration values.
	SetTopicConfigs(ctx context.Context, name string, configs map[string]string) error
	// DeleteTopics deletes topics; missing topics are not an error.
	DeleteTopics(ctx context.Context, names []string) error

	DescribeACLs(ctx context.Context, f aclFilter) ([]aclBinding, error)
	// CreateACLs creates ACLs; creating an existing ACL is a no-op.
	CreateACLs(ctx context.Context, acls []aclBinding) error
	// DeleteACLs deletes exactly the given ACLs.
	DeleteACLs(ctx context.Context, acls []aclBinding) error

	// AlterUserQuotas sets and removes client quotas of a user entity.
	AlterUserQuotas(ctx context.Context, user string, set map[string]float64, remove []string) error

	// SCRAMUserExists reports whether the user has SCRAM credentials.
	SCRAMUserExists(ctx context.Context, user string) (bool, error)
	UpsertSCRAM(ctx context.Context, user string, mech kadm.ScramMechanism, password string, iterations int32) error
	// DeleteSCRAM removes the user's credential; a missing one is not an error.
	DeleteSCRAM(ctx context.Context, user string, mech kadm.ScramMechanism) error

	ListGroups(ctx context.Context) ([]string, error)
	// DeleteGroups deletes consumer groups and returns per-group errors.
	DeleteGroups(ctx context.Context, groups []string) map[string]error

	Ping(ctx context.Context) error
	Close()
}

// kafkaAdmin implements admin with franz-go.
type kafkaAdmin struct {
	cl  *kgo.Client
	adm *kadm.Client
}

func newKafkaAdmin(opts ...kgo.Opt) (*kafkaAdmin, error) {
	cl, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, err
	}
	return &kafkaAdmin{cl: cl, adm: kadm.NewClient(cl)}, nil
}

func (k *kafkaAdmin) Close() { k.cl.Close() }

func (k *kafkaAdmin) Ping(ctx context.Context) error { return k.cl.Ping(ctx) }

func (k *kafkaAdmin) ListTopics(ctx context.Context) (map[string]topicInfo, error) {
	ds, err := k.adm.ListTopics(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]topicInfo, len(ds))
	for name, d := range ds {
		// A topic that is still being created or deleted may report an
		// error (e.g. LEADER_NOT_AVAILABLE); it exists nonetheless.
		out[name] = topicInfo{Partitions: int32(len(d.Partitions))} //nolint:gosec // partition counts are int32 in the Kafka protocol
	}
	return out, nil
}

func (k *kafkaAdmin) CreateTopic(ctx context.Context, name string, partitions int32, rf int16, configs map[string]string) error {
	var cfg map[string]*string
	if len(configs) > 0 {
		cfg = make(map[string]*string, len(configs))
		for key, v := range configs {
			cfg[key] = kadm.StringPtr(v)
		}
	}
	resp, err := k.adm.CreateTopic(ctx, partitions, rf, cfg, name)
	if err == nil {
		err = resp.Err
	}
	if err != nil && !errors.Is(err, kerr.TopicAlreadyExists) {
		return withMessage(err, resp.ErrMessage)
	}
	return nil
}

func (k *kafkaAdmin) SetPartitions(ctx context.Context, name string, n int32) error {
	rs, err := k.adm.UpdatePartitions(ctx, int(n), name)
	if err != nil {
		return err
	}
	r, ok := rs[name]
	if !ok {
		return fmt.Errorf("no create-partitions response for %s", name)
	}
	return withMessage(r.Err, r.ErrMessage)
}

func (k *kafkaAdmin) SetTopicConfigs(ctx context.Context, name string, configs map[string]string) error {
	if len(configs) == 0 {
		return nil
	}
	ops := make([]kadm.AlterConfig, 0, len(configs))
	for key, v := range configs {
		ops = append(ops, kadm.AlterConfig{Op: kadm.SetConfig, Name: key, Value: kadm.StringPtr(v)})
	}
	rs, err := k.adm.AlterTopicConfigs(ctx, ops, name)
	if err != nil {
		return err
	}
	for _, r := range rs {
		if r.Err != nil {
			return withMessage(r.Err, r.ErrMessage)
		}
	}
	return nil
}

func (k *kafkaAdmin) DeleteTopics(ctx context.Context, names []string) error {
	if len(names) == 0 {
		return nil
	}
	rs, err := k.adm.DeleteTopics(ctx, names...)
	if err != nil {
		return err
	}
	var errs []error
	for name, r := range rs {
		if r.Err != nil && !errors.Is(r.Err, kerr.UnknownTopicOrPartition) {
			errs = append(errs, fmt.Errorf("delete topic %s: %w", name, withMessage(r.Err, r.ErrMessage)))
		}
	}
	return errors.Join(errs...)
}

func orAny[T ~int8](v, anyValue T) T {
	if v == 0 {
		return anyValue
	}
	return v
}

func (k *kafkaAdmin) DescribeACLs(ctx context.Context, f aclFilter) ([]aclBinding, error) {
	req := kmsg.NewPtrDescribeACLsRequest()
	req.ResourceType = orAny(f.Type, kmsg.ACLResourceTypeAny)
	req.ResourceName = f.Name
	req.ResourcePatternType = orAny(f.Pattern, kmsg.ACLResourcePatternTypeAny)
	req.Principal = f.Principal
	req.Operation = kmsg.ACLOperationAny
	req.PermissionType = orAny(f.Perm, kmsg.ACLPermissionTypeAny)
	resp, err := req.RequestWith(ctx, k.cl)
	if err != nil {
		return nil, err
	}
	if err := kerr.ErrorForCode(resp.ErrorCode); err != nil {
		return nil, withMessage(err, deref(resp.ErrorMessage))
	}
	var out []aclBinding
	for _, r := range resp.Resources {
		for _, a := range r.ACLs {
			out = append(out, aclBinding{
				Type: r.ResourceType, Name: r.ResourceName, Pattern: r.ResourcePatternType,
				Principal: a.Principal, Host: a.Host, Operation: a.Operation, Perm: a.PermissionType,
			})
		}
	}
	return out, nil
}

func (k *kafkaAdmin) CreateACLs(ctx context.Context, acls []aclBinding) error {
	if len(acls) == 0 {
		return nil
	}
	req := kmsg.NewPtrCreateACLsRequest()
	for _, a := range acls {
		c := kmsg.NewCreateACLsRequestCreation()
		c.ResourceType, c.ResourceName, c.ResourcePatternType = a.Type, a.Name, a.Pattern
		c.Principal, c.Host, c.Operation, c.PermissionType = a.Principal, a.Host, a.Operation, a.Perm
		req.Creations = append(req.Creations, c)
	}
	resp, err := req.RequestWith(ctx, k.cl)
	if err != nil {
		return err
	}
	var errs []error
	for i, r := range resp.Results {
		if err := kerr.ErrorForCode(r.ErrorCode); err != nil {
			errs = append(errs, fmt.Errorf("create ACL %s: %w", acls[i], withMessage(err, deref(r.ErrorMessage))))
		}
	}
	return errors.Join(errs...)
}

func (k *kafkaAdmin) DeleteACLs(ctx context.Context, acls []aclBinding) error {
	if len(acls) == 0 {
		return nil
	}
	req := kmsg.NewPtrDeleteACLsRequest()
	for _, a := range acls {
		f := kmsg.NewDeleteACLsRequestFilter()
		f.ResourceType, f.ResourceName, f.ResourcePatternType = a.Type, kmsg.StringPtr(a.Name), a.Pattern
		f.Principal, f.Host = kmsg.StringPtr(a.Principal), kmsg.StringPtr(a.Host)
		f.Operation, f.PermissionType = a.Operation, a.Perm
		req.Filters = append(req.Filters, f)
	}
	resp, err := req.RequestWith(ctx, k.cl)
	if err != nil {
		return err
	}
	var errs []error
	for i, r := range resp.Results {
		if err := kerr.ErrorForCode(r.ErrorCode); err != nil {
			errs = append(errs, fmt.Errorf("delete ACL %s: %w", acls[i], withMessage(err, deref(r.ErrorMessage))))
		}
	}
	return errors.Join(errs...)
}

func (k *kafkaAdmin) AlterUserQuotas(ctx context.Context, user string, set map[string]float64, remove []string) error {
	var ops []kadm.AlterClientQuotaOp
	for key, v := range set {
		ops = append(ops, kadm.AlterClientQuotaOp{Key: key, Value: v})
	}
	for _, key := range remove {
		ops = append(ops, kadm.AlterClientQuotaOp{Key: key, Remove: true})
	}
	if len(ops) == 0 {
		return nil
	}
	rs, err := k.adm.AlterClientQuotas(ctx, []kadm.AlterClientQuotaEntry{{
		Entity: kadm.ClientQuotaEntity{{Type: "user", Name: kadm.StringPtr(user)}},
		Ops:    ops,
	}})
	if err != nil {
		return err
	}
	for _, r := range rs {
		if r.Err != nil {
			return withMessage(r.Err, r.ErrMessage)
		}
	}
	return nil
}

func (k *kafkaAdmin) SCRAMUserExists(ctx context.Context, user string) (bool, error) {
	rs, err := k.adm.DescribeUserSCRAMs(ctx, user)
	if err != nil {
		return false, err
	}
	r, ok := rs[user]
	if !ok || errors.Is(r.Err, kerr.ResourceNotFound) {
		return false, nil
	}
	if r.Err != nil {
		return false, withMessage(r.Err, r.ErrMessage)
	}
	return len(r.CredInfos) > 0, nil
}

func (k *kafkaAdmin) UpsertSCRAM(ctx context.Context, user string, mech kadm.ScramMechanism, password string, iterations int32) error {
	rs, err := k.adm.AlterUserSCRAMs(ctx, nil, []kadm.UpsertSCRAM{{
		User: user, Mechanism: mech, Iterations: iterations, Password: password,
	}})
	if err != nil {
		return err
	}
	if r, ok := rs[user]; ok && r.Err != nil {
		return withMessage(r.Err, r.ErrMessage)
	}
	return nil
}

func (k *kafkaAdmin) DeleteSCRAM(ctx context.Context, user string, mech kadm.ScramMechanism) error {
	rs, err := k.adm.AlterUserSCRAMs(ctx, []kadm.DeleteSCRAM{{User: user, Mechanism: mech}}, nil)
	if err != nil {
		return err
	}
	if r, ok := rs[user]; ok && r.Err != nil && !errors.Is(r.Err, kerr.ResourceNotFound) {
		return withMessage(r.Err, r.ErrMessage)
	}
	return nil
}

func (k *kafkaAdmin) ListGroups(ctx context.Context) ([]string, error) {
	gs, err := k.adm.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	return gs.Groups(), nil
}

func (k *kafkaAdmin) DeleteGroups(ctx context.Context, groups []string) map[string]error {
	out := map[string]error{}
	if len(groups) == 0 {
		return out
	}
	rs, err := k.adm.DeleteGroups(ctx, groups...)
	if err != nil {
		for _, g := range groups {
			out[g] = err
		}
		return out
	}
	for g, r := range rs {
		if r.Err != nil && !errors.Is(r.Err, kerr.GroupIDNotFound) {
			out[g] = r.Err
		}
	}
	return out
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// withMessage appends a broker error message to err.
func withMessage(err error, msg string) error {
	if err == nil {
		return nil
	}
	if msg = strings.TrimSpace(msg); msg != "" && !strings.Contains(err.Error(), msg) {
		return fmt.Errorf("%w: %s", err, msg)
	}
	return err
}
