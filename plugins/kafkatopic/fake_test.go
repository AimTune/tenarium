package kafkatopic

import (
	"context"
	"errors"
	"slices"
	"sync"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kmsg"
)

type fakeTopic struct {
	Partitions int32
	RF         int16
	Configs    map[string]string
}

// fakeAdmin is an in-memory admin.
type fakeAdmin struct {
	mu      sync.Mutex
	topics  map[string]*fakeTopic
	acls    []aclBinding
	quotas  map[string]map[string]float64
	scram   map[string]string // user -> password
	groups  []string
	pingErr error
	calls   []string
}

func newFakeAdmin() *fakeAdmin {
	return &fakeAdmin{
		topics: map[string]*fakeTopic{},
		quotas: map[string]map[string]float64{},
		scram:  map[string]string{},
	}
}

var _ admin = (*fakeAdmin)(nil)

func (f *fakeAdmin) record(s string) { f.calls = append(f.calls, s) }

func (f *fakeAdmin) ListTopics(context.Context) (map[string]topicInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]topicInfo{}
	for n, t := range f.topics {
		out[n] = topicInfo{Partitions: t.Partitions}
	}
	return out, nil
}

func (f *fakeAdmin) CreateTopic(_ context.Context, name string, partitions int32, rf int16, configs map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("create-topic " + name)
	if _, ok := f.topics[name]; ok {
		return nil
	}
	if partitions == -1 {
		partitions = 1 // broker default
	}
	f.topics[name] = &fakeTopic{Partitions: partitions, RF: rf, Configs: configs}
	return nil
}

func (f *fakeAdmin) SetPartitions(_ context.Context, name string, n int32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.topics[name]
	if !ok {
		return errors.New("unknown topic")
	}
	if n < t.Partitions {
		return errors.New("cannot reduce partitions")
	}
	t.Partitions = n
	return nil
}

func (f *fakeAdmin) SetTopicConfigs(_ context.Context, name string, configs map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.topics[name]
	if !ok {
		return errors.New("unknown topic")
	}
	if t.Configs == nil {
		t.Configs = map[string]string{}
	}
	for k, v := range configs {
		t.Configs[k] = v
	}
	return nil
}

func (f *fakeAdmin) DeleteTopics(_ context.Context, names []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, n := range names {
		f.record("delete-topic " + n)
		delete(f.topics, n)
	}
	return nil
}

func (f *fakeAdmin) DescribeACLs(_ context.Context, flt aclFilter) ([]aclBinding, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []aclBinding
	for _, a := range f.acls {
		if flt.Type != 0 && flt.Type != kmsg.ACLResourceTypeAny && flt.Type != a.Type {
			continue
		}
		if flt.Name != nil && *flt.Name != a.Name {
			continue
		}
		if flt.Pattern != 0 && flt.Pattern != kmsg.ACLResourcePatternTypeAny && flt.Pattern != a.Pattern {
			continue
		}
		if flt.Principal != nil && *flt.Principal != a.Principal {
			continue
		}
		if flt.Perm != 0 && flt.Perm != kmsg.ACLPermissionTypeAny && flt.Perm != a.Perm {
			continue
		}
		out = append(out, a)
	}
	return out, nil
}

func (f *fakeAdmin) CreateACLs(_ context.Context, acls []aclBinding) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range acls {
		if !slices.Contains(f.acls, a) {
			f.acls = append(f.acls, a)
		}
	}
	return nil
}

func (f *fakeAdmin) DeleteACLs(_ context.Context, acls []aclBinding) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acls = slices.DeleteFunc(f.acls, func(a aclBinding) bool { return slices.Contains(acls, a) })
	return nil
}

func (f *fakeAdmin) AlterUserQuotas(_ context.Context, user string, set map[string]float64, remove []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	q := f.quotas[user]
	if q == nil {
		q = map[string]float64{}
		f.quotas[user] = q
	}
	for k, v := range set {
		q[k] = v
	}
	for _, k := range remove {
		delete(q, k)
	}
	if len(q) == 0 {
		delete(f.quotas, user)
	}
	return nil
}

func (f *fakeAdmin) SCRAMUserExists(_ context.Context, user string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.scram[user]
	return ok, nil
}

func (f *fakeAdmin) UpsertSCRAM(_ context.Context, user string, _ kadm.ScramMechanism, password string, _ int32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scram[user] = password
	return nil
}

func (f *fakeAdmin) DeleteSCRAM(_ context.Context, user string, _ kadm.ScramMechanism) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.scram, user)
	return nil
}

func (f *fakeAdmin) ListGroups(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.groups), nil
}

func (f *fakeAdmin) DeleteGroups(_ context.Context, groups []string) map[string]error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.groups = slices.DeleteFunc(f.groups, func(g string) bool { return slices.Contains(groups, g) })
	return nil
}

func (f *fakeAdmin) Ping(context.Context) error { return f.pingErr }
func (f *fakeAdmin) Close()                     {}

// aclsOf returns the ACLs of principal.
func (f *fakeAdmin) aclsOf(principal string) []aclBinding {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []aclBinding
	for _, a := range f.acls {
		if a.Principal == principal {
			out = append(out, a)
		}
	}
	return out
}
