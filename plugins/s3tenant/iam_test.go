package s3tenant

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// fakeIAM is an in-memory iamAPI.
type fakeIAM struct {
	mu       sync.Mutex
	users    map[string]*fakeUser
	keySeq   int
	maxKeys  int
	calls    []string
	failList error
}

type fakeUser struct {
	user     types.User
	policies map[string]string
	attached []string
	groups   []string
	keys     []string
	login    bool
}

func newFakeIAM() *fakeIAM { return &fakeIAM{users: map[string]*fakeUser{}, maxKeys: 2} }

func noEntity(name string) error {
	return &types.NoSuchEntityException{Message: aws.String("The user with name " + name + " cannot be found.")}
}

func (f *fakeIAM) call(op string) { f.calls = append(f.calls, op) }

func (f *fakeIAM) get(name *string) (*fakeUser, error) {
	u, ok := f.users[aws.ToString(name)]
	if !ok {
		return nil, noEntity(aws.ToString(name))
	}
	return u, nil
}

func (f *fakeIAM) GetUser(_ context.Context, in *iam.GetUserInput, _ ...func(*iam.Options)) (*iam.GetUserOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, err := f.get(in.UserName)
	if err != nil {
		return nil, err
	}
	cp := u.user
	return &iam.GetUserOutput{User: &cp}, nil
}

func (f *fakeIAM) CreateUser(_ context.Context, in *iam.CreateUserInput, _ ...func(*iam.Options)) (*iam.CreateUserOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call("CreateUser")
	name := aws.ToString(in.UserName)
	if _, ok := f.users[name]; ok {
		return nil, &types.EntityAlreadyExistsException{Message: aws.String("exists")}
	}
	u := &fakeUser{policies: map[string]string{}, user: types.User{
		UserName: in.UserName, Path: in.Path, Tags: in.Tags,
		Arn: aws.String("arn:aws:iam::000000000000:user" + aws.ToString(in.Path) + name),
	}}
	if in.PermissionsBoundary != nil {
		u.user.PermissionsBoundary = &types.AttachedPermissionsBoundary{PermissionsBoundaryArn: in.PermissionsBoundary}
	}
	f.users[name] = u
	cp := u.user
	return &iam.CreateUserOutput{User: &cp}, nil
}

func (f *fakeIAM) TagUser(_ context.Context, in *iam.TagUserInput, _ ...func(*iam.Options)) (*iam.TagUserOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call("TagUser")
	u, err := f.get(in.UserName)
	if err != nil {
		return nil, err
	}
	u.user.Tags = append(u.user.Tags, in.Tags...)
	return &iam.TagUserOutput{}, nil
}

func (f *fakeIAM) DeleteUser(_ context.Context, in *iam.DeleteUserInput, _ ...func(*iam.Options)) (*iam.DeleteUserOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call("DeleteUser")
	u, err := f.get(in.UserName)
	if err != nil {
		return nil, err
	}
	if len(u.policies) > 0 || len(u.attached) > 0 || len(u.groups) > 0 || len(u.keys) > 0 || u.login {
		return nil, &types.DeleteConflictException{Message: aws.String("must delete dependents first")}
	}
	delete(f.users, aws.ToString(in.UserName))
	return &iam.DeleteUserOutput{}, nil
}

func (f *fakeIAM) ListUsers(context.Context, *iam.ListUsersInput, ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
	return &iam.ListUsersOutput{}, f.failList
}

func (f *fakeIAM) PutUserPolicy(_ context.Context, in *iam.PutUserPolicyInput, _ ...func(*iam.Options)) (*iam.PutUserPolicyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call("PutUserPolicy")
	u, err := f.get(in.UserName)
	if err != nil {
		return nil, err
	}
	u.policies[aws.ToString(in.PolicyName)] = aws.ToString(in.PolicyDocument)
	return &iam.PutUserPolicyOutput{}, nil
}

func (f *fakeIAM) ListUserPolicies(_ context.Context, in *iam.ListUserPoliciesInput, _ ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, err := f.get(in.UserName)
	if err != nil {
		return nil, err
	}
	out := &iam.ListUserPoliciesOutput{}
	for n := range u.policies {
		out.PolicyNames = append(out.PolicyNames, n)
	}
	return out, nil
}

func (f *fakeIAM) DeleteUserPolicy(_ context.Context, in *iam.DeleteUserPolicyInput, _ ...func(*iam.Options)) (*iam.DeleteUserPolicyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, err := f.get(in.UserName)
	if err != nil {
		return nil, err
	}
	delete(u.policies, aws.ToString(in.PolicyName))
	return &iam.DeleteUserPolicyOutput{}, nil
}

func (f *fakeIAM) ListAttachedUserPolicies(_ context.Context, in *iam.ListAttachedUserPoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, err := f.get(in.UserName)
	if err != nil {
		return nil, err
	}
	out := &iam.ListAttachedUserPoliciesOutput{}
	for _, a := range u.attached {
		out.AttachedPolicies = append(out.AttachedPolicies, types.AttachedPolicy{PolicyArn: aws.String(a)})
	}
	return out, nil
}

func (f *fakeIAM) DetachUserPolicy(_ context.Context, in *iam.DetachUserPolicyInput, _ ...func(*iam.Options)) (*iam.DetachUserPolicyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, err := f.get(in.UserName)
	if err != nil {
		return nil, err
	}
	u.attached = remove(u.attached, aws.ToString(in.PolicyArn))
	return &iam.DetachUserPolicyOutput{}, nil
}

func (f *fakeIAM) ListGroupsForUser(_ context.Context, in *iam.ListGroupsForUserInput, _ ...func(*iam.Options)) (*iam.ListGroupsForUserOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, err := f.get(in.UserName)
	if err != nil {
		return nil, err
	}
	out := &iam.ListGroupsForUserOutput{}
	for _, g := range u.groups {
		out.Groups = append(out.Groups, types.Group{GroupName: aws.String(g)})
	}
	return out, nil
}

func (f *fakeIAM) RemoveUserFromGroup(_ context.Context, in *iam.RemoveUserFromGroupInput, _ ...func(*iam.Options)) (*iam.RemoveUserFromGroupOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, err := f.get(in.UserName)
	if err != nil {
		return nil, err
	}
	u.groups = remove(u.groups, aws.ToString(in.GroupName))
	return &iam.RemoveUserFromGroupOutput{}, nil
}

func (f *fakeIAM) ListAccessKeys(_ context.Context, in *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, err := f.get(in.UserName)
	if err != nil {
		return nil, err
	}
	out := &iam.ListAccessKeysOutput{}
	for _, k := range u.keys {
		out.AccessKeyMetadata = append(out.AccessKeyMetadata, types.AccessKeyMetadata{
			AccessKeyId: aws.String(k), UserName: in.UserName, Status: types.StatusTypeActive,
		})
	}
	return out, nil
}

func (f *fakeIAM) CreateAccessKey(_ context.Context, in *iam.CreateAccessKeyInput, _ ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call("CreateAccessKey")
	u, err := f.get(in.UserName)
	if err != nil {
		return nil, err
	}
	if len(u.keys) >= f.maxKeys {
		return nil, &types.LimitExceededException{Message: aws.String("too many keys")}
	}
	f.keySeq++
	id := fmt.Sprintf("AKIATEST%04d", f.keySeq)
	u.keys = append(u.keys, id)
	return &iam.CreateAccessKeyOutput{AccessKey: &types.AccessKey{
		AccessKeyId: aws.String(id), SecretAccessKey: aws.String("secret-" + id),
		UserName: in.UserName, Status: types.StatusTypeActive, CreateDate: aws.Time(time.Unix(1700000000, 0).UTC()),
	}}, nil
}

func (f *fakeIAM) DeleteAccessKey(_ context.Context, in *iam.DeleteAccessKeyInput, _ ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, err := f.get(in.UserName)
	if err != nil {
		return nil, err
	}
	id := aws.ToString(in.AccessKeyId)
	if !contains(u.keys, id) {
		return nil, noEntity(id)
	}
	u.keys = remove(u.keys, id)
	return &iam.DeleteAccessKeyOutput{}, nil
}

func (f *fakeIAM) DeleteLoginProfile(_ context.Context, in *iam.DeleteLoginProfileInput, _ ...func(*iam.Options)) (*iam.DeleteLoginProfileOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, err := f.get(in.UserName)
	if err != nil {
		return nil, err
	}
	if !u.login {
		return nil, noEntity("login profile")
	}
	u.login = false
	return &iam.DeleteLoginProfileOutput{}, nil
}

func (f *fakeIAM) ListSigningCertificates(context.Context, *iam.ListSigningCertificatesInput, ...func(*iam.Options)) (*iam.ListSigningCertificatesOutput, error) {
	return &iam.ListSigningCertificatesOutput{}, nil
}

func (f *fakeIAM) DeleteSigningCertificate(context.Context, *iam.DeleteSigningCertificateInput, ...func(*iam.Options)) (*iam.DeleteSigningCertificateOutput, error) {
	return &iam.DeleteSigningCertificateOutput{}, nil
}

func (f *fakeIAM) ListSSHPublicKeys(context.Context, *iam.ListSSHPublicKeysInput, ...func(*iam.Options)) (*iam.ListSSHPublicKeysOutput, error) {
	return &iam.ListSSHPublicKeysOutput{}, nil
}

func (f *fakeIAM) DeleteSSHPublicKey(context.Context, *iam.DeleteSSHPublicKeyInput, ...func(*iam.Options)) (*iam.DeleteSSHPublicKeyOutput, error) {
	return &iam.DeleteSSHPublicKeyOutput{}, nil
}

func (f *fakeIAM) ListServiceSpecificCredentials(context.Context, *iam.ListServiceSpecificCredentialsInput, ...func(*iam.Options)) (*iam.ListServiceSpecificCredentialsOutput, error) {
	return &iam.ListServiceSpecificCredentialsOutput{}, nil
}

func (f *fakeIAM) DeleteServiceSpecificCredential(context.Context, *iam.DeleteServiceSpecificCredentialInput, ...func(*iam.Options)) (*iam.DeleteServiceSpecificCredentialOutput, error) {
	return &iam.DeleteServiceSpecificCredentialOutput{}, nil
}

func (f *fakeIAM) ListMFADevices(context.Context, *iam.ListMFADevicesInput, ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error) {
	return &iam.ListMFADevicesOutput{}, nil
}

func (f *fakeIAM) DeactivateMFADevice(context.Context, *iam.DeactivateMFADeviceInput, ...func(*iam.Options)) (*iam.DeactivateMFADeviceOutput, error) {
	return &iam.DeactivateMFADeviceOutput{}, nil
}

func remove(s []string, v string) []string {
	out := s[:0]
	for _, x := range s {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// newIAMPlugin initializes the plugin with IAM enabled and swaps in a fake
// IAM client. No S3 call is made by the IAM code paths.
func newIAMPlugin(t *testing.T, cfg map[string]any) (*Plugin, *sdktest.Registrar, *fakeIAM) {
	t.Helper()
	full := map[string]any{
		"endpoint": "localhost:9", "access_key": "ak", "secret_key": "sk", "secure": false,
		"iam": map[string]any{"enabled": true},
	}
	for k, v := range cfg {
		full[k] = v
	}
	reg := sdktest.NewRegistrar(full)
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	f := newFakeIAM()
	p.iam = f
	p.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	return p, reg, f
}

func TestIAMConfigValidation(t *testing.T) {
	base := Config{Endpoint: "s3.amazonaws.com", AccessKey: "ak", SecretKey: "sk"}
	for _, tc := range []struct {
		iam     IAMConfig
		mode    string
		wantErr string
	}{
		{IAMConfig{}, "", ""},
		{IAMConfig{Enabled: true}, "", ""},
		{IAMConfig{Enabled: true}, ModePrefix, ""},
		{IAMConfig{Enabled: true, Endpoint: "localhost:4566"}, "", "iam.endpoint"},
		{IAMConfig{Enabled: true, Endpoint: "http://localhost:4566"}, "", ""},
		{IAMConfig{Enabled: true, AccessKey: "x"}, "", "set together"},
		{IAMConfig{Enabled: true, Path: "tenarium"}, "", "iam.path"},
		{IAMConfig{Enabled: true, Path: "/a b/"}, "", "invalid character"},
		{IAMConfig{Enabled: true, Path: "/"}, "", ""},
		{IAMConfig{Enabled: true, UserTemplate: "static"}, "", "must depend on the tenant"},
		{IAMConfig{Enabled: true, UserTemplate: "{{.Nope}}"}, "", "iam.user_template"},
		{IAMConfig{Enabled: true, UserTemplate: "s3-{{.Tenant.Slug}}"}, "", ""},
		{IAMConfig{Enabled: true, PolicyTemplate: `{"Version": `}, "", "invalid JSON"},
		{IAMConfig{Enabled: true, PolicyTemplate: `{"Resource": "arn:{{.Partition}}:s3:::{{.Bucket}}", "U": "{{.User}}"}`}, "", ""},
	} {
		c := base
		c.IAM = tc.iam
		if tc.mode == ModePrefix {
			c.Mode, c.Bucket = ModePrefix, "shared"
		}
		p := &Plugin{cfg: c}
		err := p.validate()
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("%+v: unexpected error %v", tc.iam, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%+v: error %v, want containing %q", tc.iam, err, tc.wantErr)
		}
	}

	p := &Plugin{cfg: base}
	p.cfg.IAM.Enabled = true
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	c := p.cfg.IAM
	if c.Path != DefaultIAMPath || c.Region != DefaultIAMRegion || c.Partition != "aws" ||
		c.AccessKey != "ak" || c.SecretKey != "sk" || c.UserTemplate != DefaultIAMUserTemplate {
		t.Fatalf("defaults not applied: %+v", c)
	}

	s, err := schema.Compile((&Plugin{}).Manifest().ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	ok := map[string]any{"endpoint": "x", "access_key": "a", "secret_key": "b",
		"iam": map[string]any{"enabled": true, "path": "/t/", "policy_template": "{}"}}
	if err := s.Validate(ok); err != nil {
		t.Fatal(err)
	}
	bad := map[string]any{"endpoint": "x", "access_key": "a", "secret_key": "b", "iam": map[string]any{"enable": true}}
	if err := s.Validate(bad); err == nil {
		t.Fatal("expected schema error for unknown iam key")
	}
}

func TestIAMUserNames(t *testing.T) {
	p := &Plugin{cfg: Config{Endpoint: "x", AccessKey: "a", SecretKey: "b", IAM: IAMConfig{
		Enabled: true, UserTemplate: "tenant user/{{.Tenant.Slug}}-{{.Tenant.Name}}",
	}}}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("x", 80)
	a := sdk.Tenant{ID: "a", Slug: "acme", Name: long}
	b := sdk.Tenant{ID: "b", Slug: "acme", Name: long}
	na, err := p.iamUserName(a, target{Bucket: "tenant-acme"})
	if err != nil {
		t.Fatal(err)
	}
	nb, _ := p.iamUserName(b, target{Bucket: "tenant-acme"})
	if na == nb || len(na) > maxIAMUserNameLen || !strings.HasPrefix(na, "tenant-user-acme-xxx") {
		t.Fatalf("names %q %q", na, nb)
	}
}

func TestDefaultIAMPolicy(t *testing.T) {
	var doc policyDoc
	p := &Plugin{}
	s, err := p.renderIAMPolicy(iamPolicyData{Bucket: "tenant-acme", Partition: "aws"})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(s), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Statement) != 2 || doc.Statement[0].Resource[0] != "arn:aws:s3:::tenant-acme" ||
		doc.Statement[1].Resource[0] != "arn:aws:s3:::tenant-acme/*" {
		t.Fatalf("bucket policy %s", s)
	}
	for _, st := range doc.Statement {
		for _, a := range st.Action {
			if strings.Contains(a, "Tagging") && st.Sid == "TenantBucket" || a == "s3:*" || strings.Contains(a, "Policy") {
				t.Fatalf("policy grants %s", a)
			}
		}
	}

	s, err = p.renderIAMPolicy(iamPolicyData{Bucket: "shared", Prefix: "tenant-acme/", Partition: "aws-cn"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"s3:prefix":["tenant-acme/","tenant-acme/*"]`,
		`"arn:aws-cn:s3:::shared/tenant-acme/*"`,
		`"Effect":"Deny"`,
		`"arn:aws-cn:s3:::shared/tenant-acme/.tenarium-owner"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("prefix policy %s lacks %s", s, want)
		}
	}
}

func TestIAMProvisionDeprovision(t *testing.T) {
	ctx := context.Background()
	p, reg, f := newIAMPlugin(t, map[string]any{
		"iam": map[string]any{"enabled": true, "permissions_boundary": "arn:aws:iam::1:policy/boundary"},
	})
	acme := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Name: "Acme"})
	tg, _ := p.target(acme)

	for range 2 { // idempotent
		if err := p.provisionIAM(ctx, acme, tg); err != nil {
			t.Fatal(err)
		}
	}
	u := f.users["tenant-acme"]
	if u == nil || aws.ToString(u.user.Path) != "/tenarium/" || userOwner(&u.user) != acme.ID ||
		u.user.PermissionsBoundary == nil {
		t.Fatalf("user %+v", u)
	}
	if !strings.Contains(u.policies[IAMPolicyName], "arn:aws:s3:::tenant-acme/*") {
		t.Fatalf("policy %v", u.policies)
	}
	if len(u.keys) != 0 {
		t.Fatal("provision must not create access keys")
	}

	// Another tenant whose name renders the same user is refused, and its
	// deprovision leaves the user alone.
	other := sdk.Tenant{ID: "other-id", Slug: "acme"}
	if err := p.provisionIAM(ctx, other, tg); err == nil || !strings.Contains(err.Error(), "belongs to another tenant") {
		t.Fatalf("conflict error %v", err)
	}
	if err := p.deprovisionIAM(ctx, other, tg); err != nil {
		t.Fatal(err)
	}
	if f.users["tenant-acme"] == nil {
		t.Fatal("deleted another tenant's user")
	}

	// Deprovision removes keys, policies, groups and the login profile.
	u.keys = []string{"AKIA1", "AKIA2"}
	u.attached = []string{"arn:aws:iam::aws:policy/ReadOnlyAccess"}
	u.groups = []string{"devs"}
	u.login = true
	for range 2 {
		if err := p.deprovisionIAM(ctx, acme, tg); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.users) != 0 {
		t.Fatalf("users left: %v", f.users)
	}
}

func TestIAMAdoptUnmarked(t *testing.T) {
	ctx := context.Background()
	p, reg, f := newIAMPlugin(t, nil)
	acme := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	tg, _ := p.target(acme)

	// An empty, untagged user is adopted.
	_, _ = f.CreateUser(ctx, &iam.CreateUserInput{UserName: aws.String("tenant-acme"), Path: aws.String("/")})
	if err := p.provisionIAM(ctx, acme, tg); err != nil {
		t.Fatal(err)
	}
	if userOwner(&f.users["tenant-acme"].user) != acme.ID {
		t.Fatal("not tagged")
	}

	// An untagged user with keys is not.
	beta := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "beta"})
	btg, _ := p.target(beta)
	_, _ = f.CreateUser(ctx, &iam.CreateUserInput{UserName: aws.String("tenant-beta")})
	f.users["tenant-beta"].keys = []string{"AKIAX"}
	if err := p.provisionIAM(ctx, beta, btg); err == nil || !strings.Contains(err.Error(), "not managed by tenarium") {
		t.Fatalf("error %v", err)
	}
	// ... and never deleted.
	if err := p.deprovisionIAM(ctx, beta, btg); err != nil {
		t.Fatal(err)
	}
	if f.users["tenant-beta"] == nil {
		t.Fatal("deleted an unmanaged user")
	}
}

func TestAccessKeyRoutes(t *testing.T) {
	ctx := context.Background()
	p, reg, f := newIAMPlugin(t, map[string]any{"mode": "prefix", "bucket": "shared", "region": "eu-west-1"})
	acme := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	other := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "other"})
	for _, r := range []string{"POST /tenants/{tenant}/access-keys", "GET /tenants/{tenant}/access-keys", "DELETE /tenants/{tenant}/access-keys/{key}"} {
		if !contains(reg.Routes, r) {
			t.Fatalf("route %s not registered: %v", r, reg.Routes)
		}
	}
	// Tenant-scoped principals may read but not update.
	reg.HostImpl.AuthorizeFunc = func(_ context.Context, pr *sdk.Principal, action sdk.Action, res sdk.Resource) error {
		if pr.TenantID == "" {
			return nil
		}
		if pr.TenantID == res.TenantID && action == sdk.ActionTenantsRead {
			return nil
		}
		return sdk.ErrForbidden
	}
	do := func(method, path string, pr *sdk.Principal) (*http.Response, string) {
		req := httptest.NewRequest(method, path, nil)
		req = req.WithContext(sdk.WithPrincipal(req.Context(), pr))
		rec := httptest.NewRecorder()
		reg.Mux.ServeHTTP(rec, req)
		body, _ := io.ReadAll(rec.Result().Body)
		return rec.Result(), string(body)
	}
	admin := &sdk.Principal{Subject: "admin"}

	// Not provisioned yet.
	if resp, _ := do("POST", "/tenants/acme/access-keys", admin); resp.StatusCode != http.StatusConflict {
		t.Fatalf("unprovisioned status %d", resp.StatusCode)
	}
	tg, _ := p.target(acme)
	if err := p.provisionIAM(ctx, acme, tg); err != nil {
		t.Fatal(err)
	}

	if resp, _ := do("POST", "/tenants/acme/access-keys", &sdk.Principal{Subject: "u", TenantID: acme.ID}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("tenant member status %d", resp.StatusCode)
	}
	if resp, _ := do("POST", "/tenants/acme/access-keys", &sdk.Principal{Subject: "u", TenantID: other.ID}); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("other tenant status %d", resp.StatusCode)
	}
	if resp, _ := do("POST", "/tenants/missing/access-keys", admin); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("missing status %d", resp.StatusCode)
	}

	resp, body := do("POST", "/tenants/acme/access-keys", admin)
	if resp.StatusCode != http.StatusCreated || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("create status %d: %s", resp.StatusCode, body)
	}
	var key AccessKey
	if err := json.Unmarshal([]byte(body), &key); err != nil {
		t.Fatal(err)
	}
	if key.User != "tenant-acme" || key.SecretAccessKey == "" || key.Bucket != "shared" ||
		key.Prefix != "tenant-acme/" || key.Region != "eu-west-1" {
		t.Fatalf("key %+v", key)
	}
	_, _ = do("POST", "/tenants/acme/access-keys", admin)
	if resp, _ := do("POST", "/tenants/acme/access-keys", admin); resp.StatusCode != http.StatusConflict {
		t.Fatalf("over limit status %d", resp.StatusCode)
	}

	resp, body = do("GET", "/tenants/acme/access-keys", admin)
	if resp.StatusCode != http.StatusOK || strings.Contains(body, "secret") || strings.Count(body, "AKIATEST") != 2 {
		t.Fatalf("list %d: %s", resp.StatusCode, body)
	}
	if resp, _ := do("DELETE", "/tenants/acme/access-keys/"+key.AccessKeyID, admin); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status %d", resp.StatusCode)
	}
	if resp, _ := do("DELETE", "/tenants/acme/access-keys/"+key.AccessKeyID, admin); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("second delete status %d", resp.StatusCode)
	}

	// The tenant route reports the user.
	resp, body = do("GET", "/tenants/acme", admin)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"iam_user":"tenant-acme"`) {
		t.Fatalf("info %d: %s", resp.StatusCode, body)
	}
	if !contains(f.calls, "CreateAccessKey") {
		t.Fatal("no key created")
	}
}

func TestIAMHealth(t *testing.T) {
	p, _, f := newIAMPlugin(t, nil)
	f.failList = fmt.Errorf("denied")
	if err := p.Health(context.Background()); err == nil || !strings.Contains(err.Error(), "iam") {
		t.Fatalf("health %v", err)
	}
}
