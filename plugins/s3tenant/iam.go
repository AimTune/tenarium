package s3tenant

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"text/template"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// IAM defaults.
const (
	DefaultIAMPath         = "/tenarium/"
	DefaultIAMUserTemplate = "{{.Name}}"
	DefaultIAMRegion       = "us-east-1"
	DefaultIAMPartition    = "aws"

	// IAMPolicyName is the inline policy the plugin manages on each user.
	IAMPolicyName = "tenarium-s3"

	maxIAMUserNameLen = 64
	maxIAMPathLen     = 512
)

// IAMConfig enables a per-tenant IAM user whose inline policy grants access
// to the tenant's bucket or prefix only.
type IAMConfig struct {
	Enabled bool `json:"enabled"`
	// Endpoint overrides the IAM endpoint (a URL with scheme), e.g. for
	// LocalStack. Empty uses AWS.
	Endpoint string `json:"endpoint"`
	// Region signs IAM requests (default us-east-1; IAM is global).
	Region string `json:"region"`
	// AccessKey and SecretKey default to the top-level credentials.
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
	// Partition is the ARN partition of the default policy (default aws).
	Partition string `json:"partition"`
	// Path is the IAM path of tenant users (default /tenarium/).
	Path string `json:"path"`
	// UserTemplate renders the user name over {Tenant, Name} (default
	// "{{.Name}}", the bucket or prefix name).
	UserTemplate string `json:"user_template"`
	// PolicyTemplate renders the inline policy over {Tenant, Bucket,
	// Prefix, Partition, User}. Empty uses a policy restricted to the
	// tenant's bucket or prefix.
	PolicyTemplate string `json:"policy_template"`
	// PermissionsBoundary is an optional managed policy ARN set as the
	// permissions boundary of created users.
	PermissionsBoundary string `json:"permissions_boundary"`
}

// iamAPI is the subset of the IAM client the plugin uses.
type iamAPI interface {
	GetUser(context.Context, *iam.GetUserInput, ...func(*iam.Options)) (*iam.GetUserOutput, error)
	CreateUser(context.Context, *iam.CreateUserInput, ...func(*iam.Options)) (*iam.CreateUserOutput, error)
	TagUser(context.Context, *iam.TagUserInput, ...func(*iam.Options)) (*iam.TagUserOutput, error)
	DeleteUser(context.Context, *iam.DeleteUserInput, ...func(*iam.Options)) (*iam.DeleteUserOutput, error)
	ListUsers(context.Context, *iam.ListUsersInput, ...func(*iam.Options)) (*iam.ListUsersOutput, error)
	PutUserPolicy(context.Context, *iam.PutUserPolicyInput, ...func(*iam.Options)) (*iam.PutUserPolicyOutput, error)
	ListUserPolicies(context.Context, *iam.ListUserPoliciesInput, ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error)
	DeleteUserPolicy(context.Context, *iam.DeleteUserPolicyInput, ...func(*iam.Options)) (*iam.DeleteUserPolicyOutput, error)
	ListAttachedUserPolicies(context.Context, *iam.ListAttachedUserPoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error)
	DetachUserPolicy(context.Context, *iam.DetachUserPolicyInput, ...func(*iam.Options)) (*iam.DetachUserPolicyOutput, error)
	ListGroupsForUser(context.Context, *iam.ListGroupsForUserInput, ...func(*iam.Options)) (*iam.ListGroupsForUserOutput, error)
	RemoveUserFromGroup(context.Context, *iam.RemoveUserFromGroupInput, ...func(*iam.Options)) (*iam.RemoveUserFromGroupOutput, error)
	ListAccessKeys(context.Context, *iam.ListAccessKeysInput, ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	CreateAccessKey(context.Context, *iam.CreateAccessKeyInput, ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error)
	DeleteAccessKey(context.Context, *iam.DeleteAccessKeyInput, ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error)
	DeleteLoginProfile(context.Context, *iam.DeleteLoginProfileInput, ...func(*iam.Options)) (*iam.DeleteLoginProfileOutput, error)
	ListSigningCertificates(context.Context, *iam.ListSigningCertificatesInput, ...func(*iam.Options)) (*iam.ListSigningCertificatesOutput, error)
	DeleteSigningCertificate(context.Context, *iam.DeleteSigningCertificateInput, ...func(*iam.Options)) (*iam.DeleteSigningCertificateOutput, error)
	ListSSHPublicKeys(context.Context, *iam.ListSSHPublicKeysInput, ...func(*iam.Options)) (*iam.ListSSHPublicKeysOutput, error)
	DeleteSSHPublicKey(context.Context, *iam.DeleteSSHPublicKeyInput, ...func(*iam.Options)) (*iam.DeleteSSHPublicKeyOutput, error)
	ListServiceSpecificCredentials(context.Context, *iam.ListServiceSpecificCredentialsInput, ...func(*iam.Options)) (*iam.ListServiceSpecificCredentialsOutput, error)
	DeleteServiceSpecificCredential(context.Context, *iam.DeleteServiceSpecificCredentialInput, ...func(*iam.Options)) (*iam.DeleteServiceSpecificCredentialOutput, error)
	ListMFADevices(context.Context, *iam.ListMFADevicesInput, ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error)
	DeactivateMFADevice(context.Context, *iam.DeactivateMFADeviceInput, ...func(*iam.Options)) (*iam.DeactivateMFADeviceOutput, error)
}

var _ iamAPI = (*iam.Client)(nil)

// validateIAM checks and defaults the iam block and compiles its templates.
func (p *Plugin) validateIAM() error {
	c := &p.cfg.IAM
	if !c.Enabled {
		return nil
	}
	if c.Endpoint != "" {
		u, err := url.Parse(c.Endpoint)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("iam.endpoint must be an http(s) URL, got %q", c.Endpoint)
		}
	}
	if (c.AccessKey == "") != (c.SecretKey == "") {
		return errors.New("iam.access_key and iam.secret_key must be set together")
	}
	if c.AccessKey == "" {
		c.AccessKey, c.SecretKey = p.cfg.AccessKey, p.cfg.SecretKey
	}
	if c.Region == "" {
		c.Region = DefaultIAMRegion
	}
	if c.Partition == "" {
		c.Partition = DefaultIAMPartition
	}
	if c.Path == "" {
		c.Path = DefaultIAMPath
	}
	if err := checkIAMPath(c.Path); err != nil {
		return err
	}
	if c.UserTemplate == "" {
		c.UserTemplate = DefaultIAMUserTemplate
	}
	var err error
	if p.iamUser, err = template.New("user").Option("missingkey=error").Parse(c.UserTemplate); err != nil {
		return fmt.Errorf("iam.user_template: %w", err)
	}
	u1, err := renderIAMUser(p.iamUser, iamUserData{Tenant: sample1, Name: "tenant-example-one"})
	if err != nil {
		return fmt.Errorf("iam.user_template: %w", err)
	}
	u2, err := renderIAMUser(p.iamUser, iamUserData{Tenant: sample2, Name: "tenant-example-two"})
	if err != nil {
		return fmt.Errorf("iam.user_template: %w", err)
	}
	if u1 == u2 {
		return errors.New("iam.user_template must depend on the tenant (e.g. {{.Name}} or {{.Tenant.Slug}})")
	}
	if c.PolicyTemplate != "" {
		if p.iamPolicy, err = template.New("iam-policy").Option("missingkey=error").Parse(c.PolicyTemplate); err != nil {
			return fmt.Errorf("iam.policy_template: %w", err)
		}
		if _, err := p.renderIAMPolicy(iamPolicyData{
			Tenant: sample1, Bucket: "tenant-example-one", Partition: c.Partition, User: u1,
		}); err != nil {
			return fmt.Errorf("iam.policy_template: %w", err)
		}
	}
	return nil
}

// checkIAMPath validates an IAM path: "/" or "/segments/", printable ASCII.
func checkIAMPath(path string) error {
	if len(path) > maxIAMPathLen || !strings.HasPrefix(path, "/") || !strings.HasSuffix(path, "/") {
		return fmt.Errorf("iam.path must start and end with / and be at most %d characters, got %q", maxIAMPathLen, path)
	}
	for _, r := range path {
		if r < 0x21 || r > 0x7e {
			return fmt.Errorf("iam.path contains an invalid character %q", r)
		}
	}
	return nil
}

func newIAMClient(c IAMConfig) *iam.Client {
	cfg := aws.Config{
		Region:      c.Region,
		Credentials: credentials.NewStaticCredentialsProvider(c.AccessKey, c.SecretKey, ""),
	}
	return iam.NewFromConfig(cfg, func(o *iam.Options) {
		if c.Endpoint != "" {
			o.BaseEndpoint = aws.String(c.Endpoint)
		}
	})
}

// iamUserData is the template data of iam.user_template.
type iamUserData struct {
	Tenant sdk.Tenant
	// Name is the tenant's bucket name (bucket mode) or prefix name
	// without the trailing slash (prefix mode).
	Name string
}

// iamPolicyData is the template data of iam.policy_template.
type iamPolicyData struct {
	Tenant    sdk.Tenant
	Bucket    string
	Prefix    string
	Partition string
	User      string
}

// renderIAMUser renders and sanitizes an IAM user name: characters outside
// [A-Za-z0-9+=,.@_-] become "-", and names longer than 64 characters are
// shortened with a hash of the tenant ID.
func renderIAMUser(tmpl *template.Template, data iamUserData) (string, error) {
	var b strings.Builder
	if err := tmpl.Execute(&b, data); err != nil {
		return "", err
	}
	var out strings.Builder
	for _, r := range b.String() {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', strings.ContainsRune("+=,.@_-", r):
			out.WriteRune(r)
		default:
			out.WriteByte('-')
		}
	}
	name := strings.Trim(out.String(), "-")
	if name == "" {
		return "", fmt.Errorf("renders an empty IAM user name for tenant %q", data.Tenant.ID)
	}
	if len(name) > maxIAMUserNameLen {
		sum := sha256.Sum256([]byte(data.Tenant.ID))
		suffix := "-" + hex.EncodeToString(sum[:4])
		name = strings.TrimRight(name[:maxIAMUserNameLen-len(suffix)], "-") + suffix
	}
	return name, nil
}

func (p *Plugin) iamUserName(t sdk.Tenant, tg target) (string, error) {
	name := tg.Bucket
	if tg.Prefix != "" {
		name = strings.TrimSuffix(tg.Prefix, "/")
	}
	u, err := renderIAMUser(p.iamUser, iamUserData{Tenant: t, Name: name})
	if err != nil {
		return "", fmt.Errorf("iam.user_template: %w", err)
	}
	return u, nil
}

// renderIAMPolicy renders the custom policy template, or builds the default
// policy restricted to the tenant's bucket (bucket mode) or prefix (prefix
// mode).
func (p *Plugin) renderIAMPolicy(d iamPolicyData) (string, error) {
	if p.iamPolicy != nil {
		var b bytes.Buffer
		if err := p.iamPolicy.Execute(&b, d); err != nil {
			return "", err
		}
		if !json.Valid(b.Bytes()) {
			return "", fmt.Errorf("renders invalid JSON for tenant %s", d.Tenant.ID)
		}
		return b.String(), nil
	}
	b, err := json.Marshal(defaultIAMPolicy(d))
	return string(b), err
}

type policyDoc struct {
	Version   string            `json:"Version"`
	Statement []policyStatement `json:"Statement"`
}

type policyStatement struct {
	Sid       string         `json:"Sid"`
	Effect    string         `json:"Effect"`
	Action    []string       `json:"Action"`
	Resource  []string       `json:"Resource"`
	Condition map[string]any `json:"Condition,omitempty"`
}

// objectActions are granted on the tenant's objects.
var objectActions = []string{
	"s3:GetObject", "s3:GetObjectVersion", "s3:PutObject",
	"s3:DeleteObject", "s3:DeleteObjectVersion",
	"s3:GetObjectTagging", "s3:PutObjectTagging", "s3:DeleteObjectTagging",
	"s3:AbortMultipartUpload", "s3:ListMultipartUploadParts",
}

func defaultIAMPolicy(d iamPolicyData) policyDoc {
	bucketARN := "arn:" + d.Partition + ":s3:::" + d.Bucket
	if d.Prefix == "" {
		return policyDoc{Version: "2012-10-17", Statement: []policyStatement{
			{
				Sid: "TenantBucket", Effect: "Allow",
				Action:   []string{"s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads", "s3:GetBucketLocation"},
				Resource: []string{bucketARN},
			},
			{Sid: "TenantObjects", Effect: "Allow", Action: objectActions, Resource: []string{bucketARN + "/*"}},
		}}
	}
	return policyDoc{Version: "2012-10-17", Statement: []policyStatement{
		{
			Sid: "TenantPrefixList", Effect: "Allow",
			Action:    []string{"s3:ListBucket", "s3:ListBucketVersions"},
			Resource:  []string{bucketARN},
			Condition: map[string]any{"StringLike": map[string]any{"s3:prefix": []string{d.Prefix, d.Prefix + "*"}}},
		},
		{
			Sid: "TenantPrefixUploads", Effect: "Allow",
			Action: []string{"s3:ListBucketMultipartUploads", "s3:GetBucketLocation"}, Resource: []string{bucketARN},
		},
		{Sid: "TenantObjects", Effect: "Allow", Action: objectActions, Resource: []string{bucketARN + "/" + d.Prefix + "*"}},
		{
			// The ownership markers belong to tenarium.
			Sid: "ProtectMarkers", Effect: "Deny",
			Action: []string{"s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion"},
			Resource: []string{
				bucketARN + "/" + d.Prefix + ownerObject,
				bucketARN + "/" + d.Prefix + retainedObject,
			},
		},
	}}
}

// iamNotFound reports whether err is IAM's NoSuchEntity.
func iamNotFound(err error) bool {
	var e *types.NoSuchEntityException
	return errors.As(err, &e)
}

// notImplemented reports whether the server answered 501 Not Implemented.
func notImplemented(err error) bool {
	var re *awshttp.ResponseError
	return errors.As(err, &re) && re.HTTPStatusCode() == http.StatusNotImplemented
}

func userOwner(u *types.User) string {
	if u == nil {
		return ""
	}
	for _, t := range u.Tags {
		if aws.ToString(t.Key) == TagTenantID {
			return aws.ToString(t.Value)
		}
	}
	return ""
}

// getIAMUser returns the user, or nil if it does not exist.
func (p *Plugin) getIAMUser(ctx context.Context, name string) (*types.User, error) {
	out, err := p.iam.GetUser(ctx, &iam.GetUserInput{UserName: aws.String(name)})
	if iamNotFound(err) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("get IAM user %s: %w", name, err)
	}
	return out.User, nil
}

// provisionIAM creates or claims the tenant's IAM user and (re)writes its
// inline policy. Access keys are never created here.
func (p *Plugin) provisionIAM(ctx context.Context, t sdk.Tenant, tg target) error {
	name, err := p.iamUserName(t, tg)
	if err != nil {
		return err
	}
	u, err := p.getIAMUser(ctx, name)
	if err != nil {
		return err
	}
	tags := []types.Tag{
		{Key: aws.String(TagTenantID), Value: aws.String(t.ID)},
		{Key: aws.String("tenarium-tenant-slug"), Value: aws.String(t.Slug)},
	}
	switch {
	case u == nil:
		in := &iam.CreateUserInput{UserName: aws.String(name), Path: aws.String(p.cfg.IAM.Path), Tags: tags}
		if p.cfg.IAM.PermissionsBoundary != "" {
			in.PermissionsBoundary = aws.String(p.cfg.IAM.PermissionsBoundary)
		}
		if _, err := p.iam.CreateUser(ctx, in); err != nil {
			var exists *types.EntityAlreadyExistsException
			if !errors.As(err, &exists) {
				return fmt.Errorf("create IAM user %s: %w", name, err)
			}
			// Created concurrently: check who owns it.
			if u, err = p.getIAMUser(ctx, name); err != nil {
				return err
			}
			if owner := userOwner(u); owner != t.ID {
				return fmt.Errorf("IAM user %s already exists and is not owned by tenant %s", name, t.ID)
			}
		}
	case userOwner(u) == t.ID:
	case userOwner(u) != "":
		return fmt.Errorf("IAM user %s already exists and belongs to another tenant (%s)", name, userOwner(u))
	default:
		// Unmarked: adopt only a user with no credentials or policies.
		empty, err := p.iamUserEmpty(ctx, name)
		if err != nil {
			return err
		}
		if !empty {
			return fmt.Errorf("IAM user %s already exists, has credentials or policies and is not managed by tenarium", name)
		}
		if _, err := p.iam.TagUser(ctx, &iam.TagUserInput{UserName: aws.String(name), Tags: tags}); err != nil {
			return fmt.Errorf("tag IAM user %s: %w", name, err)
		}
	}
	policy, err := p.renderIAMPolicy(iamPolicyData{
		Tenant: t, Bucket: tg.Bucket, Prefix: tg.Prefix, Partition: p.cfg.IAM.Partition, User: name,
	})
	if err != nil {
		return fmt.Errorf("iam.policy_template: %w", err)
	}
	if _, err := p.iam.PutUserPolicy(ctx, &iam.PutUserPolicyInput{
		UserName: aws.String(name), PolicyName: aws.String(IAMPolicyName), PolicyDocument: aws.String(policy),
	}); err != nil {
		return fmt.Errorf("put policy of IAM user %s: %w", name, err)
	}
	return nil
}

// iamUserEmpty reports whether a user has no access keys and no policies.
func (p *Plugin) iamUserEmpty(ctx context.Context, name string) (bool, error) {
	keys, err := p.iam.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: aws.String(name)})
	if err != nil {
		return false, fmt.Errorf("list access keys of %s: %w", name, err)
	}
	pols, err := p.iam.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{UserName: aws.String(name)})
	if err != nil {
		return false, fmt.Errorf("list policies of %s: %w", name, err)
	}
	att, err := p.iam.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: aws.String(name)})
	if err != nil {
		return false, fmt.Errorf("list attached policies of %s: %w", name, err)
	}
	return len(keys.AccessKeyMetadata) == 0 && len(pols.PolicyNames) == 0 && len(att.AttachedPolicies) == 0, nil
}

// deprovisionIAM deletes the tenant's IAM user with everything that would
// block its deletion (access keys, policies, group memberships, login
// profile, certificates, SSH keys, service credentials, MFA devices).
// Users not owned by the tenant are left alone.
func (p *Plugin) deprovisionIAM(ctx context.Context, t sdk.Tenant, tg target) error {
	name, err := p.iamUserName(t, tg)
	if err != nil {
		return err
	}
	u, err := p.getIAMUser(ctx, name)
	if err != nil || u == nil {
		return err
	}
	if owner := userOwner(u); owner != t.ID {
		p.log.Warn("not deleting an IAM user not owned by the tenant", "user", name, "tenant_id", t.ID, "owner", owner)
		return nil
	}
	return p.deleteIAMUser(ctx, name)
}

func (p *Plugin) deleteIAMUser(ctx context.Context, name string) error {
	user := aws.String(name)
	ignore := func(err error) error {
		if err == nil || iamNotFound(err) {
			return nil
		}
		return err
	}
	wrap := func(what string, err error) error {
		if err = ignore(err); err != nil {
			return fmt.Errorf("IAM user %s: %s: %w", name, what, err)
		}
		return nil
	}
	// optional is wrap for credential types that IAM-compatible servers
	// (LocalStack, Ceph RGW, ...) may not implement; there is nothing to
	// clean up then.
	optional := func(what string, err error) error {
		if notImplemented(err) {
			return nil
		}
		return wrap(what, err)
	}

	keys := iam.NewListAccessKeysPaginator(p.iam, &iam.ListAccessKeysInput{UserName: user})
	for keys.HasMorePages() {
		page, err := keys.NextPage(ctx)
		if err != nil {
			return wrap("list access keys", err)
		}
		for _, k := range page.AccessKeyMetadata {
			_, err := p.iam.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{UserName: user, AccessKeyId: k.AccessKeyId})
			if err := wrap("delete access key", err); err != nil {
				return err
			}
		}
	}
	pols := iam.NewListUserPoliciesPaginator(p.iam, &iam.ListUserPoliciesInput{UserName: user})
	for pols.HasMorePages() {
		page, err := pols.NextPage(ctx)
		if err != nil {
			return wrap("list policies", err)
		}
		for _, n := range page.PolicyNames {
			_, err := p.iam.DeleteUserPolicy(ctx, &iam.DeleteUserPolicyInput{UserName: user, PolicyName: aws.String(n)})
			if err := wrap("delete policy", err); err != nil {
				return err
			}
		}
	}
	att := iam.NewListAttachedUserPoliciesPaginator(p.iam, &iam.ListAttachedUserPoliciesInput{UserName: user})
	for att.HasMorePages() {
		page, err := att.NextPage(ctx)
		if err != nil {
			return wrap("list attached policies", err)
		}
		for _, a := range page.AttachedPolicies {
			_, err := p.iam.DetachUserPolicy(ctx, &iam.DetachUserPolicyInput{UserName: user, PolicyArn: a.PolicyArn})
			if err := wrap("detach policy", err); err != nil {
				return err
			}
		}
	}
	groups := iam.NewListGroupsForUserPaginator(p.iam, &iam.ListGroupsForUserInput{UserName: user})
	for groups.HasMorePages() {
		page, err := groups.NextPage(ctx)
		if err != nil {
			return wrap("list groups", err)
		}
		for _, g := range page.Groups {
			_, err := p.iam.RemoveUserFromGroup(ctx, &iam.RemoveUserFromGroupInput{UserName: user, GroupName: g.GroupName})
			if err := wrap("remove from group", err); err != nil {
				return err
			}
		}
	}
	_, err := p.iam.DeleteLoginProfile(ctx, &iam.DeleteLoginProfileInput{UserName: user})
	if err := optional("delete login profile", err); err != nil {
		return err
	}
	certs := iam.NewListSigningCertificatesPaginator(p.iam, &iam.ListSigningCertificatesInput{UserName: user})
	for certs.HasMorePages() {
		page, err := certs.NextPage(ctx)
		if err != nil {
			if err := optional("list signing certificates", err); err != nil {
				return err
			}
			break
		}
		for _, c := range page.Certificates {
			_, err := p.iam.DeleteSigningCertificate(ctx, &iam.DeleteSigningCertificateInput{UserName: user, CertificateId: c.CertificateId})
			if err := wrap("delete signing certificate", err); err != nil {
				return err
			}
		}
	}
	ssh := iam.NewListSSHPublicKeysPaginator(p.iam, &iam.ListSSHPublicKeysInput{UserName: user})
	for ssh.HasMorePages() {
		page, err := ssh.NextPage(ctx)
		if err != nil {
			if err := optional("list SSH keys", err); err != nil {
				return err
			}
			break
		}
		for _, k := range page.SSHPublicKeys {
			_, err := p.iam.DeleteSSHPublicKey(ctx, &iam.DeleteSSHPublicKeyInput{UserName: user, SSHPublicKeyId: k.SSHPublicKeyId})
			if err := wrap("delete SSH key", err); err != nil {
				return err
			}
		}
	}
	svc, err := p.iam.ListServiceSpecificCredentials(ctx, &iam.ListServiceSpecificCredentialsInput{UserName: user})
	if err := optional("list service credentials", err); err != nil {
		return err
	}
	if svc != nil {
		for _, c := range svc.ServiceSpecificCredentials {
			_, err := p.iam.DeleteServiceSpecificCredential(ctx, &iam.DeleteServiceSpecificCredentialInput{
				UserName: user, ServiceSpecificCredentialId: c.ServiceSpecificCredentialId,
			})
			if err := wrap("delete service credential", err); err != nil {
				return err
			}
		}
	}
	mfa := iam.NewListMFADevicesPaginator(p.iam, &iam.ListMFADevicesInput{UserName: user})
	for mfa.HasMorePages() {
		page, err := mfa.NextPage(ctx)
		if err != nil {
			if err := optional("list MFA devices", err); err != nil {
				return err
			}
			break
		}
		for _, d := range page.MFADevices {
			_, err := p.iam.DeactivateMFADevice(ctx, &iam.DeactivateMFADeviceInput{UserName: user, SerialNumber: d.SerialNumber})
			if err := wrap("deactivate MFA device", err); err != nil {
				return err
			}
		}
	}
	_, err = p.iam.DeleteUser(ctx, &iam.DeleteUserInput{UserName: user})
	return wrap("delete", err)
}

// AccessKey is the response of POST /tenants/{tenant}/access-keys. The
// secret is returned only once and never stored.
type AccessKey struct {
	User            string    `json:"user"`
	AccessKeyID     string    `json:"access_key_id"`
	SecretAccessKey string    `json:"secret_access_key,omitempty"`
	Status          string    `json:"status"`
	CreatedAt       time.Time `json:"created_at"`
	Bucket          string    `json:"bucket"`
	Prefix          string    `json:"prefix,omitempty"`
	Endpoint        string    `json:"endpoint"`
	Region          string    `json:"region,omitempty"`
}

// tenantIAMUser resolves the tenant of a key route, authorizes the caller
// for action and checks that the tenant's IAM user exists and is owned by
// it. It writes the error response and returns ok=false on failure.
func (p *Plugin) tenantIAMUser(w http.ResponseWriter, r *http.Request, action sdk.Action) (target, string, bool) {
	t, err := p.host.GetTenant(r.Context(), r.PathValue("tenant"))
	if errors.Is(err, sdk.ErrNotFound) {
		http.Error(w, "tenant not found", http.StatusNotFound)
		return target{}, "", false
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return target{}, "", false
	}
	res := sdk.Resource{Type: "tenant", ID: t.ID, TenantID: t.ID}
	// Callers who cannot even read the tenant learn nothing about it.
	if err := p.host.Authorize(r.Context(), sdk.ActionTenantsRead, res); err != nil {
		http.Error(w, "tenant not found", http.StatusNotFound)
		return target{}, "", false
	}
	if err := p.host.Authorize(r.Context(), action, res); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return target{}, "", false
	}
	tg, err := p.target(t)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return target{}, "", false
	}
	name, err := p.iamUserName(t, tg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return target{}, "", false
	}
	u, err := p.getIAMUser(r.Context(), name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return target{}, "", false
	}
	if u == nil || userOwner(u) != t.ID {
		http.Error(w, "the tenant has no IAM user; provision the tenant first", http.StatusConflict)
		return target{}, "", false
	}
	return tg, name, true
}

// serveCreateAccessKey creates an access key for the tenant's IAM user and
// returns its secret once. IAM allows two keys per user, so rotate by
// creating the new key and then deleting the old one.
func (p *Plugin) serveCreateAccessKey(w http.ResponseWriter, r *http.Request) {
	tg, name, ok := p.tenantIAMUser(w, r, sdk.ActionTenantsUpdate)
	if !ok {
		return
	}
	out, err := p.iam.CreateAccessKey(r.Context(), &iam.CreateAccessKeyInput{UserName: aws.String(name)})
	if err != nil {
		var limit *types.LimitExceededException
		if errors.As(err, &limit) {
			http.Error(w, "the IAM user already has the maximum number of access keys; delete one first", http.StatusConflict)
			return
		}
		http.Error(w, fmt.Sprintf("create access key: %v", err), http.StatusBadGateway)
		return
	}
	k := out.AccessKey
	resp := AccessKey{
		User: name, AccessKeyID: aws.ToString(k.AccessKeyId), SecretAccessKey: aws.ToString(k.SecretAccessKey),
		Status: string(k.Status), CreatedAt: aws.ToTime(k.CreateDate),
		Bucket: tg.Bucket, Prefix: tg.Prefix, Endpoint: p.cfg.Endpoint, Region: p.cfg.Region,
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// serveListAccessKeys lists the tenant user's access keys (without secrets).
func (p *Plugin) serveListAccessKeys(w http.ResponseWriter, r *http.Request) {
	tg, name, ok := p.tenantIAMUser(w, r, sdk.ActionTenantsUpdate)
	if !ok {
		return
	}
	keys := []AccessKey{}
	pages := iam.NewListAccessKeysPaginator(p.iam, &iam.ListAccessKeysInput{UserName: aws.String(name)})
	for pages.HasMorePages() {
		page, err := pages.NextPage(r.Context())
		if err != nil {
			http.Error(w, fmt.Sprintf("list access keys: %v", err), http.StatusBadGateway)
			return
		}
		for _, k := range page.AccessKeyMetadata {
			keys = append(keys, AccessKey{
				User: name, AccessKeyID: aws.ToString(k.AccessKeyId), Status: string(k.Status),
				CreatedAt: aws.ToTime(k.CreateDate), Bucket: tg.Bucket, Prefix: tg.Prefix,
				Endpoint: p.cfg.Endpoint, Region: p.cfg.Region,
			})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"access_keys": keys})
}

// serveDeleteAccessKey deletes one access key of the tenant's IAM user.
func (p *Plugin) serveDeleteAccessKey(w http.ResponseWriter, r *http.Request) {
	_, name, ok := p.tenantIAMUser(w, r, sdk.ActionTenantsUpdate)
	if !ok {
		return
	}
	_, err := p.iam.DeleteAccessKey(r.Context(), &iam.DeleteAccessKeyInput{
		UserName: aws.String(name), AccessKeyId: aws.String(r.PathValue("key")),
	})
	if iamNotFound(err) {
		http.Error(w, "access key not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, fmt.Sprintf("delete access key: %v", err), http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
