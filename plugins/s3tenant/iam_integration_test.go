package s3tenant

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/minio/minio-go/v7"
)

// IAM integration tests need TENARIUM_TEST_S3_ENDPOINT (see
// integration_test.go) and an IAM API at TENARIUM_TEST_S3_IAM_ENDPOINT (a
// URL, e.g. LocalStack: http://localhost:4566). IAM credentials default to
// "test"/"test" and can be overridden with TENARIUM_TEST_S3_IAM_ACCESS_KEY /
// TENARIUM_TEST_S3_IAM_SECRET_KEY.

func iamEndpoint(t *testing.T) string {
	t.Helper()
	e := os.Getenv("TENARIUM_TEST_S3_IAM_ENDPOINT")
	if e == "" {
		t.Skip("TENARIUM_TEST_S3_IAM_ENDPOINT not set")
	}
	return e
}

func iamTestConfig(t *testing.T, extra map[string]any) map[string]any {
	c := map[string]any{
		"enabled":    true,
		"endpoint":   iamEndpoint(t),
		"access_key": envOr("TENARIUM_TEST_S3_IAM_ACCESS_KEY", "test"),
		"secret_key": envOr("TENARIUM_TEST_S3_IAM_SECRET_KEY", "test"),
		"path":       "/tenarium-test/",
	}
	for k, v := range extra {
		c[k] = v
	}
	return c
}

func TestIntegrationIAM(t *testing.T) {
	for _, mode := range []string{ModeBucket, ModePrefix} {
		t.Run(mode, func(t *testing.T) {
			cfg := map[string]any{"name_template": "tnt-{{.Slug}}", "iam": iamTestConfig(t, nil)}
			shared := ""
			if mode == ModePrefix {
				shared = "tnt-shared-" + randHex(t)
				cfg["mode"], cfg["bucket"] = ModePrefix, shared
			}
			// The shared bucket must exist before Init's health check.
			if shared != "" {
				bp, _ := newPlugin(t, nil)
				if err := bp.client.MakeBucket(context.Background(), shared, minio.MakeBucketOptions{Region: "us-east-1"}); err != nil {
					t.Fatal(err)
				}
				cleanupBucket(t, bp, shared)
			}
			p, reg := newPlugin(t, cfg)
			ctx := context.Background()
			slug := "iam-" + randHex(t)
			ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug})
			user := "tnt-" + slug
			if mode == ModeBucket {
				cleanupBucket(t, p, user)
			}
			t.Cleanup(func() { _ = p.deleteIAMUser(context.Background(), user) })

			for range 2 {
				if err := p.Provision(ctx, ten); err != nil {
					t.Fatalf("provision: %v", err)
				}
			}
			out, err := p.iam.GetUser(ctx, &iam.GetUserInput{UserName: aws.String(user)})
			if err != nil {
				t.Fatalf("get user: %v", err)
			}
			if userOwner(out.User) != ten.ID || aws.ToString(out.User.Path) != "/tenarium-test/" {
				t.Fatalf("user %+v", out.User)
			}
			pol, err := p.iam.(*iam.Client).GetUserPolicy(ctx, &iam.GetUserPolicyInput{
				UserName: aws.String(user), PolicyName: aws.String(IAMPolicyName),
			})
			if err != nil {
				t.Fatalf("get policy: %v", err)
			}
			if doc := aws.ToString(pol.PolicyDocument); !strings.Contains(doc, "tnt-") {
				t.Fatalf("policy %s", doc)
			}

			// Access keys via the admin route.
			req := httptest.NewRequest(http.MethodPost, "/tenants/"+slug+"/access-keys", nil)
			req = req.WithContext(sdk.WithPrincipal(req.Context(), &sdk.Principal{Subject: "admin"}))
			rec := httptest.NewRecorder()
			reg.Mux.ServeHTTP(rec, req)
			body, _ := io.ReadAll(rec.Result().Body)
			if rec.Code != http.StatusCreated {
				t.Fatalf("create key %d: %s", rec.Code, body)
			}
			var key AccessKey
			if err := json.Unmarshal(body, &key); err != nil {
				t.Fatal(err)
			}
			if key.AccessKeyID == "" || key.SecretAccessKey == "" || key.User != user {
				t.Fatalf("key %+v", key)
			}

			// Deprovision deletes the user even though it has a key.
			for range 2 {
				if err := p.Deprovision(ctx, ten); err != nil {
					t.Fatalf("deprovision: %v", err)
				}
			}
			if u, err := p.getIAMUser(ctx, user); err != nil || u != nil {
				t.Fatalf("user still exists: %+v, %v", u, err)
			}
			if mode == ModeBucket && bucketExists(t, p, user) {
				t.Fatal("bucket still exists")
			}
		})
	}
}

func TestIntegrationIAMRetainAndConflict(t *testing.T) {
	p, reg := newPlugin(t, map[string]any{
		"name_template": "tnt-{{.Slug}}", "on_deprovision": "retain", "iam": iamTestConfig(t, nil),
	})
	ctx := context.Background()
	slug := "iamr-" + randHex(t)
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug})
	name := "tnt-" + slug
	cleanupBucket(t, p, name)
	t.Cleanup(func() { _ = p.deleteIAMUser(context.Background(), name) })

	// A user tagged for another tenant blocks provisioning and survives.
	if _, err := p.iam.CreateUser(ctx, &iam.CreateUserInput{UserName: aws.String(name), Tags: nil}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.iam.TagUser(ctx, &iam.TagUserInput{UserName: aws.String(name), Tags: []types.Tag{{Key: aws.String(TagTenantID), Value: aws.String("someone-else")}}}); err != nil {
		t.Fatal(err)
	}
	if err := p.Provision(ctx, ten); err == nil || !strings.Contains(err.Error(), "another tenant") {
		t.Fatalf("expected conflict, got %v", err)
	}
	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	if u, _ := p.getIAMUser(ctx, name); u == nil {
		t.Fatal("deleted another tenant's user")
	}
	if err := p.deleteIAMUser(ctx, name); err != nil {
		t.Fatal(err)
	}

	// retain keeps the bucket but removes the user (a fresh tenant: the
	// conflicting run above already retained the first bucket).
	slug2 := "iamr-" + randHex(t)
	ten2 := reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug2})
	name2 := "tnt-" + slug2
	cleanupBucket(t, p, name2)
	t.Cleanup(func() { _ = p.deleteIAMUser(context.Background(), name2) })
	if err := p.Provision(ctx, ten2); err != nil {
		t.Fatal(err)
	}
	if u, _ := p.getIAMUser(ctx, name2); u == nil {
		t.Fatal("user not created")
	}
	if err := p.Deprovision(ctx, ten2); err != nil {
		t.Fatal(err)
	}
	if u, _ := p.getIAMUser(ctx, name2); u != nil {
		t.Fatal("user kept on retain")
	}
	if !bucketExists(t, p, name2) {
		t.Fatal("bucket not retained")
	}
}
