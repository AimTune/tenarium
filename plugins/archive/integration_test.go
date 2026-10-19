package archive

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
	"github.com/minio/minio-go/v7"
)

// Integration tests run against an S3-compatible server named by
// TENARIUM_TEST_S3_ENDPOINT (host:port, plain HTTP), e.g. SeaweedFS or
// MinIO. Credentials default to "any"/"any" and can be overridden with
// TENARIUM_TEST_S3_ACCESS_KEY / TENARIUM_TEST_S3_SECRET_KEY.

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// s3Bucket creates a fresh bucket and returns the backend configuration.
func s3Bucket(t *testing.T) map[string]any {
	t.Helper()
	endpoint := os.Getenv("TENARIUM_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("TENARIUM_TEST_S3_ENDPOINT not set")
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	cfg := S3Config{
		Endpoint: endpoint, Region: "us-east-1", Bucket: "tenarium-archive-" + hex.EncodeToString(b),
		AccessKey: envOr("TENARIUM_TEST_S3_ACCESS_KEY", "any"), SecretKey: envOr("TENARIUM_TEST_S3_SECRET_KEY", "any"),
	}
	insecure := false
	cfg.Secure = &insecure
	s, err := newS3Store(cfg, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.client.MakeBucket(ctx, cfg.Bucket, minio.MakeBucketOptions{Region: cfg.Region}); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	t.Cleanup(func() {
		keys, _ := s.List(ctx, "")
		for _, k := range keys {
			_ = s.Delete(ctx, k)
		}
		if err := s.client.RemoveBucket(ctx, cfg.Bucket); err != nil {
			t.Logf("cleanup %s: %v", cfg.Bucket, err)
		}
	})
	return map[string]any{
		"endpoint": cfg.Endpoint, "region": cfg.Region, "bucket": cfg.Bucket,
		"access_key": cfg.AccessKey, "secret_key": cfg.SecretKey, "secure": false,
	}
}

func TestS3StoreIntegration(t *testing.T) {
	cfg := s3Bucket(t)
	s, err := newS3Store(S3Config{
		Endpoint: cfg["endpoint"].(string), Region: "us-east-1", Bucket: cfg["bucket"].(string),
		AccessKey: cfg["access_key"].(string), SecretKey: cfg["secret_key"].(string), Secure: new(bool),
	}, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	testStore(t, s)
}

// TestS3ArchiveIntegration archives events through the subscription and
// reads them back through the route.
func TestS3ArchiveIntegration(t *testing.T) {
	cfg := s3Bucket(t)
	reg := sdktest.NewRegistrar(map[string]any{"backend": "s3", "s3": cfg, "batch_size": 3})
	c := &clock{now: t0}
	p := &Plugin{now: c.Now}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if err := p.Health(context.Background()); err != nil {
		t.Fatalf("Health: %v", err)
	}
	f := &fixture{p: p, reg: reg, clock: c}
	f.deliver(t,
		event(1, "tenant.created", "t1", t0),
		event(2, "tenant.created", "t2", t0.Add(time.Second)),
		event(3, "tenant.updated", "t1", t0.Add(2*time.Second)),
		event(4, "tenant.updated", "t1", t0.Add(3*time.Second)),
		event(4, "tenant.updated", "t1", t0.Add(3*time.Second)), // redelivery
		event(5, "tenant.deleted", "t1", t0.Add(40*time.Minute)),
	)
	keys, err := p.store.List(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(keys)
	want := []string{key("2026/10/10/08", 1, 3), key("2026/10/10/08", 4, 4), key("2026/10/10/09", 5, 5)}
	if !slices.Equal(keys, want) {
		t.Fatalf("keys = %v, want %v", keys, want)
	}
	resp, events := get(t, f, rangeQuery(t0, t0.Add(time.Hour), "tenant_id=t1"), admin)
	if resp.StatusCode != http.StatusOK || !slices.Equal(seqs(events), []int64{1, 3, 4, 5}) {
		t.Fatalf("read back: %d %v", resp.StatusCode, seqs(events))
	}
}
