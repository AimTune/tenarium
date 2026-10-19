package secrets

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
)

// Real-service tests, skipped unless the environment points at a service:
//
//	docker run -d -p 8200:8200 -e VAULT_DEV_ROOT_TOKEN_ID=root hashicorp/vault
//	TENARIUM_TEST_VAULT_ADDR=http://127.0.0.1:8200 TENARIUM_TEST_VAULT_TOKEN=root
//
//	docker run -d -p 4566:4566 localstack/localstack
//	TENARIUM_TEST_AWS_ENDPOINT=http://127.0.0.1:4566
//
// The tests enable the transit engine / create a KMS key themselves.

func TestIntegrationVaultTransit(t *testing.T) {
	addr, token := os.Getenv("TENARIUM_TEST_VAULT_ADDR"), os.Getenv("TENARIUM_TEST_VAULT_TOKEN")
	if addr == "" || token == "" {
		t.Skip("set TENARIUM_TEST_VAULT_ADDR and TENARIUM_TEST_VAULT_TOKEN")
	}
	ctx := context.Background()
	vp, err := NewVaultTransitProvider(VaultTransitConfig{Address: addr, Token: token, KeyName: "tenarium-test"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	p := vp.(*vaultProvider)
	admin := func(path string, body any) error {
		return doJSON(ctx, p.client, "vault", func() (*http.Request, error) {
			req, _, err := jsonRequest(ctx, strings.TrimRight(addr, "/")+"/v1/"+path, body)
			if err == nil {
				req.Header.Set("X-Vault-Token", token)
			}
			return req, err
		}, nil)
	}
	// Ignore "path is already in use".
	_ = admin("sys/mounts/transit", map[string]string{"type": "transit"})
	if err := admin("transit/keys/tenarium-test", map[string]string{"type": "aes256-gcm96"}); err != nil {
		t.Fatalf("creating transit key: %v", err)
	}
	exercise(t, vp)

	// Vault-side key rotation: old values still decrypt, Rotate re-wraps.
	kr, _ := NewEnvelope(vp, nil, EnvelopeOptions{})
	ct, err := kr.Encrypt(ctx, []byte("before rotation"), "a")
	if err != nil {
		t.Fatal(err)
	}
	if err := admin("transit/keys/tenarium-test/rotate", nil); err != nil {
		t.Fatal(err)
	}
	kr2, _ := NewEnvelope(vp, nil, EnvelopeOptions{})
	if got, err := kr2.Decrypt(ctx, ct, "a"); err != nil || string(got) != "before rotation" {
		t.Fatalf("decrypt after vault rotation: %v", err)
	}
}

func TestIntegrationAWSKMS(t *testing.T) {
	endpoint := os.Getenv("TENARIUM_TEST_AWS_ENDPOINT")
	if endpoint == "" {
		t.Skip("set TENARIUM_TEST_AWS_ENDPOINT (e.g. LocalStack http://127.0.0.1:4566)")
	}
	ctx := context.Background()
	cfg := AWSKMSConfig{
		KeyID: "bootstrap", Region: "us-east-1", Endpoint: endpoint,
		AccessKeyID: "test", SecretAccessKey: "test",
	}
	bp, err := NewAWSKMSProvider(ctx, cfg, 0)
	if err != nil {
		t.Fatal(err)
	}
	var created struct {
		KeyMetadata struct {
			Arn string `json:"Arn"`
		} `json:"KeyMetadata"`
	}
	if err := bp.(*awsKMSProvider).call(ctx, "TrentService.CreateKey", map[string]any{"Description": "tenarium secrets test"}, &created); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	cfg.KeyID = created.KeyMetadata.Arn
	p, err := NewAWSKMSProvider(ctx, cfg, 0)
	if err != nil {
		t.Fatal(err)
	}
	exercise(t, p)
}
