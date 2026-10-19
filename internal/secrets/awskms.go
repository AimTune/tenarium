package secrets

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

// AWSKMSConfig configures the "awskms" provider, which wraps data keys with
// an AWS KMS symmetric key through the KMS JSON API (TrentService.Encrypt /
// TrentService.Decrypt), signed with SigV4.
type AWSKMSConfig struct {
	// KeyID is a key id, key ARN, alias name ("alias/tenarium") or alias
	// ARN. New values record the key ARN that KMS reports.
	KeyID string `yaml:"key_id" json:"key_id"`
	// Region, e.g. "eu-west-1". Falls back to the SDK default chain
	// (AWS_REGION, shared config).
	Region string `yaml:"region" json:"region"`
	// Endpoint overrides https://kms.<region>.amazonaws.com (LocalStack,
	// VPC endpoints, FIPS endpoints).
	Endpoint string `yaml:"endpoint" json:"endpoint"`
	// Profile selects a shared-config profile.
	Profile string `yaml:"profile" json:"profile"`
	// Static credentials. When empty the SDK default chain is used (env,
	// shared config, web identity / IRSA, ECS, EC2 instance role).
	AccessKeyID     string `yaml:"access_key_id" json:"access_key_id"`
	SecretAccessKey string `yaml:"secret_access_key" json:"secret_access_key"`
	SessionToken    string `yaml:"session_token" json:"session_token"`

	// HTTPClient overrides the HTTP client (tests, proxies).
	HTTPClient *http.Client `yaml:"-" json:"-"`
}

func (c AWSKMSConfig) validate() error {
	if c.KeyID == "" {
		return errors.New("aws_kms.key_id: required")
	}
	if (c.AccessKeyID == "") != (c.SecretAccessKey == "") {
		return errors.New("aws_kms: access_key_id and secret_access_key must be set together")
	}
	return nil
}

type awsKMSProvider struct {
	cfg      AWSKMSConfig
	region   string
	endpoint string
	creds    aws.CredentialsProvider
	signer   *v4.Signer
	client   *http.Client
}

// NewAWSKMSProvider builds the "awskms" KeyProvider.
func NewAWSKMSProvider(ctx context.Context, c AWSKMSConfig, timeout time.Duration) (KeyProvider, error) {
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	var opts []func(*awsconfig.LoadOptions) error
	if c.Region != "" {
		opts = append(opts, awsconfig.WithRegion(c.Region))
	}
	if c.Profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(c.Profile))
	}
	if c.AccessKeyID != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, c.SessionToken)))
	}
	ac, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("secrets: aws_kms: loading AWS config: %w", err)
	}
	region := ac.Region
	if region == "" {
		region = regionFromARN(c.KeyID)
	}
	if region == "" {
		return nil, errors.New("secrets: aws_kms.region: required (not found in config, environment or key ARN)")
	}
	if ac.Credentials == nil {
		return nil, errors.New("secrets: aws_kms: no AWS credentials available")
	}
	endpoint := strings.TrimRight(c.Endpoint, "/")
	if endpoint == "" {
		endpoint = "https://kms." + region + ".amazonaws.com"
	}
	return &awsKMSProvider{
		cfg:      c,
		region:   region,
		endpoint: endpoint + "/",
		creds:    ac.Credentials,
		signer:   v4.NewSigner(),
		client:   httpClientOr(c.HTTPClient, timeout),
	}, nil
}

func regionFromARN(s string) string {
	// arn:aws:kms:<region>:<account>:key/<id>
	parts := strings.Split(s, ":")
	if len(parts) >= 6 && parts[0] == "arn" && parts[2] == "kms" {
		return parts[3]
	}
	return ""
}

func (p *awsKMSProvider) Name() string { return "awskms" }

var awsEncryptionContext = map[string]string{"purpose": dekContext}

func (p *awsKMSProvider) Wrap(ctx context.Context, dek []byte) (string, []byte, error) {
	var out struct {
		CiphertextBlob string `json:"CiphertextBlob"`
		KeyID          string `json:"KeyId"`
	}
	err := p.call(ctx, "TrentService.Encrypt", map[string]any{
		"KeyId":             p.cfg.KeyID,
		"Plaintext":         base64.StdEncoding.EncodeToString(dek),
		"EncryptionContext": awsEncryptionContext,
	}, &out)
	if err != nil {
		return "", nil, err
	}
	blob, err := base64.StdEncoding.DecodeString(out.CiphertextBlob)
	if err != nil {
		return "", nil, fmt.Errorf("aws kms: bad CiphertextBlob: %w", err)
	}
	keyID := out.KeyID
	if keyID == "" {
		keyID = p.cfg.KeyID
	}
	return keyID, blob, nil
}

func (p *awsKMSProvider) Unwrap(ctx context.Context, keyID string, wrapped []byte) ([]byte, error) {
	var out struct {
		Plaintext string `json:"Plaintext"`
	}
	// Passing KeyId pins decryption to the key recorded in the ciphertext;
	// KMS rejects the call if the blob was produced by another key.
	err := p.call(ctx, "TrentService.Decrypt", map[string]any{
		"KeyId":             keyID,
		"CiphertextBlob":    base64.StdEncoding.EncodeToString(wrapped),
		"EncryptionContext": awsEncryptionContext,
	}, &out)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.Plaintext)
}

func (p *awsKMSProvider) call(ctx context.Context, target string, payload any, out any) error {
	return doJSON(ctx, p.client, "awskms", func() (*http.Request, error) {
		req, body, err := jsonRequest(ctx, p.endpoint, payload)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-amz-json-1.1")
		req.Header.Set("X-Amz-Target", target)
		creds, err := p.creds.Retrieve(ctx)
		if err != nil {
			return nil, fmt.Errorf("aws kms: retrieving credentials: %w", err)
		}
		sum := sha256.Sum256(body)
		if err := p.signer.SignHTTP(ctx, creds, req, hex.EncodeToString(sum[:]), "kms", p.region, time.Now()); err != nil {
			return nil, fmt.Errorf("aws kms: signing request: %w", err)
		}
		return req, nil
	}, out)
}
