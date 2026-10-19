package archive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// s3Store stores objects in an S3 bucket through minio-go, the client the
// s3-tenant plugin uses.
type s3Store struct {
	client  *minio.Client
	bucket  string
	timeout time.Duration
}

func newS3Store(c S3Config, timeout time.Duration) (*s3Store, error) {
	if c.Endpoint == "" || strings.Contains(c.Endpoint, "://") || strings.Contains(c.Endpoint, "/") {
		return nil, fmt.Errorf("s3.endpoint must be host[:port] without scheme or path, got %q (use s3.secure to choose TLS)", c.Endpoint)
	}
	if c.AccessKey == "" || c.SecretKey == "" {
		return nil, errors.New("s3.access_key and s3.secret_key are required")
	}
	if c.Bucket == "" {
		return nil, errors.New("s3.bucket is required")
	}
	secure := c.Secure == nil || *c.Secure
	client, err := minio.New(c.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(c.AccessKey, c.SecretKey, ""),
		Secure: secure,
		Region: c.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("s3.endpoint: %w", err)
	}
	return &s3Store{client: client, bucket: c.Bucket, timeout: timeout}, nil
}

func (s *s3Store) ctx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, s.timeout)
}

func (s *s3Store) Put(ctx context.Context, key string, body []byte, contentType string) error {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	_, err := s.client.PutObject(ctx, s.bucket, key, bytes.NewReader(body), int64(len(body)),
		// Content-MD5 instead of a streaming (aws-chunked) signature, which some
		// S3-compatible stores do not accept over plain HTTP (as in s3-tenant).
		minio.PutObjectOptions{ContentType: contentType, SendContentMd5: true, DisableContentSha256: true})
	return err
}

func (s *s3Store) Get(ctx context.Context, key string) ([]byte, error) {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, s3Err(key, err)
	}
	defer obj.Close()
	b, err := io.ReadAll(obj)
	if err != nil {
		return nil, s3Err(key, err)
	}
	return b, nil
}

func s3Err(key string, err error) error {
	if minio.ToErrorResponse(err).Code == "NoSuchKey" {
		return fmt.Errorf("%s: %w", key, errNotFound)
	}
	return err
}

func (s *s3Store) Delete(ctx context.Context, key string) error {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	err := s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{})
	if err != nil && minio.ToErrorResponse(err).Code == "NoSuchKey" {
		return nil
	}
	return err
}

func (s *s3Store) List(ctx context.Context, prefix string) ([]string, error) {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	var keys []string
	for o := range s.client.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if o.Err != nil {
			return nil, o.Err
		}
		keys = append(keys, o.Key)
	}
	return keys, nil
}

func (s *s3Store) Check(ctx context.Context) error {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	ok, err := s.client.BucketExists(ctx, s.bucket)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("bucket %s does not exist", s.bucket)
	}
	return nil
}
