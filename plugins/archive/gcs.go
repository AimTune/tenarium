package archive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// GCSScope is the OAuth2 scope requested for GCS credentials.
const GCSScope = "https://www.googleapis.com/auth/devstorage.read_write"

// DefaultGCSEndpoint is the Google Cloud Storage API.
const DefaultGCSEndpoint = "https://storage.googleapis.com"

// gcsStore is a minimal Google Cloud Storage JSON API client, like the one
// of the gcs-tenant plugin.
type gcsStore struct {
	endpoint string // without trailing slash
	bucket   string
	http     *http.Client
}

func newGCSStore(ctx context.Context, c GCSConfig, timeout time.Duration) (*gcsStore, error) {
	if c.Bucket == "" {
		return nil, errors.New("gcs.bucket is required")
	}
	if c.Endpoint == "" {
		c.Endpoint = DefaultGCSEndpoint
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		strings.Trim(u.Path, "/") != "" || u.RawQuery != "" {
		return nil, fmt.Errorf("gcs.endpoint must be an http(s) URL without path, got %q", c.Endpoint)
	}
	if c.CredentialsFile != "" && c.CredentialsJSON != "" {
		return nil, errors.New("set only one of gcs.credentials_file and gcs.credentials_json")
	}
	if c.Anonymous && (c.CredentialsFile != "" || c.CredentialsJSON != "") {
		return nil, errors.New("gcs.anonymous cannot be combined with credentials")
	}
	hc := &http.Client{Timeout: timeout}
	if !c.Anonymous {
		creds, err := gcsCredentials(ctx, c)
		if err != nil {
			return nil, err
		}
		// The token source outlives Init, so it must not use Init's context.
		hc = oauth2.NewClient(context.WithoutCancel(ctx), creds.TokenSource)
		hc.Timeout = timeout
	}
	return &gcsStore{endpoint: strings.TrimRight(c.Endpoint, "/"), bucket: c.Bucket, http: hc}, nil
}

var gcsCredentialTypes = map[string]google.CredentialsType{
	string(google.ServiceAccount):                google.ServiceAccount,
	string(google.AuthorizedUser):                google.AuthorizedUser,
	string(google.ExternalAccount):               google.ExternalAccount,
	string(google.ExternalAccountAuthorizedUser): google.ExternalAccountAuthorizedUser,
	string(google.ImpersonatedServiceAccount):    google.ImpersonatedServiceAccount,
}

func gcsCredentials(ctx context.Context, c GCSConfig) (*google.Credentials, error) {
	raw, source := []byte(c.CredentialsJSON), "gcs.credentials_json"
	if c.CredentialsFile != "" {
		b, err := os.ReadFile(c.CredentialsFile)
		if err != nil {
			return nil, fmt.Errorf("gcs.credentials_file: %w", err)
		}
		raw, source = b, "gcs.credentials_file"
	}
	if len(raw) == 0 {
		creds, err := google.FindDefaultCredentials(ctx, GCSScope)
		if err != nil {
			return nil, fmt.Errorf("application default credentials: %w (set gcs.credentials_file, gcs.credentials_json or gcs.anonymous)", err)
		}
		return creds, nil
	}
	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	typ, ok := gcsCredentialTypes[head.Type]
	if !ok {
		return nil, fmt.Errorf("%s: unsupported credentials type %q", source, head.Type)
	}
	creds, err := google.CredentialsFromJSONWithType(ctx, raw, typ, GCSScope)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	return creds, nil
}

// gcsError is an error answered by the JSON API.
type gcsError struct {
	Code    int
	Message string
}

func (e *gcsError) Error() string { return fmt.Sprintf("gcs: %d: %s", e.Code, e.Message) }

func gcsStatus(err error) int {
	var e *gcsError
	if errors.As(err, &e) {
		return e.Code
	}
	return 0
}

// do sends req and returns the body of a 2xx response, read up to limit.
func (s *gcsStore) do(req *http.Request, limit int64) ([]byte, error) {
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		var env struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		e := &gcsError{Code: resp.StatusCode, Message: http.StatusText(resp.StatusCode)}
		if json.Unmarshal(raw, &env) == nil && env.Error.Message != "" {
			e.Message = env.Error.Message
		}
		return nil, e
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

func (s *gcsStore) objectURL(key string) string {
	return s.endpoint + "/storage/v1/b/" + url.PathEscape(s.bucket) + "/o/" + url.PathEscape(key)
}

func (s *gcsStore) Put(ctx context.Context, key string, body []byte, contentType string) error {
	q := url.Values{"uploadType": {"media"}, "name": {key}}
	u := s.endpoint + "/upload/storage/v1/b/" + url.PathEscape(s.bucket) + "/o?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	_, err = s.do(req, 1<<20)
	return err
}

// maxObjectSize bounds reads; objects hold at most MaxBatchSize events.
const maxObjectSize = 256 << 20

func (s *gcsStore) Get(ctx context.Context, key string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.objectURL(key)+"?alt=media", nil)
	if err != nil {
		return nil, err
	}
	b, err := s.do(req, maxObjectSize)
	if gcsStatus(err) == http.StatusNotFound {
		return nil, fmt.Errorf("%s: %w", key, errNotFound)
	}
	return b, err
}

func (s *gcsStore) Delete(ctx context.Context, key string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.objectURL(key), nil)
	if err != nil {
		return err
	}
	if _, err = s.do(req, 1<<20); gcsStatus(err) == http.StatusNotFound {
		return nil
	}
	return err
}

func (s *gcsStore) List(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	token := ""
	for {
		q := url.Values{"prefix": {prefix}, "maxResults": {"1000"}, "fields": {"items(name),nextPageToken"}}
		if token != "" {
			q.Set("pageToken", token)
		}
		u := s.endpoint + "/storage/v1/b/" + url.PathEscape(s.bucket) + "/o?" + q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		raw, err := s.do(req, 64<<20)
		if err != nil {
			return nil, err
		}
		var page struct {
			Items []struct {
				Name string `json:"name"`
			} `json:"items"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return nil, fmt.Errorf("gcs: list: %w", err)
		}
		for _, it := range page.Items {
			keys = append(keys, it.Name)
		}
		if page.NextPageToken == "" {
			return keys, nil
		}
		token = page.NextPageToken
	}
}

func (s *gcsStore) Check(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint+"/storage/v1/b/"+url.PathEscape(s.bucket), nil)
	if err != nil {
		return err
	}
	_, err = s.do(req, 1<<20)
	return err
}
