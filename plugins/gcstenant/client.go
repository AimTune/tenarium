package gcstenant

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
)

// client is a minimal Google Cloud Storage JSON API client. Only the calls
// the provisioner needs are implemented, on top of an *http.Client that
// carries the credentials (or none, for emulators).
type client struct {
	endpoint string // e.g. https://storage.googleapis.com, without trailing slash
	http     *http.Client
}

// apiError is an error answered by the JSON API.
type apiError struct {
	Code    int
	Reason  string
	Message string
}

func (e *apiError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("gcs: %d %s: %s", e.Code, e.Reason, e.Message)
	}
	return fmt.Sprintf("gcs: %d: %s", e.Code, e.Message)
}

// statusOf returns the HTTP status of an API error, or 0.
func statusOf(err error) int {
	var e *apiError
	if errors.As(err, &e) {
		return e.Code
	}
	return 0
}

func isNotFound(err error) bool { return statusOf(err) == http.StatusNotFound }

// isPrecondition reports a failed ifGenerationMatch/ifMetagenerationMatch.
func isPrecondition(err error) bool { return statusOf(err) == http.StatusPreconditionFailed }

// bucket is the subset of the bucket resource the provisioner reads. Fields
// it does not manage are not sent back on PATCH, so they are left alone.
type bucket struct {
	Name           string            `json:"name"`
	Location       string            `json:"location,omitempty"`
	StorageClass   string            `json:"storageClass,omitempty"`
	Metageneration string            `json:"metageneration,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	Versioning     *struct {
		Enabled bool `json:"enabled"`
	} `json:"versioning,omitempty"`
	Lifecycle *struct {
		Rule []map[string]any `json:"rule"`
	} `json:"lifecycle,omitempty"`
	IAMConfiguration *struct {
		UniformBucketLevelAccess *struct {
			Enabled bool `json:"enabled"`
		} `json:"uniformBucketLevelAccess,omitempty"`
		PublicAccessPrevention string `json:"publicAccessPrevention,omitempty"`
	} `json:"iamConfiguration,omitempty"`
}

func (b *bucket) versioningEnabled() bool { return b.Versioning != nil && b.Versioning.Enabled }

// object is the subset of the object resource the provisioner reads.
type object struct {
	Name       string            `json:"name"`
	Generation string            `json:"generation"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

func (c *client) api(path string) string { return c.endpoint + "/storage/v1" + path }

// do sends a JSON request and decodes a JSON response into out (if not nil).
func (c *client) do(ctx context.Context, method, rawURL string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.send(req, out)
}

func (c *client) send(req *http.Request, out any) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return decodeError(resp)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil
	}
	if w, ok := out.(*[]byte); ok {
		b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		*w = b
		return err
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func decodeError(resp *http.Response) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var env struct {
		Error struct {
			Message string `json:"message"`
			Errors  []struct {
				Reason string `json:"reason"`
			} `json:"errors"`
		} `json:"error"`
	}
	e := &apiError{Code: resp.StatusCode}
	if json.Unmarshal(raw, &env) == nil && env.Error.Message != "" {
		e.Message = env.Error.Message
		if len(env.Error.Errors) > 0 {
			e.Reason = env.Error.Errors[0].Reason
		}
	} else {
		e.Message = http.StatusText(resp.StatusCode)
	}
	return e
}

func (c *client) getBucket(ctx context.Context, name string) (*bucket, error) {
	var b bucket
	if err := c.do(ctx, http.MethodGet, c.api("/b/"+url.PathEscape(name)), nil, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

func (c *client) createBucket(ctx context.Context, project string, b map[string]any) error {
	q := url.Values{"project": {project}}
	return c.do(ctx, http.MethodPost, c.api("/b?"+q.Encode()), b, nil)
}

// patchBucket applies patch if the bucket's metageneration still is
// metageneration (when not empty), and returns the updated bucket.
func (c *client) patchBucket(ctx context.Context, name, metageneration string, patch map[string]any) (*bucket, error) {
	u := c.api("/b/" + url.PathEscape(name))
	if metageneration != "" {
		u += "?" + url.Values{"ifMetagenerationMatch": {metageneration}}.Encode()
	}
	var b bucket
	if err := c.do(ctx, http.MethodPatch, u, patch, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

func (c *client) deleteBucket(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, c.api("/b/"+url.PathEscape(name)), nil, nil)
}

// listBuckets lists at most one bucket of project; used as a health check.
func (c *client) listBuckets(ctx context.Context, project string) error {
	q := url.Values{"project": {project}, "maxResults": {"1"}}
	return c.do(ctx, http.MethodGet, c.api("/b?"+q.Encode()), nil, nil)
}

// listObjects calls fn for every object generation (live and
// noncurrent) under prefix. limit > 0 stops after that many.
func (c *client) listObjects(ctx context.Context, bkt, prefix string, limit int, fn func(object) error) error {
	token := ""
	seen := 0
	for {
		q := url.Values{"prefix": {prefix}, "versions": {"true"}}
		if limit > 0 && limit < 1000 {
			q.Set("maxResults", strconv.Itoa(limit))
		} else {
			q.Set("maxResults", "1000")
		}
		if token != "" {
			q.Set("pageToken", token)
		}
		var page struct {
			Items         []object `json:"items"`
			NextPageToken string   `json:"nextPageToken"`
		}
		if err := c.do(ctx, http.MethodGet, c.api("/b/"+url.PathEscape(bkt)+"/o?"+q.Encode()), nil, &page); err != nil {
			return err
		}
		for _, o := range page.Items {
			if err := fn(o); err != nil {
				return err
			}
			seen++
			if limit > 0 && seen >= limit {
				return nil
			}
		}
		if page.NextPageToken == "" {
			return nil
		}
		token = page.NextPageToken
	}
}

func (c *client) objectURL(bkt, name string) string {
	return c.api("/b/" + url.PathEscape(bkt) + "/o/" + url.PathEscape(name))
}

// getObject returns the metadata of the live generation of an object.
func (c *client) getObject(ctx context.Context, bkt, name string) (*object, error) {
	var o object
	if err := c.do(ctx, http.MethodGet, c.objectURL(bkt, name), nil, &o); err != nil {
		return nil, err
	}
	return &o, nil
}

// readObject returns the content (at most 64 KiB) of a given generation.
func (c *client) readObject(ctx context.Context, bkt, name, generation string) ([]byte, error) {
	q := url.Values{"alt": {"media"}}
	if generation != "" {
		q.Set("generation", generation)
	}
	var b []byte
	err := c.do(ctx, http.MethodGet, c.objectURL(bkt, name)+"?"+q.Encode(), nil, &b)
	return b, err
}

// deleteObject deletes one generation of an object permanently (the live
// one if generation is empty). ifGenerationMatch, when not empty, is sent
// as a precondition.
func (c *client) deleteObject(ctx context.Context, bkt, name, generation, ifGenerationMatch string) error {
	q := url.Values{}
	if generation != "" {
		q.Set("generation", generation)
	}
	if ifGenerationMatch != "" {
		q.Set("ifGenerationMatch", ifGenerationMatch)
	}
	u := c.objectURL(bkt, name)
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	return c.do(ctx, http.MethodDelete, u, nil, nil)
}

// putObject uploads a small object with metadata in one multipart request.
// ifGenerationMatch is a precondition: "0" means "only if it does not
// exist", a generation means "only if it is still that one".
func (c *client) putObject(ctx context.Context, bkt, name, contentType string, content []byte, metadata map[string]string, ifGenerationMatch string) error {
	meta, err := json.Marshal(map[string]any{"name": name, "contentType": contentType, "metadata": metadata})
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.SetBoundary(boundary()); err != nil {
		return err
	}
	for _, part := range []struct {
		typ  string
		body []byte
	}{{"application/json; charset=UTF-8", meta}, {contentType, content}} {
		w, err := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {part.typ}})
		if err != nil {
			return err
		}
		if _, err := w.Write(part.body); err != nil {
			return err
		}
	}
	if err := mw.Close(); err != nil {
		return err
	}
	q := url.Values{"uploadType": {"multipart"}}
	if ifGenerationMatch != "" {
		q.Set("ifGenerationMatch", ifGenerationMatch)
	}
	u := c.endpoint + "/upload/storage/v1/b/" + url.PathEscape(bkt) + "/o?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "multipart/related; boundary="+mw.Boundary())
	return c.send(req, nil)
}

func boundary() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "tenarium-" + hex.EncodeToString(b)
}
