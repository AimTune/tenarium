package rabbitmqvhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// client is a minimal RabbitMQ Management HTTP API client.
type client struct {
	base       string
	user, pass string
	http       *http.Client
}

// apiError is a non-2xx Management API response.
type apiError struct {
	Method, Path string
	Status       int
	Body         string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("rabbitmq management API %s %s: %d %s", e.Method, e.Path, e.Status, e.Body)
}

func isNotFound(err error) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

func (c *client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.user, c.pass)
	// No Accept header: some endpoints (PUT /api/vhost-limits) answer 406
	// to "Accept: application/json" because they return no body.
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return &apiError{Method: method, Path: path, Status: resp.StatusCode, Body: strings.TrimSpace(string(msg))}
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func esc(s string) string { return url.PathEscape(s) }

// tagList decodes tags reported either as a JSON list (RabbitMQ 3.9+) or as
// a comma separated string (older releases).
type tagList []string

func (t *tagList) UnmarshalJSON(b []byte) error {
	var list []string
	if err := json.Unmarshal(b, &list); err == nil {
		*t = list
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("tags: %w", err)
	}
	*t = nil
	for _, tag := range strings.Split(s, ",") {
		if tag = strings.TrimSpace(tag); tag != "" {
			*t = append(*t, tag)
		}
	}
	return nil
}

// vhostInfo is a GET /api/vhosts/{name} response.
type vhostInfo struct {
	Name             string  `json:"name"`
	Description      string  `json:"description"`
	Tags             tagList `json:"tags"`
	DefaultQueueType string  `json:"default_queue_type"`
	Metadata         struct {
		Description string  `json:"description"`
		Tags        tagList `json:"tags"`
	} `json:"metadata"`
}

func (v *vhostInfo) tags() []string {
	if len(v.Tags) > 0 {
		return v.Tags
	}
	return v.Metadata.Tags
}

// vhostBody is a PUT /api/vhosts/{name} request.
type vhostBody struct {
	Description      string `json:"description"`
	Tags             string `json:"tags"`
	DefaultQueueType string `json:"default_queue_type,omitempty"`
}

// userInfo is a GET /api/users/{name} response.
type userInfo struct {
	Name string  `json:"name"`
	Tags tagList `json:"tags"`
}

// userBody is a PUT /api/users/{name} request.
type userBody struct {
	Password string `json:"password"`
	Tags     string `json:"tags"`
}

// permissionBody is a PUT /api/permissions/{vhost}/{user} request.
type permissionBody struct {
	Configure string `json:"configure"`
	Write     string `json:"write"`
	Read      string `json:"read"`
}

// getVhost returns the vhost, or nil if it does not exist.
func (c *client) getVhost(ctx context.Context, name string) (*vhostInfo, error) {
	var v vhostInfo
	err := c.do(ctx, http.MethodGet, "/api/vhosts/"+esc(name), nil, &v)
	if isNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// getUser returns the user, or nil if it does not exist.
func (c *client) getUser(ctx context.Context, name string) (*userInfo, error) {
	var u userInfo
	err := c.do(ctx, http.MethodGet, "/api/users/"+esc(name), nil, &u)
	if isNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (c *client) putVhost(ctx context.Context, name string, b vhostBody) error {
	return c.do(ctx, http.MethodPut, "/api/vhosts/"+esc(name), b, nil)
}

func (c *client) putUser(ctx context.Context, name string, b userBody) error {
	return c.do(ctx, http.MethodPut, "/api/users/"+esc(name), b, nil)
}

func (c *client) putPermissions(ctx context.Context, vhost, user string, b permissionBody) error {
	return c.do(ctx, http.MethodPut, "/api/permissions/"+esc(vhost)+"/"+esc(user), b, nil)
}

func (c *client) putVhostLimit(ctx context.Context, vhost, limit string, value int64) error {
	return c.do(ctx, http.MethodPut, "/api/vhost-limits/"+esc(vhost)+"/"+esc(limit), map[string]int64{"value": value}, nil)
}

// deleteIgnoreMissing issues DELETE path, treating 404 as success.
func (c *client) deleteIgnoreMissing(ctx context.Context, path string) error {
	if err := c.do(ctx, http.MethodDelete, path, nil, nil); err != nil && !isNotFound(err) {
		return err
	}
	return nil
}
