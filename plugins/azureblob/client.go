package azureblob

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// APIVersion is the Blob service REST API version sent as x-ms-version.
const APIVersion = "2023-11-03"

// Azurite (storage emulator) well-known development account.
const (
	DevAccountName = "devstoreaccount1"
	DevAccountKey  = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
	DevBlobURL     = "http://127.0.0.1:10000/devstoreaccount1"
)

// maxErrorBody bounds how much of an error response is read.
const maxErrorBody = 64 << 10

// credentials are the resolved connection settings of a storage account.
type credentials struct {
	Account  string
	Key      []byte
	Endpoint *url.URL // blob service endpoint, no trailing slash
}

// parseConnectionString resolves an Azure Storage connection string.
// Supported keys: DefaultEndpointsProtocol, AccountName, AccountKey,
// EndpointSuffix, BlobEndpoint and UseDevelopmentStorage=true (Azurite
// defaults). Shared access signatures are not supported: provisioning needs
// account-level rights.
func parseConnectionString(s string) (credentials, error) {
	kv := map[string]string{}
	for part := range strings.SplitSeq(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return credentials{}, fmt.Errorf("connection_string: malformed segment %q", redactSegment(part))
		}
		kv[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	if _, ok := kv["sharedaccesssignature"]; ok {
		return credentials{}, errors.New("connection_string: SharedAccessSignature is not supported, use an account key")
	}
	if strings.EqualFold(kv["usedevelopmentstorage"], "true") {
		blob := DevBlobURL
		if proxy := kv["developmentstorageproxyuri"]; proxy != "" {
			blob = strings.TrimSuffix(proxy, "/") + "/" + DevAccountName
		}
		return newCredentials(DevAccountName, DevAccountKey, blob)
	}
	account, key := kv["accountname"], kv["accountkey"]
	if account == "" || key == "" {
		return credentials{}, errors.New("connection_string: AccountName and AccountKey are required")
	}
	blob := kv["blobendpoint"]
	if blob == "" {
		proto := kv["defaultendpointsprotocol"]
		if proto == "" {
			proto = "https"
		}
		if proto != "https" && proto != "http" {
			return credentials{}, fmt.Errorf("connection_string: DefaultEndpointsProtocol must be http or https, got %q", proto)
		}
		suffix := kv["endpointsuffix"]
		if suffix == "" {
			suffix = "core.windows.net"
		}
		blob = proto + "://" + account + ".blob." + suffix
	}
	return newCredentials(account, key, blob)
}

// redactSegment hides the value of a connection string segment, which may be
// a secret, in error messages.
func redactSegment(s string) string {
	if len(s) > 12 {
		return s[:12] + "..."
	}
	return s
}

// newCredentials validates account, base64 key and endpoint. An endpoint
// without a path whose host is an IP address or localhost (an emulator) gets
// the account appended as the first path segment (path-style URLs).
func newCredentials(account, key, endpoint string) (credentials, error) {
	if !validAccountName(account) {
		return credentials{}, fmt.Errorf("account name %q is invalid (3-24 lowercase letters and digits)", account)
	}
	k, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(k) == 0 {
		return credentials{}, errors.New("account key must be base64 encoded")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return credentials{}, fmt.Errorf("blob endpoint: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return credentials{}, fmt.Errorf("blob endpoint must be an absolute http(s) URL, got %q", endpoint)
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return credentials{}, fmt.Errorf("blob endpoint must not have a query, fragment or user info, got %q", endpoint)
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawPath = ""
	if u.Path == "" && isLocalHost(u.Hostname()) {
		u.Path = "/" + account
	}
	return credentials{Account: account, Key: k, Endpoint: u}, nil
}

func isLocalHost(h string) bool {
	return h == "localhost" || net.ParseIP(h) != nil
}

func validAccountName(s string) bool {
	if len(s) < 3 || len(s) > 24 {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

// apiError is an error response of the Blob service.
type apiError struct {
	Status  int
	Code    string // x-ms-error-code, e.g. "ContainerNotFound"
	Message string
}

func (e *apiError) Error() string {
	msg := e.Message
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		msg = msg[:i] // drop the RequestId/Time lines
	}
	if msg == "" {
		return fmt.Sprintf("blob service: %d %s", e.Status, e.Code)
	}
	return fmt.Sprintf("blob service: %d %s: %s", e.Status, e.Code, strings.TrimSpace(msg))
}

// errCode returns the Blob service error code of err ("" if none).
func errCode(err error) string {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.Code
	}
	return ""
}

// client is a minimal Blob service client using Shared Key authorization.
type client struct {
	http  *http.Client
	creds credentials
	now   func() time.Time
}

// containerURL returns the URL of container ("" for the account root) with
// query.
func (c *client) containerURL(container string, query url.Values) *url.URL {
	u := *c.creds.Endpoint
	u.Path = u.Path + "/" + container
	u.RawQuery = query.Encode()
	return &u
}

// do sends a signed request. Non-2xx responses are returned as *apiError
// with the body consumed; on success the caller must close the body.
func (c *client) do(ctx context.Context, method, container string, query url.Values, header http.Header, body []byte) (*http.Response, error) {
	u := c.containerURL(container, query)
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return nil, err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	if body != nil {
		req.ContentLength = int64(len(body))
	}
	req.Header.Set("x-ms-date", c.now().UTC().Format(http.TimeFormat))
	req.Header.Set("x-ms-version", APIVersion)
	sign(req, c.creds.Account, c.creds.Key)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp, nil
	}
	defer resp.Body.Close()
	ae := &apiError{Status: resp.StatusCode, Code: resp.Header.Get("x-ms-error-code")}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	var xe struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	if xml.Unmarshal(raw, &xe) == nil {
		if ae.Code == "" {
			ae.Code = xe.Code
		}
		ae.Message = xe.Message
	}
	if ae.Code == "" {
		ae.Code = http.StatusText(resp.StatusCode)
	}
	return nil, ae
}

// drain discards and closes a response body.
func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBody))
	resp.Body.Close()
}

// sign adds the SharedKey Authorization header to req. x-ms-date and
// x-ms-version must already be set.
func sign(req *http.Request, account string, key []byte) {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(stringToSign(req, account)))
	req.Header.Set("Authorization", "SharedKey "+account+":"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
}

// stringToSign builds the Shared Key string-to-sign of the Blob service
// (versions 2015-02-21 and later: a zero Content-Length is an empty line).
// See https://learn.microsoft.com/rest/api/storageservices/authorize-with-shared-key.
func stringToSign(req *http.Request, account string) string {
	h := req.Header
	length := ""
	if req.ContentLength > 0 {
		length = strconv.FormatInt(req.ContentLength, 10)
	}
	var b strings.Builder
	for _, v := range []string{
		req.Method,
		h.Get("Content-Encoding"),
		h.Get("Content-Language"),
		length,
		h.Get("Content-MD5"),
		h.Get("Content-Type"),
		h.Get("Date"),
		h.Get("If-Modified-Since"),
		h.Get("If-Match"),
		h.Get("If-None-Match"),
		h.Get("If-Unmodified-Since"),
		h.Get("Range"),
	} {
		b.WriteString(v)
		b.WriteByte('\n')
	}
	b.WriteString(canonicalizedHeaders(h))
	b.WriteString(canonicalizedResource(req.URL, account))
	return b.String()
}

// canonicalizedHeaders returns the x-ms-* headers, lowercased and sorted, one
// "name:value\n" line each.
func canonicalizedHeaders(h http.Header) string {
	vals := map[string][]string{}
	for k, v := range h {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-ms-") {
			vals[lk] = append(vals[lk], v...)
		}
	}
	var b strings.Builder
	for _, k := range slices.Sorted(maps.Keys(vals)) {
		vs := make([]string, len(vals[k]))
		for i, v := range vals[k] {
			vs[i] = strings.Join(strings.Fields(v), " ")
		}
		b.WriteString(k + ":" + strings.Join(vs, ",") + "\n")
	}
	return b.String()
}

// canonicalizedResource returns "/<account><path>" followed by one
// "\n<name>:<values>" line per query parameter, sorted by lowercased name.
func canonicalizedResource(u *url.URL, account string) string {
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	var b strings.Builder
	b.WriteString("/" + account + path)
	q := map[string][]string{}
	for k, v := range u.Query() {
		lk := strings.ToLower(k)
		q[lk] = append(q[lk], v...)
	}
	for _, k := range slices.Sorted(maps.Keys(q)) {
		vs := slices.Clone(q[k])
		slices.Sort(vs)
		b.WriteString("\n" + k + ":" + strings.Join(vs, ","))
	}
	return b.String()
}

// Metadata header prefix.
const metaPrefix = "x-ms-meta-"

// containerProps are the properties of a container that matter here.
type containerProps struct {
	Metadata     map[string]string // names lowercased
	PublicAccess string            // "none", "blob" or "container"
	LastModified string            // HTTP date, for conditional requests
}

// getContainer returns the properties of container, or ok=false if it does
// not exist.
func (c *client) getContainer(ctx context.Context, container string) (containerProps, bool, error) {
	resp, err := c.do(ctx, http.MethodHead, container, url.Values{"restype": {"container"}}, nil, nil)
	if errCode(err) == "ContainerNotFound" {
		return containerProps{}, false, nil
	} else if err != nil {
		return containerProps{}, false, fmt.Errorf("get container %s: %w", container, err)
	}
	drain(resp)
	props := containerProps{
		Metadata:     map[string]string{},
		PublicAccess: resp.Header.Get("x-ms-blob-public-access"),
		LastModified: resp.Header.Get("Last-Modified"),
	}
	if props.PublicAccess == "" {
		props.PublicAccess = PublicAccessNone
	}
	for k, v := range resp.Header {
		lk := strings.ToLower(k)
		if name, ok := strings.CutPrefix(lk, metaPrefix); ok && len(v) > 0 {
			props.Metadata[name] = v[0]
		}
	}
	return props, true, nil
}

// metaHeader returns metadata as x-ms-meta-* headers. Keys are set without
// MIME canonicalization so Azure stores the names as given.
func metaHeader(meta map[string]string) http.Header {
	h := http.Header{}
	for k, v := range meta {
		h[metaPrefix+k] = []string{v}
	}
	return h
}

// createContainer creates container with metadata and public access level.
func (c *client) createContainer(ctx context.Context, container string, meta map[string]string, access string) error {
	h := metaHeader(meta)
	if access != PublicAccessNone {
		h.Set("x-ms-blob-public-access", access)
	}
	resp, err := c.do(ctx, http.MethodPut, container, url.Values{"restype": {"container"}}, h, nil)
	if err != nil {
		return err
	}
	drain(resp)
	return nil
}

// setMetadata replaces all metadata of container.
func (c *client) setMetadata(ctx context.Context, container string, meta map[string]string) error {
	resp, err := c.do(ctx, http.MethodPut, container,
		url.Values{"restype": {"container"}, "comp": {"metadata"}}, metaHeader(meta), nil)
	if err != nil {
		return fmt.Errorf("set metadata of %s: %w", container, err)
	}
	drain(resp)
	return nil
}

// setPublicAccess changes the public access level of container, preserving
// its stored access policies (Set Container ACL replaces both).
func (c *client) setPublicAccess(ctx context.Context, container, access string) error {
	q := url.Values{"restype": {"container"}, "comp": {"acl"}}
	resp, err := c.do(ctx, http.MethodGet, container, q, nil, nil)
	if err != nil {
		return fmt.Errorf("get ACL of %s: %w", container, err)
	}
	acl, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("get ACL of %s: %w", container, err)
	}
	h := http.Header{}
	if access != PublicAccessNone {
		h.Set("x-ms-blob-public-access", access)
	}
	var body []byte
	if len(bytes.TrimSpace(acl)) > 0 {
		body = acl
		h.Set("Content-Type", "application/xml")
	}
	resp, err = c.do(ctx, http.MethodPut, container, q, h, body)
	if err != nil {
		return fmt.Errorf("set public access of %s: %w", container, err)
	}
	drain(resp)
	return nil
}

// isEmpty reports whether container holds no blob.
func (c *client) isEmpty(ctx context.Context, container string) (bool, error) {
	resp, err := c.do(ctx, http.MethodGet, container,
		url.Values{"restype": {"container"}, "comp": {"list"}, "maxresults": {"1"}}, nil, nil)
	if err != nil {
		return false, fmt.Errorf("list blobs of %s: %w", container, err)
	}
	defer resp.Body.Close()
	var res struct {
		Blobs struct {
			Blob []struct {
				Name string `xml:"Name"`
			} `xml:"Blob"`
		} `xml:"Blobs"`
	}
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&res); err != nil {
		return false, fmt.Errorf("list blobs of %s: %w", container, err)
	}
	return len(res.Blobs.Blob) == 0, nil
}

// deleteContainer marks container for deletion. With unmodifiedSince set,
// the request fails with ConditionNotMet if the container changed since.
func (c *client) deleteContainer(ctx context.Context, container, unmodifiedSince string) error {
	h := http.Header{}
	if unmodifiedSince != "" {
		h.Set("If-Unmodified-Since", unmodifiedSince)
	}
	resp, err := c.do(ctx, http.MethodDelete, container, url.Values{"restype": {"container"}}, h, nil)
	if err != nil {
		return err
	}
	drain(resp)
	return nil
}

// listContainers lists at most one container; it checks reachability and
// credentials.
func (c *client) listContainers(ctx context.Context) error {
	resp, err := c.do(ctx, http.MethodGet, "", url.Values{"comp": {"list"}, "maxresults": {"1"}}, nil, nil)
	if err != nil {
		return err
	}
	drain(resp)
	return nil
}
