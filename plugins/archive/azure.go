package archive

import (
	"bytes"
	"cmp"
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

// azureAPIVersion is the Blob service REST API version (x-ms-version).
const azureAPIVersion = "2023-11-03"

// Azurite (storage emulator) well-known development account.
const (
	azureDevAccount = "devstoreaccount1"
	azureDevKey     = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
	azureDevBlobURL = "http://127.0.0.1:10000/devstoreaccount1"
)

// azureStore is a minimal Blob service client with Shared Key
// authorization, like the one of the azure-blob plugin.
type azureStore struct {
	http      *http.Client
	account   string
	key       []byte
	endpoint  *url.URL // blob service endpoint, no trailing slash
	container string
	now       func() time.Time
}

func newAzureStore(c AzureConfig, timeout time.Duration) (*azureStore, error) {
	if c.Container == "" {
		return nil, errors.New("azure.container is required")
	}
	var (
		account, key, endpoint string
		err                    error
	)
	switch {
	case c.ConnectionString != "" && (c.AccountName != "" || c.AccountKey != "" || c.Endpoint != ""):
		return nil, errors.New("set either azure.connection_string or azure.account_name/account_key/endpoint")
	case c.ConnectionString != "":
		if account, key, endpoint, err = parseAzureConnectionString(c.ConnectionString); err != nil {
			return nil, err
		}
	case c.AccountName != "" && c.AccountKey != "":
		account, key, endpoint = c.AccountName, c.AccountKey, c.Endpoint
		if endpoint == "" {
			endpoint = "https://" + account + ".blob.core.windows.net"
		}
	default:
		return nil, errors.New("azure needs connection_string or account_name and account_key")
	}
	k, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(k) == 0 {
		return nil, errors.New("azure account key must be base64 encoded")
	}
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, fmt.Errorf("azure blob endpoint must be an absolute http(s) URL, got %q", endpoint)
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawPath = ""
	if h := u.Hostname(); u.Path == "" && (h == "localhost" || net.ParseIP(h) != nil) {
		u.Path = "/" + account // emulators use path-style URLs
	}
	return &azureStore{
		http: &http.Client{Timeout: timeout}, account: account, key: k, endpoint: u,
		container: c.Container, now: time.Now,
	}, nil
}

// parseAzureConnectionString supports DefaultEndpointsProtocol, AccountName,
// AccountKey, EndpointSuffix, BlobEndpoint and UseDevelopmentStorage=true.
func parseAzureConnectionString(s string) (account, key, endpoint string, err error) {
	kv := map[string]string{}
	for part := range strings.SplitSeq(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return "", "", "", errors.New("azure.connection_string: malformed segment")
		}
		kv[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	if _, ok := kv["sharedaccesssignature"]; ok {
		return "", "", "", errors.New("azure.connection_string: SharedAccessSignature is not supported, use an account key")
	}
	if strings.EqualFold(kv["usedevelopmentstorage"], "true") {
		blob := azureDevBlobURL
		if proxy := kv["developmentstorageproxyuri"]; proxy != "" {
			blob = strings.TrimSuffix(proxy, "/") + "/" + azureDevAccount
		}
		return azureDevAccount, azureDevKey, blob, nil
	}
	account, key = kv["accountname"], kv["accountkey"]
	if account == "" || key == "" {
		return "", "", "", errors.New("azure.connection_string: AccountName and AccountKey are required")
	}
	endpoint = kv["blobendpoint"]
	if endpoint == "" {
		proto := cmp.Or(kv["defaultendpointsprotocol"], "https")
		if proto != "https" && proto != "http" {
			return "", "", "", fmt.Errorf("azure.connection_string: DefaultEndpointsProtocol must be http or https, got %q", proto)
		}
		endpoint = proto + "://" + account + ".blob." + cmp.Or(kv["endpointsuffix"], "core.windows.net")
	}
	return account, key, endpoint, nil
}

// azureError is an error response of the Blob service.
type azureError struct {
	Status int
	Code   string
}

func (e *azureError) Error() string { return fmt.Sprintf("blob service: %d %s", e.Status, e.Code) }

func azureCode(err error) string {
	var e *azureError
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// do sends a signed request to {container}/{blob} (blob may be empty) and
// returns the body of a 2xx response, read up to limit.
func (s *azureStore) do(ctx context.Context, method, blob string, query url.Values, header http.Header, body []byte, limit int64) ([]byte, error) {
	u := *s.endpoint
	u.Path += "/" + s.container
	if blob != "" {
		u.Path += "/" + blob
	}
	u.RawQuery = query.Encode()
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
	req.Header.Set("x-ms-date", s.now().UTC().Format(http.TimeFormat))
	req.Header.Set("x-ms-version", azureAPIVersion)
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(azureStringToSign(req, s.account)))
	req.Header.Set("Authorization", "SharedKey "+s.account+":"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		ae := &azureError{Status: resp.StatusCode, Code: resp.Header.Get("x-ms-error-code")}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		var xe struct {
			Code string `xml:"Code"`
		}
		if ae.Code == "" && xml.Unmarshal(raw, &xe) == nil {
			ae.Code = xe.Code
		}
		if ae.Code == "" {
			ae.Code = http.StatusText(resp.StatusCode)
		}
		return nil, ae
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// azureStringToSign builds the Shared Key string-to-sign of the Blob service.
// See https://learn.microsoft.com/rest/api/storageservices/authorize-with-shared-key.
func azureStringToSign(req *http.Request, account string) string {
	h := req.Header
	length := ""
	if req.ContentLength > 0 {
		length = strconv.FormatInt(req.ContentLength, 10)
	}
	var b strings.Builder
	for _, v := range []string{
		req.Method, h.Get("Content-Encoding"), h.Get("Content-Language"), length, h.Get("Content-MD5"),
		h.Get("Content-Type"), h.Get("Date"), h.Get("If-Modified-Since"), h.Get("If-Match"),
		h.Get("If-None-Match"), h.Get("If-Unmodified-Since"), h.Get("Range"),
	} {
		b.WriteString(v)
		b.WriteByte('\n')
	}
	vals := map[string][]string{}
	for k, v := range h {
		if lk := strings.ToLower(k); strings.HasPrefix(lk, "x-ms-") {
			vals[lk] = append(vals[lk], v...)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(vals)) {
		b.WriteString(k + ":" + strings.Join(vals[k], ",") + "\n")
	}
	p := req.URL.EscapedPath()
	if p == "" {
		p = "/"
	}
	b.WriteString("/" + account + p)
	q := map[string][]string{}
	for k, v := range req.URL.Query() {
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

func (s *azureStore) Put(ctx context.Context, key string, body []byte, contentType string) error {
	h := http.Header{}
	h.Set("x-ms-blob-type", "BlockBlob")
	h.Set("Content-Type", contentType)
	_, err := s.do(ctx, http.MethodPut, key, nil, h, body, 1<<20)
	return err
}

func (s *azureStore) Get(ctx context.Context, key string) ([]byte, error) {
	b, err := s.do(ctx, http.MethodGet, key, nil, nil, nil, maxObjectSize)
	if azureCode(err) == "BlobNotFound" {
		return nil, fmt.Errorf("%s: %w", key, errNotFound)
	}
	return b, err
}

func (s *azureStore) Delete(ctx context.Context, key string) error {
	_, err := s.do(ctx, http.MethodDelete, key, nil, nil, nil, 1<<20)
	if azureCode(err) == "BlobNotFound" {
		return nil
	}
	return err
}

func (s *azureStore) List(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	marker := ""
	for {
		q := url.Values{"restype": {"container"}, "comp": {"list"}, "prefix": {prefix}, "maxresults": {"5000"}}
		if marker != "" {
			q.Set("marker", marker)
		}
		raw, err := s.do(ctx, http.MethodGet, "", q, nil, nil, 64<<20)
		if err != nil {
			return nil, err
		}
		var res struct {
			Blobs struct {
				Blob []struct {
					Name string `xml:"Name"`
				} `xml:"Blob"`
			} `xml:"Blobs"`
			NextMarker string `xml:"NextMarker"`
		}
		if err := xml.Unmarshal(raw, &res); err != nil {
			return nil, fmt.Errorf("blob service: list: %w", err)
		}
		for _, b := range res.Blobs.Blob {
			keys = append(keys, b.Name)
		}
		if res.NextMarker == "" {
			return keys, nil
		}
		marker = res.NextMarker
	}
}

func (s *azureStore) Check(ctx context.Context) error {
	_, err := s.do(ctx, http.MethodHead, "", url.Values{"restype": {"container"}}, nil, nil, 0)
	return err
}
