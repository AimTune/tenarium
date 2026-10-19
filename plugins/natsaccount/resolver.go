package natsaccount

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

// resolver stores account JWTs where NATS servers find them.
type resolver interface {
	// Lookup returns the JWT stored for the account, or "" if none.
	Lookup(ctx context.Context, pub string) (string, error)
	// Push stores (creates or replaces) an account JWT.
	Push(ctx context.Context, pub, token string) error
	// Delete sends an operator-signed delete request. It returns an error
	// wrapping errDeleteUnsupported when the resolver cannot delete.
	Delete(ctx context.Context, request string) error
	Health(ctx context.Context) error
	Close() error
}

// errDeleteUnsupported means the resolver does not allow deleting accounts.
var errDeleteUnsupported = errors.New("resolver does not support deleting accounts")

// NATS system subjects of the account resolver.
const (
	subjClaimsUpdate = "$SYS.REQ.CLAIMS.UPDATE"
	subjClaimsDelete = "$SYS.REQ.CLAIMS.DELETE"
	subjClaimsLookup = "$SYS.REQ.ACCOUNT.%s.CLAIMS.LOOKUP"
)

// natsResolver talks to the "full" or "cache" resolver of NATS servers
// through the system account. It connects lazily, so Init never touches the
// network.
type natsResolver struct {
	cfg     *ResolverConfig
	timeout time.Duration

	mu sync.Mutex
	nc *nats.Conn
}

func newNATSResolver(cfg *ResolverConfig, timeout time.Duration) *natsResolver {
	return &natsResolver{cfg: cfg, timeout: timeout}
}

func (r *natsResolver) conn() (*nats.Conn, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.nc != nil && !r.nc.IsClosed() {
		return r.nc, nil
	}
	c := r.cfg
	opts := []nats.Option{
		nats.Name("tenarium-nats-tenant"),
		nats.Timeout(r.timeout),
		nats.MaxReconnects(-1),
		nats.NoEcho(),
	}
	switch {
	case c.CredentialsFile != "":
		opts = append(opts, nats.UserCredentials(c.CredentialsFile))
	case c.UserJWT != "":
		opts = append(opts, nats.UserJWTAndSeed(strings.TrimSpace(c.UserJWT), strings.TrimSpace(c.UserSeed)))
	case c.User != "":
		opts = append(opts, nats.UserInfo(c.User, c.Password))
	case c.Token != "":
		opts = append(opts, nats.Token(c.Token))
	}
	if c.CAFile != "" {
		opts = append(opts, nats.RootCAs(c.CAFile))
	}
	nc, err := nats.Connect(strings.Join(c.URLs, ","), opts...)
	if err != nil {
		return nil, fmt.Errorf("connect to NATS: %w", err)
	}
	r.nc = nc
	return nc, nil
}

func (r *natsResolver) request(ctx context.Context, subj string, data []byte) ([]byte, error) {
	nc, err := r.conn()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	msg, err := nc.RequestWithContext(ctx, subj, data)
	if errors.Is(err, nats.ErrNoResponders) {
		return nil, fmt.Errorf("no NATS server answered %s: the servers need the full (or cache) account resolver and the credentials must be a system account user", subj)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", subj, err)
	}
	return msg.Data, nil
}

// claimsResponse is the server's answer to CLAIMS.UPDATE/DELETE requests.
type claimsResponse struct {
	Data *struct {
		Account string `json:"account"`
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"data"`
	Error *struct {
		Account     string `json:"account"`
		Code        int    `json:"code"`
		Description string `json:"description"`
	} `json:"error"`
}

func parseClaimsResponse(b []byte) error {
	var resp claimsResponse
	if err := json.Unmarshal(b, &resp); err != nil {
		return fmt.Errorf("unexpected resolver response %q: %w", truncate(string(b)), err)
	}
	if resp.Error != nil {
		if strings.Contains(resp.Error.Description, "delete must be enabled") {
			return fmt.Errorf("%w: %s", errDeleteUnsupported, resp.Error.Description)
		}
		return fmt.Errorf("resolver error %d: %s", resp.Error.Code, resp.Error.Description)
	}
	if resp.Data == nil {
		return fmt.Errorf("unexpected resolver response %q", truncate(string(b)))
	}
	if resp.Data.Code != 0 && resp.Data.Code != http.StatusOK {
		return fmt.Errorf("resolver answered %d: %s", resp.Data.Code, resp.Data.Message)
	}
	return nil
}

func (r *natsResolver) Lookup(ctx context.Context, pub string) (string, error) {
	b, err := r.request(ctx, fmt.Sprintf(subjClaimsLookup, pub), nil)
	if err != nil {
		return "", err
	}
	// The resolver answers with the raw JWT, or an empty message when it
	// does not know the account.
	s := strings.TrimSpace(string(b))
	if strings.HasPrefix(s, "{") {
		return "", parseClaimsResponse(b)
	}
	return s, nil
}

func (r *natsResolver) Push(ctx context.Context, _ string, token string) error {
	b, err := r.request(ctx, subjClaimsUpdate, []byte(token))
	if err != nil {
		return err
	}
	return parseClaimsResponse(b)
}

func (r *natsResolver) Delete(ctx context.Context, request string) error {
	b, err := r.request(ctx, subjClaimsDelete, []byte(request))
	if err != nil {
		return err
	}
	return parseClaimsResponse(b)
}

func (r *natsResolver) Health(ctx context.Context) error {
	nc, err := r.conn()
	if err != nil {
		return err
	}
	if !nc.IsConnected() {
		return fmt.Errorf("NATS connection is %s", nc.Status())
	}
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	return nc.FlushWithContext(ctx)
}

func (r *natsResolver) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.nc != nil {
		r.nc.Close()
		r.nc = nil
	}
	return nil
}

// httpResolver talks to the nats-account-server HTTP API:
// GET/POST {url}/accounts/{pub}.
type httpResolver struct {
	base   string
	token  string
	client *http.Client
}

func newHTTPResolver(cfg *ResolverConfig, timeout time.Duration) (*httpResolver, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("resolver.ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("resolver.ca_file: no PEM certificates found")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &httpResolver{
		base:   cfg.URL,
		token:  cfg.Token,
		client: &http.Client{Timeout: timeout, Transport: tr},
	}, nil
}

// resolverReply is the status and (size-capped) body of an account server reply.
// The response body is fully read and closed by do.
type resolverReply struct {
	StatusCode int
	Status     string
	Body       []byte
}

func (r *httpResolver) do(ctx context.Context, method, url string, body io.Reader) (resolverReply, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return resolverReply{}, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/jwt")
	}
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return resolverReply{}, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resolverReply{}, err
	}
	return resolverReply{StatusCode: resp.StatusCode, Status: resp.Status, Body: b}, nil
}

func (r *httpResolver) Lookup(ctx context.Context, pub string) (string, error) {
	resp, err := r.do(ctx, http.MethodGet, r.base+"/accounts/"+pub, nil)
	if err != nil {
		return "", err
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return "", nil
	case resp.StatusCode == http.StatusOK:
		return strings.TrimSpace(string(resp.Body)), nil
	default:
		return "", fmt.Errorf("GET account: %s: %s", resp.Status, truncate(strings.TrimSpace(string(resp.Body))))
	}
}

func (r *httpResolver) Push(ctx context.Context, pub, token string) error {
	resp, err := r.do(ctx, http.MethodPost, r.base+"/accounts/"+pub, strings.NewReader(token))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("POST account: %s: %s", resp.Status, truncate(strings.TrimSpace(string(resp.Body))))
	}
	return nil
}

func (r *httpResolver) Delete(context.Context, string) error {
	return fmt.Errorf("%w: the account server has no delete API", errDeleteUnsupported)
}

func (r *httpResolver) Health(ctx context.Context) error {
	resp, err := r.do(ctx, http.MethodGet, r.base, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 500 {
		return fmt.Errorf("account server: %s: %s", resp.Status, truncate(strings.TrimSpace(string(resp.Body))))
	}
	return nil
}

func (r *httpResolver) Close() error {
	r.client.CloseIdleConnections()
	return nil
}

// maxErrorBody caps how much of a resolver reply is quoted in an error.
const maxErrorBody = 200

func truncate(s string) string {
	if len(s) > maxErrorBody {
		return s[:maxErrorBody] + "..."
	}
	return s
}
