package extplugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// RESTHost implements sdk.Host over the Tenarium REST API. External plugins
// get one configured from TENARIUM_API_URL and TENARIUM_API_KEY.
type RESTHost struct {
	BaseURL string
	APIKey  string
	Client  *http.Client
}

var _ sdk.Host = (*RESTHost)(nil)

// HostFromEnv returns a RESTHost from the environment, or a host whose
// methods fail with a clear error if TENARIUM_API_URL is unset.
func HostFromEnv() sdk.Host {
	u := os.Getenv(EnvAPIURL)
	if u == "" {
		return unconfiguredHost{}
	}
	return &RESTHost{BaseURL: strings.TrimRight(u, "/"), APIKey: os.Getenv(EnvAPIKey), Client: &http.Client{Timeout: 10 * time.Second}}
}

func (h *RESTHost) get(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.BaseURL+path, nil)
	if err != nil {
		return err
	}
	if h.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+h.APIKey)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return sdk.ErrNotFound
	case resp.StatusCode >= 300:
		return fmt.Errorf("tenarium api %s: %s", path, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func (h *RESTHost) GetTenant(ctx context.Context, idOrSlug string) (sdk.Tenant, error) {
	var t sdk.Tenant
	return t, h.get(ctx, "/v1/tenants/"+url.PathEscape(idOrSlug), &t)
}

func (h *RESTHost) ListTenants(ctx context.Context, after string, limit int) ([]sdk.Tenant, error) {
	q := url.Values{}
	if after != "" {
		q.Set("after", after)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(min(limit, 500)))
	}
	var page struct {
		Items []sdk.Tenant `json:"items"`
	}
	return page.Items, h.get(ctx, "/v1/tenants?"+q.Encode(), &page)
}

func (h *RESTHost) GetPlan(ctx context.Context, id string) (sdk.Plan, error) {
	var p sdk.Plan
	return p, h.get(ctx, "/v1/plans/"+url.PathEscape(id), &p)
}

func (h *RESTHost) Entitlements(ctx context.Context, tenantID string) (sdk.Entitlements, error) {
	var e sdk.Entitlements
	return e, h.get(ctx, "/v1/tenants/"+url.PathEscape(tenantID)+"/entitlements", &e)
}

// Authorize is not available out of process: the plugin sees the caller in
// X-Tenarium-Principal and must apply its own tenant check (for example,
// compare Principal.TenantID with the requested tenant).
func (h *RESTHost) Authorize(context.Context, sdk.Action, sdk.Resource) error {
	return errNoAuthorize
}

var errNoAuthorize = fmt.Errorf("%w: Host.Authorize is not available to external plugins", sdk.ErrForbidden)

var errNoHost = errors.New("tenarium host API unavailable: set " + EnvAPIURL + " (and " + EnvAPIKey + ")")

type unconfiguredHost struct{}

func (unconfiguredHost) GetTenant(context.Context, string) (sdk.Tenant, error) {
	return sdk.Tenant{}, errNoHost
}
func (unconfiguredHost) ListTenants(context.Context, string, int) ([]sdk.Tenant, error) {
	return nil, errNoHost
}
func (unconfiguredHost) GetPlan(context.Context, string) (sdk.Plan, error) {
	return sdk.Plan{}, errNoHost
}
func (unconfiguredHost) Entitlements(context.Context, string) (sdk.Entitlements, error) {
	return sdk.Entitlements{}, errNoHost
}
func (unconfiguredHost) Authorize(context.Context, sdk.Action, sdk.Resource) error {
	return errNoAuthorize
}

func (h *RESTHost) GetUser(ctx context.Context, idOrEmail string) (sdk.User, error) {
	var u sdk.User
	return u, h.get(ctx, "/v1/users/"+url.PathEscape(idOrEmail), &u)
}

func (unconfiguredHost) GetUser(context.Context, string) (sdk.User, error) {
	return sdk.User{}, errNoHost
}

func (h unconfiguredHost) SuspendTenant(context.Context, string, string) (sdk.Tenant, error) {
	return sdk.Tenant{}, errNoHost
}
func (h unconfiguredHost) ResumeTenant(context.Context, string) (sdk.Tenant, error) {
	return sdk.Tenant{}, errNoHost
}
func (h unconfiguredHost) SetTenantPlan(context.Context, string, string) (sdk.Tenant, error) {
	return sdk.Tenant{}, errNoHost
}
func (h unconfiguredHost) RecordUsage(context.Context, string, string, int64) (int64, error) {
	return 0, errNoHost
}

func (h *RESTHost) post(ctx context.Context, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.BaseURL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if h.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+h.APIKey)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return sdk.ErrNotFound
	case resp.StatusCode >= 300:
		return fmt.Errorf("tenarium api %s: %s", path, resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (h *RESTHost) SuspendTenant(ctx context.Context, idOrSlug, reason string) (sdk.Tenant, error) {
	var t sdk.Tenant
	return t, h.post(ctx, "/v1/tenants/"+url.PathEscape(idOrSlug)+"/suspend", map[string]string{"reason": reason}, &t)
}

func (h *RESTHost) ResumeTenant(ctx context.Context, idOrSlug string) (sdk.Tenant, error) {
	var t sdk.Tenant
	return t, h.post(ctx, "/v1/tenants/"+url.PathEscape(idOrSlug)+"/resume", map[string]string{}, &t)
}

func (h *RESTHost) SetTenantPlan(ctx context.Context, idOrSlug, plan string) (sdk.Tenant, error) {
	b, _ := json.Marshal(map[string]string{"plan": plan})
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, h.BaseURL+"/v1/tenants/"+url.PathEscape(idOrSlug), bytes.NewReader(b))
	if err != nil {
		return sdk.Tenant{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if h.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+h.APIKey)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		return sdk.Tenant{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return sdk.Tenant{}, fmt.Errorf("tenarium api set plan: %s", resp.Status)
	}
	var t sdk.Tenant
	return t, json.NewDecoder(resp.Body).Decode(&t)
}

func (h *RESTHost) RecordUsage(ctx context.Context, idOrSlug, metric string, delta int64) (int64, error) {
	var out struct {
		Value int64 `json:"value"`
	}
	err := h.post(ctx, "/v1/tenants/"+url.PathEscape(idOrSlug)+"/usage/"+url.PathEscape(metric), map[string]int64{"delta": delta}, &out)
	return out.Value, err
}
