package grafanatenant

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// do calls the Grafana API. orgID, when non-zero, is sent as
// X-Grafana-Org-Id to run an org-scoped call in that organization (the
// caller must be a member). query is a list of key, value pairs.
func (p *Plugin) do(ctx context.Context, method, path string, orgID int64, in any, query ...string) (int, []byte, error) {
	var payload io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, nil, err
		}
		payload = bytes.NewReader(b)
	}
	target := p.base.String() + path
	if len(query) > 0 {
		q := url.Values{}
		for i := 0; i+1 < len(query); i += 2 {
			q.Add(query[i], query[i+1])
		}
		target += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, target, payload)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if p.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+p.cfg.Token)
	} else {
		req.SetBasicAuth(p.cfg.Username, p.cfg.Password)
	}
	if orgID != 0 {
		req.Header.Set("X-Grafana-Org-Id", strconv.FormatInt(orgID, 10))
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("grafana: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return 0, nil, fmt.Errorf("grafana: %s %s: %w", method, path, err)
	}
	return resp.StatusCode, body, nil
}

// call runs do and decodes a successful JSON response into out (if not
// nil). Statuses in ok besides 2xx are accepted and returned.
func (p *Plugin) call(ctx context.Context, op, method, path string, orgID int64, in, out any, ok ...int) (int, error) {
	status, body, err := p.do(ctx, method, path, orgID, in)
	if err != nil {
		return 0, err
	}
	if status/100 == 2 {
		if out != nil && len(body) > 0 {
			if err := json.Unmarshal(body, out); err != nil {
				return status, fmt.Errorf("grafana: %s: %w", op, err)
			}
		}
		return status, nil
	}
	for _, s := range ok {
		if status == s {
			return status, nil
		}
	}
	return status, apiError(op, status, body)
}

// APIError is a non-successful Grafana response.
type APIError struct {
	Op      string
	Status  int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("grafana: %s: %s: %s", e.Op, http.StatusText(e.Status), e.Message)
}

func apiError(op string, status int, body []byte) error {
	var m struct {
		Message string `json:"message"`
	}
	msg := strings.TrimSpace(string(body))
	if json.Unmarshal(body, &m) == nil && m.Message != "" {
		msg = m.Message
	}
	if len(msg) > 512 {
		msg = msg[:512]
	}
	return &APIError{Op: op, Status: status, Message: msg}
}

// isLastAdmin reports whether err is Grafana refusing to remove or demote
// an organization's last admin.
func isLastAdmin(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusBadRequest &&
		strings.Contains(strings.ToLower(ae.Message), "last")
}

// address is a Grafana organization address; tenarium uses it as the
// ownership marker.
type address struct {
	Address1 string `json:"address1"`
	Address2 string `json:"address2"`
	City     string `json:"city"`
	ZipCode  string `json:"zipCode"`
	State    string `json:"state"`
	Country  string `json:"country"`
}

type org struct {
	ID      int64   `json:"id"`
	Name    string  `json:"name"`
	Address address `json:"address"`
}

// owner returns the tenant ID the organization is marked for, or "".
func (o *org) owner() string {
	if id, ok := strings.CutPrefix(o.Address.Address1, MarkerOwner); ok {
		return id
	}
	return ""
}

// retainedFrom returns the deleted tenant the organization was retained
// from, or "".
func (o *org) retainedFrom() string {
	if id, ok := strings.CutPrefix(o.Address.Address1, MarkerDeleted); ok {
		return id
	}
	return ""
}

func orgPath(id int64) string { return "/api/orgs/" + strconv.FormatInt(id, 10) }

// orgByName returns the organization named name, or nil.
func (p *Plugin) orgByName(ctx context.Context, name string) (*org, error) {
	var o org
	status, err := p.call(ctx, "get organization "+name, http.MethodGet,
		"/api/orgs/name/"+url.PathEscape(name), 0, nil, &o, http.StatusNotFound)
	if err != nil || status == http.StatusNotFound {
		return nil, err
	}
	return &o, nil
}

// createOrg creates an organization and returns its ID, or 0 if the name is
// taken.
func (p *Plugin) createOrg(ctx context.Context, name string) (int64, error) {
	var out struct {
		OrgID int64 `json:"orgId"`
	}
	status, err := p.call(ctx, "create organization "+name, http.MethodPost, "/api/orgs", 0,
		map[string]string{"name": name}, &out, http.StatusConflict)
	if err != nil || status == http.StatusConflict {
		return 0, err
	}
	return out.OrgID, nil
}

func (p *Plugin) setAddress(ctx context.Context, id int64, a address) error {
	_, err := p.call(ctx, "set address of organization "+strconv.FormatInt(id, 10),
		http.MethodPut, orgPath(id)+"/address", 0, a, nil)
	return err
}

func (p *Plugin) renameOrg(ctx context.Context, id int64, name string) error {
	_, err := p.call(ctx, "rename organization "+strconv.FormatInt(id, 10),
		http.MethodPut, orgPath(id), 0, map[string]string{"name": name}, nil)
	return err
}

func (p *Plugin) deleteOrg(ctx context.Context, id int64) error {
	_, err := p.call(ctx, "delete organization "+strconv.FormatInt(id, 10),
		http.MethodDelete, orgPath(id), 0, nil, nil, http.StatusNotFound)
	return err
}

type orgUser struct {
	UserID int64  `json:"userId"`
	Login  string `json:"login"`
	Email  string `json:"email"`
	Role   string `json:"role"`
}

func (p *Plugin) orgUsers(ctx context.Context, id int64) ([]orgUser, error) {
	var users []orgUser
	_, err := p.call(ctx, "list users of organization "+strconv.FormatInt(id, 10),
		http.MethodGet, orgPath(id)+"/users", 0, nil, &users)
	return users, err
}

func (p *Plugin) addOrgUser(ctx context.Context, id int64, login, role string) error {
	_, err := p.call(ctx, "add user to organization "+strconv.FormatInt(id, 10),
		http.MethodPost, orgPath(id)+"/users", 0,
		map[string]string{"loginOrEmail": login, "role": role}, nil, http.StatusConflict)
	return err
}

func (p *Plugin) setOrgUserRole(ctx context.Context, id, userID int64, role string) error {
	_, err := p.call(ctx, "update user role in organization "+strconv.FormatInt(id, 10),
		http.MethodPatch, orgPath(id)+"/users/"+strconv.FormatInt(userID, 10), 0,
		map[string]string{"role": role}, nil)
	return err
}

func (p *Plugin) removeOrgUser(ctx context.Context, id, userID int64) error {
	_, err := p.call(ctx, "remove user from organization "+strconv.FormatInt(id, 10),
		http.MethodDelete, orgPath(id)+"/users/"+strconv.FormatInt(userID, 10), 0, nil, nil,
		http.StatusNotFound)
	return err
}

type user struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Email string `json:"email"`
}

// lookupUser finds a Grafana user by login or email, or returns nil.
func (p *Plugin) lookupUser(ctx context.Context, loginOrEmail string) (*user, error) {
	status, body, err := p.do(ctx, http.MethodGet, "/api/users/lookup", 0, nil, "loginOrEmail", loginOrEmail)
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, nil
	default:
		return nil, apiError("look up user", status, body)
	}
	var u user
	if err := json.Unmarshal(body, &u); err != nil {
		return nil, fmt.Errorf("grafana: look up user: %w", err)
	}
	return &u, nil
}

// self returns the Grafana user ID of the plugin's own account (cached).
func (p *Plugin) self(ctx context.Context) (int64, error) {
	p.selfMu.Lock()
	defer p.selfMu.Unlock()
	if p.hasSelf {
		return p.selfID, nil
	}
	var u user
	if _, err := p.call(ctx, "get current user", http.MethodGet, "/api/user", 0, nil, &u); err != nil {
		return 0, err
	}
	p.selfID, p.hasSelf = u.ID, true
	return u.ID, nil
}

type quota struct {
	Target string `json:"target"`
	Limit  int64  `json:"limit"`
	Used   int64  `json:"used"`
}

func (p *Plugin) orgQuotas(ctx context.Context, id int64) ([]quota, error) {
	var qs []quota
	_, err := p.call(ctx, "get quotas of organization "+strconv.FormatInt(id, 10),
		http.MethodGet, orgPath(id)+"/quotas", 0, nil, &qs)
	return qs, err
}

func (p *Plugin) setQuota(ctx context.Context, id int64, target string, limit int64) error {
	_, err := p.call(ctx, "set "+target+" quota of organization "+strconv.FormatInt(id, 10),
		http.MethodPut, orgPath(id)+"/quotas/"+url.PathEscape(target), 0,
		map[string]int64{"limit": limit}, nil)
	return err
}
