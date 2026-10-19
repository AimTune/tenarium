package grafanatenant

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeGrafana is a small in-memory Grafana HTTP API covering what the
// plugin uses. User 1 ("admin") is the server admin the plugin signs in as.
type fakeGrafana struct {
	t  *testing.T
	mu sync.Mutex

	orgs       map[int64]*org
	nextOrg    int64
	users      map[int64]*user
	nextUser   int64
	members    map[int64]map[int64]string // org -> user -> role
	quotas     map[int64]map[string]int64
	used       map[int64]map[string]int64
	dashboards map[int64]int
	ds         map[int64]map[string]map[string]any
	quotaOff   bool
	calls      []string
}

func newFakeGrafana(t *testing.T) (*fakeGrafana, *httptest.Server) {
	f := &fakeGrafana{
		t:          t,
		orgs:       map[int64]*org{1: {ID: 1, Name: "Main Org."}},
		nextOrg:    2,
		users:      map[int64]*user{1: {ID: 1, Login: "admin", Email: "admin@localhost"}},
		nextUser:   2,
		members:    map[int64]map[int64]string{1: {1: RoleAdmin}},
		quotas:     map[int64]map[string]int64{},
		used:       map[int64]map[string]int64{},
		dashboards: map[int64]int{},
		ds:         map[int64]map[string]map[string]any{},
	}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeGrafana) addUser(login, email string) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := f.nextUser
	f.nextUser++
	f.users[id] = &user{ID: id, Login: login, Email: email}
	return id
}

func (f *fakeGrafana) orgNamed(name string) *org {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, o := range f.orgs {
		if o.Name == name {
			c := *o
			return &c
		}
	}
	return nil
}

func (f *fakeGrafana) role(orgID, userID int64) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.members[orgID][userID]
}

func (f *fakeGrafana) createOrg(name string) int64 {
	id := f.nextOrg
	f.nextOrg++
	f.orgs[id] = &org{ID: id, Name: name}
	f.members[id] = map[int64]string{1: RoleAdmin}
	f.quotas[id] = map[string]int64{"dashboard": 100, "data_source": 10, "org_user": 10, "api_key": 10, "alert_rule": 100}
	f.ds[id] = map[string]map[string]any{}
	return id
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func msg(w http.ResponseWriter, status int, m string) {
	writeJSON(w, status, map[string]string{"message": m})
}

func (f *fakeGrafana) admins(orgID int64) int {
	n := 0
	for _, r := range f.members[orgID] {
		if r == RoleAdmin {
			n++
		}
	}
	return n
}

func (f *fakeGrafana) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	if r.URL.Path == "/api/health" {
		writeJSON(w, 200, map[string]string{"database": "ok"})
		return
	}
	if u, pw, ok := r.BasicAuth(); !ok || u != "admin" || pw != "secret" {
		msg(w, 401, "invalid username or password")
		return
	}
	var body map[string]any
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	str := func(k string) string { s, _ := body[k].(string); return s }
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	id := func(i int) int64 {
		n, _ := strconv.ParseInt(parts[i], 10, 64)
		return n
	}
	// Org-scoped calls need membership of the X-Grafana-Org-Id org.
	scoped := int64(1)
	if h := r.Header.Get("X-Grafana-Org-Id"); h != "" {
		scoped, _ = strconv.ParseInt(h, 10, 64)
	}
	requireMember := func() bool {
		if f.members[scoped][1] == "" {
			msg(w, 403, "access denied")
			return false
		}
		return true
	}

	switch p := r.URL.Path; {
	case r.Method == "GET" && p == "/api/user":
		writeJSON(w, 200, f.users[1])
	case r.Method == "GET" && p == "/api/orgs":
		writeJSON(w, 200, []any{})
	case r.Method == "POST" && p == "/api/orgs":
		for _, o := range f.orgs {
			if o.Name == str("name") {
				msg(w, 409, "Organization name taken")
				return
			}
		}
		writeJSON(w, 200, map[string]any{"orgId": f.createOrg(str("name")), "message": "Organization created"})
	case r.Method == "GET" && strings.HasPrefix(p, "/api/orgs/name/"):
		for _, o := range f.orgs {
			if o.Name == strings.TrimPrefix(p, "/api/orgs/name/") {
				writeJSON(w, 200, o)
				return
			}
		}
		msg(w, 404, "Organization not found")
	case len(parts) >= 3 && parts[0] == "api" && parts[1] == "orgs":
		o := f.orgs[id(2)]
		if o == nil {
			msg(w, 404, "Organization not found")
			return
		}
		f.serveOrg(w, r, o, parts[3:], body)
	case r.Method == "GET" && p == "/api/users/lookup":
		q := r.URL.Query().Get("loginOrEmail")
		for _, u := range f.users {
			if u.Login == q || u.Email == q {
				writeJSON(w, 200, u)
				return
			}
		}
		msg(w, 404, "user not found")
	case r.Method == "POST" && p == "/api/admin/users":
		for _, u := range f.users {
			if u.Login == str("login") || u.Email == str("email") {
				msg(w, 412, "user already exists")
				return
			}
		}
		uid := f.nextUser
		f.nextUser++
		f.users[uid] = &user{ID: uid, Login: str("login"), Email: str("email")}
		if oid, _ := body["OrgId"].(float64); oid != 0 {
			f.members[int64(oid)][uid] = RoleViewer
		}
		writeJSON(w, 200, map[string]any{"id": uid, "message": "User created"})
	case r.Method == "GET" && p == "/api/search":
		if !requireMember() {
			return
		}
		hits := []any{}
		for range f.dashboards[scoped] {
			hits = append(hits, map[string]any{"type": "dash-db"})
		}
		writeJSON(w, 200, hits)
	case r.Method == "GET" && p == "/api/datasources":
		if !requireMember() {
			return
		}
		out := []any{}
		for _, d := range f.ds[scoped] {
			out = append(out, d)
		}
		writeJSON(w, 200, out)
	case r.Method == "GET" && strings.HasPrefix(p, "/api/datasources/name/"):
		if !requireMember() {
			return
		}
		if d, ok := f.ds[scoped][strings.TrimPrefix(p, "/api/datasources/name/")]; ok {
			writeJSON(w, 200, d)
			return
		}
		msg(w, 404, "Data source not found")
	case r.Method == "POST" && p == "/api/datasources":
		if !requireMember() {
			return
		}
		body["uid"] = "uid-" + str("name")
		f.ds[scoped][str("name")] = body
		msg(w, 200, "Datasource added")
	case r.Method == "PUT" && strings.HasPrefix(p, "/api/datasources/uid/"):
		if !requireMember() {
			return
		}
		body["uid"] = strings.TrimPrefix(p, "/api/datasources/uid/")
		f.ds[scoped][str("name")] = body
		msg(w, 200, "Datasource updated")
	default:
		msg(w, 404, "not found: "+r.Method+" "+p)
	}
}

func (f *fakeGrafana) serveOrg(w http.ResponseWriter, r *http.Request, o *org, rest []string, body map[string]any) {
	str := func(k string) string { s, _ := body[k].(string); return s }
	switch {
	case len(rest) == 0 && r.Method == "GET":
		writeJSON(w, 200, o)
	case len(rest) == 0 && r.Method == "PUT":
		o.Name = str("name")
		msg(w, 200, "Organization updated")
	case len(rest) == 0 && r.Method == "DELETE":
		delete(f.orgs, o.ID)
		delete(f.members, o.ID)
		msg(w, 200, "Organization deleted")
	case len(rest) == 1 && rest[0] == "address" && r.Method == "PUT":
		o.Address = address{Address1: str("address1"), Address2: str("address2"), City: str("city"),
			ZipCode: str("zipCode"), State: str("state"), Country: str("country")}
		msg(w, 200, "Address updated")
	case len(rest) == 1 && rest[0] == "users" && r.Method == "GET":
		ids := make([]int64, 0)
		for uid := range f.members[o.ID] {
			ids = append(ids, uid)
		}
		slices.Sort(ids)
		out := []orgUser{}
		for _, uid := range ids {
			u := f.users[uid]
			out = append(out, orgUser{UserID: uid, Login: u.Login, Email: u.Email, Role: f.members[o.ID][uid]})
		}
		writeJSON(w, 200, out)
	case len(rest) == 1 && rest[0] == "users" && r.Method == "POST":
		for _, u := range f.users {
			if u.Login == str("loginOrEmail") || u.Email == str("loginOrEmail") {
				if _, ok := f.members[o.ID][u.ID]; ok {
					msg(w, 409, "User is already member of this organization")
					return
				}
				f.members[o.ID][u.ID] = str("role")
				msg(w, 200, "User added to organization")
				return
			}
		}
		msg(w, 404, "User not found")
	case len(rest) == 2 && rest[0] == "users":
		uid, _ := strconv.ParseInt(rest[1], 10, 64)
		cur, ok := f.members[o.ID][uid]
		if !ok {
			msg(w, 404, "User not found in organization")
			return
		}
		lastAdmin := cur == RoleAdmin && f.admins(o.ID) == 1
		switch r.Method {
		case "PATCH":
			if lastAdmin && str("role") != RoleAdmin {
				msg(w, 400, "Cannot change role so that there is no organization admin left")
				return
			}
			f.members[o.ID][uid] = str("role")
			msg(w, 200, "Organization user updated")
		case "DELETE":
			if lastAdmin {
				msg(w, 400, "Cannot remove last organization admin")
				return
			}
			delete(f.members[o.ID], uid)
			msg(w, 200, "User removed from organization")
		}
	case len(rest) == 1 && rest[0] == "quotas" && r.Method == "GET":
		if f.quotaOff {
			msg(w, 404, "Quotas not enabled")
			return
		}
		out := []quota{}
		for _, t := range QuotaTargets {
			out = append(out, quota{Target: t, Limit: f.quotas[o.ID][t], Used: f.used[o.ID][t]})
		}
		writeJSON(w, 200, out)
	case len(rest) == 2 && rest[0] == "quotas" && r.Method == "PUT":
		lim, _ := body["limit"].(float64)
		f.quotas[o.ID][rest[1]] = int64(lim)
		msg(w, 200, "Organization quota updated")
	default:
		msg(w, 404, "not found")
	}
}
