package clickhousetenant

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// fakeCH is a tiny in-memory ClickHouse that understands exactly the
// statements the plugin sends, and records them.
type fakeCH struct {
	mu        sync.Mutex
	queries   []string
	databases map[string]string   // name -> comment
	tables    map[string][]string // database -> tables
	users     map[string]string   // name -> default database
	passwords map[string]string   // name -> password
	grants    map[string]string   // user -> grant statement
	profiles  map[string][]string // name -> apply_to_list
	quotas    map[string][]string // name -> apply_to_list
	ddl       map[string]string   // "profile:<name>" / "quota:<name>" -> statement
	// fail makes queries containing the key fail with the given code.
	fail map[string]int
}

func newFakeCH(t *testing.T) (*fakeCH, *httptest.Server) {
	f := &fakeCH{
		databases: map[string]string{}, tables: map[string][]string{},
		users: map[string]string{}, passwords: map[string]string{}, grants: map[string]string{},
		profiles: map[string][]string{}, quotas: map[string][]string{}, ddl: map[string]string{},
		fail: map[string]int{},
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeCH) Queries() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...)
}

var (
	reIdent          = "`([^`]+)`"
	reCluster        = `(?: ON CLUSTER '[^']+')?`
	reCreateDB       = regexp.MustCompile("^CREATE DATABASE IF NOT EXISTS " + reIdent + reCluster + "(?: ENGINE = .+)? COMMENT '([^']*)'$")
	reAlterDBComment = regexp.MustCompile("^ALTER DATABASE " + reIdent + reCluster + " MODIFY COMMENT '([^']*)'$")
	reDropDB         = regexp.MustCompile("^DROP DATABASE IF EXISTS " + reIdent + reCluster + " SYNC$")
	reCreateUser     = regexp.MustCompile("^CREATE USER IF NOT EXISTS " + reIdent + reCluster + " IDENTIFIED WITH sha256_password BY '([^']*)' DEFAULT DATABASE " + reIdent + "$")
	reAlterUser      = regexp.MustCompile("^ALTER USER " + reIdent + reCluster + " IDENTIFIED WITH sha256_password BY '([^']*)' DEFAULT DATABASE " + reIdent + "$")
	reGrant          = regexp.MustCompile("^GRANT" + reCluster + " (.+) ON " + reIdent + `\.\* TO ` + reIdent + " WITH REPLACE OPTION$")
	reProfile        = regexp.MustCompile("^CREATE SETTINGS PROFILE OR REPLACE " + reIdent + reCluster + "(?: SETTINGS .+)? TO " + reIdent + "$")
	reQuota          = regexp.MustCompile("^CREATE QUOTA OR REPLACE " + reIdent + reCluster + " FOR INTERVAL .+ TO " + reIdent + "$")
	reDropUser       = regexp.MustCompile("^DROP USER IF EXISTS " + reIdent + reCluster + "$")
	reDropProfile    = regexp.MustCompile("^DROP SETTINGS PROFILE IF EXISTS " + reIdent + reCluster + "$")
	reDropQuota      = regexp.MustCompile("^DROP QUOTA IF EXISTS " + reIdent + reCluster + "$")
)

func (f *fakeCH) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	q := string(body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, q)
	if r.Header.Get("X-ClickHouse-User") != "admin" || r.Header.Get("X-ClickHouse-Key") != "secret" {
		w.Header().Set("X-ClickHouse-Exception-Code", "516")
		http.Error(w, "Code: 516. DB::Exception: admin: Authentication failed", http.StatusUnauthorized)
		return
	}
	for k, code := range f.fail {
		if strings.Contains(q, k) {
			w.Header().Set("X-ClickHouse-Exception-Code", fmt.Sprint(code))
			http.Error(w, fmt.Sprintf("Code: %d. DB::Exception: injected", code), http.StatusInternalServerError)
			return
		}
	}
	param := func(n string) string { return r.URL.Query().Get("param_" + n) }
	rows := func(v ...any) {
		for _, row := range v {
			b, _ := json.Marshal(row)
			_, _ = w.Write(append(b, '\n'))
		}
	}
	q = strings.TrimSuffix(q, " FORMAT JSONEachRow")
	switch {
	case q == "SELECT 1":
		_, _ = io.WriteString(w, "1\n")
	case strings.HasPrefix(q, "SELECT comment FROM system.databases"):
		if c, ok := f.databases[param("name")]; ok {
			rows(map[string]string{"comment": c})
		}
	case strings.HasPrefix(q, "SELECT name FROM system.tables"):
		if ts := f.tables[param("db")]; len(ts) > 0 {
			rows(map[string]string{"name": ts[0]})
		}
	case strings.HasPrefix(q, "SELECT default_database FROM system.users"):
		if d, ok := f.users[param("name")]; ok {
			rows(map[string]string{"default_database": d})
		}
	case strings.HasPrefix(q, "SELECT apply_to_all, apply_to_list FROM system.settings_profiles"):
		if to, ok := f.profiles[param("name")]; ok {
			rows(map[string]any{"apply_to_all": 0, "apply_to_list": to})
		}
	case strings.HasPrefix(q, "SELECT apply_to_all, apply_to_list FROM system.quotas"):
		if to, ok := f.quotas[param("name")]; ok {
			rows(map[string]any{"apply_to_all": 0, "apply_to_list": to})
		}
	default:
		if !f.ddlLocked(q) {
			w.Header().Set("X-ClickHouse-Exception-Code", "62")
			http.Error(w, "Code: 62. DB::Exception: Syntax error (fake): "+q, http.StatusBadRequest)
		}
	}
}

func (f *fakeCH) ddlLocked(q string) bool {
	if m := reCreateDB.FindStringSubmatch(q); m != nil {
		if _, ok := f.databases[m[1]]; !ok {
			f.databases[m[1]] = m[2]
		}
	} else if m := reAlterDBComment.FindStringSubmatch(q); m != nil {
		f.databases[m[1]] = m[2]
	} else if m := reDropDB.FindStringSubmatch(q); m != nil {
		delete(f.databases, m[1])
		delete(f.tables, m[1])
	} else if m := reCreateUser.FindStringSubmatch(q); m != nil {
		if _, ok := f.users[m[1]]; !ok {
			f.users[m[1]], f.passwords[m[1]] = m[3], m[2]
		}
	} else if m := reAlterUser.FindStringSubmatch(q); m != nil {
		f.users[m[1]], f.passwords[m[1]] = m[3], m[2]
	} else if m := reGrant.FindStringSubmatch(q); m != nil {
		f.grants[m[3]] = q
	} else if m := reProfile.FindStringSubmatch(q); m != nil {
		f.profiles[m[1]] = []string{m[2]}
		f.ddl["profile:"+m[1]] = q
	} else if m := reQuota.FindStringSubmatch(q); m != nil {
		f.quotas[m[1]] = []string{m[2]}
		f.ddl["quota:"+m[1]] = q
	} else if m := reDropUser.FindStringSubmatch(q); m != nil {
		delete(f.users, m[1])
		delete(f.grants, m[1])
		for _, set := range []map[string][]string{f.profiles, f.quotas} {
			for k, to := range set {
				if len(to) == 1 && to[0] == m[1] {
					set[k] = []string{}
				}
			}
		}
	} else if m := reDropProfile.FindStringSubmatch(q); m != nil {
		delete(f.profiles, m[1])
	} else if m := reDropQuota.FindStringSubmatch(q); m != nil {
		delete(f.quotas, m[1])
	} else {
		return false
	}
	return true
}
