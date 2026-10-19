package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

// fakeVault is an in-memory subset of the Vault HTTP API: token checks,
// AppRole login, ACL policies, KV v2 metadata, AppRole roles and transit
// keys. Mounts are fixed: KV v2 at secret/, AppRole at auth/approle/,
// transit at transit/.
type fakeVault struct {
	mu        sync.Mutex
	srv       *httptest.Server
	tokens    map[string]bool
	policies  map[string]string
	kv        map[string]*kvEntry // key path below secret/
	roles     map[string]map[string]any
	roleIDs   map[string]string
	secretIDs map[string][]map[string]string
	keys      map[string]*transitKey
	health    int

	loginRoleID, loginSecretID string
	loginTTL                   int64
	logins                     int
	seq                        int
	requests                   []string // "METHOD path"
	namespaces                 map[string]bool
}

type kvEntry struct {
	custom   map[string]string
	versions int
}

type transitKey struct {
	typ             string
	deletionAllowed bool
}

func newFakeVault(t *testing.T) *fakeVault {
	f := &fakeVault{
		tokens:     map[string]bool{"root": true},
		policies:   map[string]string{"default": "# default", "root": ""},
		kv:         map[string]*kvEntry{},
		roles:      map[string]map[string]any{},
		roleIDs:    map[string]string{},
		secretIDs:  map[string][]map[string]string{},
		keys:       map[string]*transitKey{},
		health:     http.StatusOK,
		namespaces: map[string]bool{},
	}
	f.srv = httptest.NewServer(f)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeVault) next(prefix string) string {
	f.seq++
	return fmt.Sprintf("%s-%04d", prefix, f.seq)
}

func (f *fakeVault) count(method, path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if r == method+" "+path {
			n++
		}
	}
	return n
}

func reply(w http.ResponseWriter, status int, v any) {
	if v == nil {
		if status == http.StatusOK {
			status = http.StatusNoContent
		}
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func vaultErr(w http.ResponseWriter, status int, msg ...string) {
	if msg == nil {
		msg = []string{}
	}
	reply(w, status, map[string]any{"errors": msg})
}

func data(v any) map[string]any { return map[string]any{"data": v} }

func (f *fakeVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	f.requests = append(f.requests, r.Method+" "+path)
	if ns := r.Header.Get("X-Vault-Namespace"); ns != "" {
		f.namespaces[ns] = true
	}
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)

	if path == "sys/health" {
		reply(w, f.health, map[string]any{"sealed": f.health == http.StatusServiceUnavailable})
		return
	}
	if mount, ok := strings.CutSuffix(path, "/login"); ok && strings.HasPrefix(mount, "auth/") {
		if body["role_id"] != f.loginRoleID || body["secret_id"] != f.loginSecretID || f.loginRoleID == "" {
			vaultErr(w, http.StatusBadRequest, "invalid role or secret ID")
			return
		}
		f.logins++
		tok := f.next("login-token")
		f.tokens[tok] = true
		reply(w, 200, map[string]any{"auth": map[string]any{"client_token": tok, "lease_duration": f.loginTTL}})
		return
	}
	if !f.tokens[r.Header.Get("X-Vault-Token")] {
		vaultErr(w, http.StatusForbidden, "permission denied")
		return
	}

	switch {
	case path == "auth/token/lookup-self":
		reply(w, 200, data(map[string]any{"id": r.Header.Get("X-Vault-Token")}))
	case strings.HasPrefix(path, "sys/policies/acl/"):
		f.servePolicy(w, r, strings.TrimPrefix(path, "sys/policies/acl/"), body)
	case strings.HasPrefix(path, "secret/metadata/"):
		f.serveMetadata(w, r, strings.TrimPrefix(path, "secret/metadata/"), body)
	case strings.HasPrefix(path, "secret/data/"):
		key := strings.TrimPrefix(path, "secret/data/")
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			vaultErr(w, http.StatusMethodNotAllowed)
			return
		}
		e := f.kv[key]
		if e == nil {
			e = &kvEntry{custom: map[string]string{}}
			f.kv[key] = e
		}
		e.versions++
		reply(w, 200, data(map[string]any{"version": e.versions}))
	case strings.HasPrefix(path, "auth/approle/role/"):
		f.serveRole(w, r, strings.TrimPrefix(path, "auth/approle/role/"), body)
	case strings.HasPrefix(path, "transit/keys/"):
		f.serveKey(w, r, strings.TrimPrefix(path, "transit/keys/"), body)
	default:
		vaultErr(w, http.StatusNotFound, "no handler for route "+path)
	}
}

func (f *fakeVault) servePolicy(w http.ResponseWriter, r *http.Request, name string, body map[string]any) {
	switch r.Method {
	case http.MethodGet:
		p, ok := f.policies[name]
		if !ok {
			vaultErr(w, http.StatusNotFound)
			return
		}
		reply(w, 200, data(map[string]any{"name": name, "policy": p}))
	case http.MethodPut, http.MethodPost:
		s, _ := body["policy"].(string)
		if s == "" {
			vaultErr(w, http.StatusBadRequest, "missing policy")
			return
		}
		f.policies[name] = s
		reply(w, 200, nil)
	case http.MethodDelete:
		if name == "default" || name == "root" {
			vaultErr(w, http.StatusBadRequest, "cannot delete built-in policy")
			return
		}
		delete(f.policies, name)
		reply(w, 200, nil)
	}
}

func (f *fakeVault) list(dir string) []string {
	dir = strings.TrimSuffix(dir, "/") + "/"
	seen := map[string]bool{}
	for k := range f.kv {
		rest, ok := strings.CutPrefix(k, dir)
		if !ok {
			continue
		}
		if i := strings.Index(rest, "/"); i >= 0 {
			rest = rest[:i+1]
		}
		seen[rest] = true
	}
	var out []string
	for k := range seen {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func (f *fakeVault) serveMetadata(w http.ResponseWriter, r *http.Request, key string, body map[string]any) {
	if r.URL.Query().Get("list") == "true" || r.Method == "LIST" {
		keys := f.list(key)
		if len(keys) == 0 {
			vaultErr(w, http.StatusNotFound)
			return
		}
		reply(w, 200, data(map[string]any{"keys": keys}))
		return
	}
	switch r.Method {
	case http.MethodGet:
		e, ok := f.kv[key]
		if !ok {
			vaultErr(w, http.StatusNotFound)
			return
		}
		reply(w, 200, data(map[string]any{"custom_metadata": e.custom, "current_version": e.versions}))
	case http.MethodPost, http.MethodPut:
		e := f.kv[key]
		if e == nil {
			e = &kvEntry{}
			f.kv[key] = e
		}
		if cm, ok := body["custom_metadata"].(map[string]any); ok {
			e.custom = map[string]string{}
			for k, v := range cm {
				e.custom[k] = fmt.Sprint(v)
			}
		}
		reply(w, 200, nil)
	case http.MethodDelete:
		delete(f.kv, key)
		reply(w, 200, nil)
	}
}

func (f *fakeVault) serveRole(w http.ResponseWriter, r *http.Request, rest string, body map[string]any) {
	name, sub, _ := strings.Cut(rest, "/")
	role, ok := f.roles[name]
	switch {
	case sub == "role-id" && r.Method == http.MethodGet:
		if !ok {
			vaultErr(w, http.StatusNotFound)
			return
		}
		reply(w, 200, data(map[string]any{"role_id": f.roleIDs[name]}))
	case sub == "secret-id" && r.Method == http.MethodPost:
		if !ok {
			vaultErr(w, http.StatusBadRequest, "role does not exist")
			return
		}
		meta := map[string]string{}
		if s, _ := body["metadata"].(string); s != "" {
			_ = json.Unmarshal([]byte(s), &meta)
		}
		f.secretIDs[name] = append(f.secretIDs[name], meta)
		reply(w, 200, data(map[string]any{"secret_id": f.next("secret-id"), "secret_id_accessor": f.next("accessor"), "secret_id_ttl": 600}))
	case sub != "":
		vaultErr(w, http.StatusNotFound)
	case r.Method == http.MethodGet:
		if !ok {
			vaultErr(w, http.StatusNotFound)
			return
		}
		reply(w, 200, data(role))
	case r.Method == http.MethodPost:
		if !ok {
			role = map[string]any{}
			f.roles[name] = role
			f.roleIDs[name] = f.next("role-id")
		}
		for k, v := range body {
			role[k] = v
		}
		reply(w, 200, nil)
	case r.Method == http.MethodDelete:
		delete(f.roles, name)
		delete(f.roleIDs, name)
		reply(w, 200, nil)
	}
}

func (f *fakeVault) serveKey(w http.ResponseWriter, r *http.Request, rest string, body map[string]any) {
	name, sub, _ := strings.Cut(rest, "/")
	k, ok := f.keys[name]
	switch {
	case sub == "config" && r.Method == http.MethodPost:
		if !ok {
			vaultErr(w, http.StatusBadRequest, "no existing key")
			return
		}
		if v, set := body["deletion_allowed"].(bool); set {
			k.deletionAllowed = v
		}
		reply(w, 200, data(map[string]any{"name": name}))
	case sub != "":
		vaultErr(w, http.StatusNotFound)
	case r.Method == http.MethodGet:
		if !ok {
			vaultErr(w, http.StatusNotFound)
			return
		}
		reply(w, 200, data(map[string]any{"name": name, "type": k.typ, "deletion_allowed": k.deletionAllowed}))
	case r.Method == http.MethodPost:
		if !ok {
			typ, _ := body["type"].(string)
			if typ == "" {
				typ = "aes256-gcm96"
			}
			f.keys[name] = &transitKey{typ: typ}
		}
		reply(w, 200, nil)
	case r.Method == http.MethodDelete:
		if !ok {
			reply(w, 200, nil)
			return
		}
		if !k.deletionAllowed {
			vaultErr(w, http.StatusBadRequest, "deletion is not allowed for this key")
			return
		}
		delete(f.keys, name)
		reply(w, 200, nil)
	}
}
