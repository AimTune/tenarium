package rabbitmqvhost

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeVhost and fakeUser are the fake server's state.
type fakeVhost struct {
	Description      string
	Tags             []string
	DefaultQueueType string
	Limits           map[string]int64
}

type fakeUser struct {
	Password string
	Tags     []string
}

// fakeRabbit is an in-memory RabbitMQ Management API.
type fakeRabbit struct {
	mu     sync.Mutex
	vhosts map[string]*fakeVhost
	users  map[string]*fakeUser
	perms  map[string]permissionBody // "vhost/user"
	// stringTags makes GET report tags as a comma separated string, like
	// old RabbitMQ releases.
	stringTags bool
	// dropTags simulates a release that ignores vhost metadata.
	dropTags bool
	fail     map[string]int // "METHOD path" -> status
	calls    []string
}

func newFake(t *testing.T) (*fakeRabbit, *httptest.Server) {
	t.Helper()
	f := &fakeRabbit{
		vhosts: map[string]*fakeVhost{},
		users:  map[string]*fakeUser{},
		perms:  map[string]permissionBody{},
		fail:   map[string]int{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/overview", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]string{"management_version": "3.13.7"})
	})
	mux.HandleFunc("GET /api/vhosts/{v}", f.getVhost)
	mux.HandleFunc("PUT /api/vhosts/{v}", f.putVhost)
	mux.HandleFunc("DELETE /api/vhosts/{v}", f.deleteVhost)
	mux.HandleFunc("GET /api/users/{u}", f.getUser)
	mux.HandleFunc("PUT /api/users/{u}", f.putUser)
	mux.HandleFunc("DELETE /api/users/{u}", f.deleteUser)
	mux.HandleFunc("PUT /api/permissions/{v}/{u}", f.putPerms)
	mux.HandleFunc("PUT /api/vhost-limits/{v}/{n}", f.putLimit)
	mux.HandleFunc("DELETE /api/vhost-limits/{v}/{n}", f.deleteLimit)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != "secret" {
			http.Error(w, `{"error":"not_authorised"}`, http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		key := r.Method + " " + r.URL.Path
		f.calls = append(f.calls, key)
		status := f.fail[key]
		f.mu.Unlock()
		if status != 0 {
			http.Error(w, `{"error":"injected"}`, status)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return f, srv
}

func splitTags(s string) []string {
	var out []string
	for _, t := range strings.Split(s, ",") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func notFound(w http.ResponseWriter) {
	http.Error(w, `{"error":"Object Not Found","reason":"Not Found"}`, http.StatusNotFound)
}

func (f *fakeRabbit) tagsJSON(tags []string) any {
	if f.stringTags {
		return strings.Join(tags, ",")
	}
	if tags == nil {
		return []string{}
	}
	return tags
}

func (f *fakeRabbit) getVhost(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.vhosts[r.PathValue("v")]
	if !ok {
		notFound(w)
		return
	}
	dqt := v.DefaultQueueType
	if dqt == "" {
		dqt = "undefined"
	}
	writeJSON(w, map[string]any{
		"name": r.PathValue("v"), "description": v.Description, "tags": f.tagsJSON(v.Tags),
		"default_queue_type": dqt,
	})
}

func (f *fakeRabbit) putVhost(w http.ResponseWriter, r *http.Request) {
	var b vhostBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	name := r.PathValue("v")
	v, exists := f.vhosts[name]
	if !exists {
		v = &fakeVhost{Limits: map[string]int64{}}
		f.vhosts[name] = v
	}
	if !f.dropTags {
		v.Description, v.Tags = b.Description, splitTags(b.Tags)
		if b.DefaultQueueType != "" {
			v.DefaultQueueType = b.DefaultQueueType
		}
	}
	if exists {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusCreated)
	}
}

func (f *fakeRabbit) deleteVhost(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	name := r.PathValue("v")
	if _, ok := f.vhosts[name]; !ok {
		notFound(w)
		return
	}
	delete(f.vhosts, name)
	for k := range f.perms {
		if strings.HasPrefix(k, name+"/") {
			delete(f.perms, k)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeRabbit) getUser(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[r.PathValue("u")]
	if !ok {
		notFound(w)
		return
	}
	writeJSON(w, map[string]any{"name": r.PathValue("u"), "tags": f.tagsJSON(u.Tags), "limits": map[string]any{}})
}

func (f *fakeRabbit) putUser(w http.ResponseWriter, r *http.Request) {
	var b userBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.Password == "" {
		http.Error(w, `{"error":"bad_request"}`, http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users[r.PathValue("u")] = &fakeUser{Password: b.Password, Tags: splitTags(b.Tags)}
	w.WriteHeader(http.StatusCreated)
}

func (f *fakeRabbit) deleteUser(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	name := r.PathValue("u")
	if _, ok := f.users[name]; !ok {
		notFound(w)
		return
	}
	delete(f.users, name)
	for k := range f.perms {
		if strings.HasSuffix(k, "/"+name) {
			delete(f.perms, k)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeRabbit) putPerms(w http.ResponseWriter, r *http.Request) {
	var b permissionBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	v, u := r.PathValue("v"), r.PathValue("u")
	if f.vhosts[v] == nil || f.users[u] == nil {
		http.Error(w, `{"error":"bad_request","reason":"vhost_or_user_not_found"}`, http.StatusBadRequest)
		return
	}
	f.perms[v+"/"+u] = b
	w.WriteHeader(http.StatusCreated)
}

func (f *fakeRabbit) putLimit(w http.ResponseWriter, r *http.Request) {
	// Like RabbitMQ, which has no JSON response for this endpoint.
	if r.Header.Get("Accept") == "application/json" {
		w.WriteHeader(http.StatusNotAcceptable)
		return
	}
	var b struct {
		Value *int64 `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.Value == nil {
		http.Error(w, `{"error":"bad_request"}`, http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	v := f.vhosts[r.PathValue("v")]
	if v == nil {
		notFound(w)
		return
	}
	v.Limits[r.PathValue("n")] = *b.Value
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeRabbit) deleteLimit(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := f.vhosts[r.PathValue("v")]
	if v == nil {
		notFound(w)
		return
	}
	delete(v.Limits, r.PathValue("n"))
	w.WriteHeader(http.StatusNoContent)
}
