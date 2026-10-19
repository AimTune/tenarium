package opensearchtenant

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

// fakeCluster is an in-memory imitation of the OpenSearch/Elasticsearch
// REST endpoints the plugin uses. It records every request.
type fakeCluster struct {
	t      *testing.T
	flavor string
	user   string
	pass   string

	mu        sync.Mutex
	status    string
	templates map[string]map[string]any
	indices   map[string][]string // index -> aliases
	security  map[string]map[string]any
	requests  []string
}

func newFake(t *testing.T, flavor string) (*fakeCluster, *httptest.Server) {
	t.Helper()
	f := &fakeCluster{
		t: t, flavor: flavor, user: "admin", pass: "secret", status: "green",
		templates: map[string]map[string]any{},
		indices:   map[string][]string{},
		security:  map[string]map[string]any{},
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeCluster) reqs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requests)
}

func (f *fakeCluster) resetRequests() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func esError(w http.ResponseWriter, status int, typ, reason string) {
	writeJSON(w, status, map[string]any{
		"error":  map[string]any{"type": typ, "reason": reason, "root_cause": []any{map[string]any{"type": typ, "reason": reason}}},
		"status": status,
	})
}

func (f *fakeCluster) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	line := r.Method + " " + r.URL.Path
	if r.URL.RawQuery != "" {
		line += "?" + r.URL.RawQuery
	}
	f.requests = append(f.requests, line)

	if u, pw, ok := r.BasicAuth(); !ok || u != f.user || pw != f.pass {
		esError(w, http.StatusUnauthorized, "security_exception", "missing authentication credentials")
		return
	}
	var body map[string]any
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			esError(w, http.StatusBadRequest, "parse_exception", err.Error())
			return
		}
	}
	path := r.URL.Path
	switch {
	case path == "/_cluster/health" && r.Method == http.MethodGet:
		writeJSON(w, 200, map[string]any{"status": f.status})
	case strings.HasPrefix(path, "/_index_template/"):
		f.serveTemplate(w, r, strings.TrimPrefix(path, "/_index_template/"), body)
	case strings.HasPrefix(path, "/_cat/indices/") && r.Method == http.MethodGet:
		prefix := strings.TrimSuffix(strings.TrimPrefix(path, "/_cat/indices/"), "*")
		rows := []map[string]string{}
		for _, name := range slices.Sorted(maps.Keys(f.indices)) {
			if strings.HasPrefix(name, prefix) {
				rows = append(rows, map[string]string{"index": name})
			}
		}
		writeJSON(w, 200, rows)
	case strings.HasPrefix(path, osSecurityAPI+"/"):
		if f.flavor != FlavorOpenSearch {
			esError(w, 400, "illegal_argument_exception", "no handler for "+path)
			return
		}
		f.serveSecurity(w, r, path, body)
	case strings.HasPrefix(path, esSecurityAPI+"/"):
		if f.flavor != FlavorElasticsearch {
			esError(w, 400, "illegal_argument_exception", "no handler for "+path)
			return
		}
		f.serveSecurity(w, r, path, body)
	case strings.HasPrefix(path, "/_"):
		esError(w, 400, "illegal_argument_exception", "unexpected request "+line)
	default:
		f.serveIndex(w, r, strings.Split(strings.TrimPrefix(path, "/"), "/"), body)
	}
}

func (f *fakeCluster) serveTemplate(w http.ResponseWriter, r *http.Request, name string, body map[string]any) {
	cur, ok := f.templates[name]
	switch r.Method {
	case http.MethodGet:
		if !ok {
			esError(w, 404, "resource_not_found_exception", "index template matching ["+name+"] not found")
			return
		}
		writeJSON(w, 200, map[string]any{"index_templates": []any{map[string]any{"name": name, "index_template": cur}}})
	case http.MethodPut:
		if ok && r.URL.Query().Get("create") == "true" {
			esError(w, 400, "illegal_argument_exception", "index template ["+name+"] already exists")
			return
		}
		f.templates[name] = body
		writeJSON(w, 200, map[string]any{"acknowledged": true})
	case http.MethodDelete:
		if !ok {
			esError(w, 404, "resource_not_found_exception", "not found")
			return
		}
		delete(f.templates, name)
		writeJSON(w, 200, map[string]any{"acknowledged": true})
	}
}

func (f *fakeCluster) serveSecurity(w http.ResponseWriter, r *http.Request, path string, body map[string]any) {
	name := path[strings.LastIndex(path, "/")+1:]
	cur, ok := f.security[path]
	switch r.Method {
	case http.MethodGet:
		if !ok {
			if f.flavor == FlavorElasticsearch {
				writeJSON(w, 404, map[string]any{})
			} else {
				writeJSON(w, 404, map[string]any{"status": "NOT_FOUND", "message": "Resource '" + name + "' not found."})
			}
			return
		}
		writeJSON(w, 200, map[string]any{name: cur})
	case http.MethodPut:
		f.security[path] = body
		writeJSON(w, 200, map[string]any{"status": "OK"})
	case http.MethodDelete:
		if !ok {
			writeJSON(w, 404, map[string]any{"status": "NOT_FOUND"})
			return
		}
		delete(f.security, path)
		writeJSON(w, 200, map[string]any{"status": "OK"})
	}
}

func (f *fakeCluster) serveIndex(w http.ResponseWriter, r *http.Request, parts []string, body map[string]any) {
	name := parts[0]
	switch {
	case len(parts) == 1 && r.Method == http.MethodPut:
		if _, ok := f.indices[name]; ok {
			esError(w, 400, "resource_already_exists_exception", "index ["+name+"] already exists")
			return
		}
		var aliases []string
		if a, ok := body["aliases"].(map[string]any); ok {
			for k := range a {
				aliases = append(aliases, k)
			}
		}
		f.indices[name] = aliases
		writeJSON(w, 200, map[string]any{"acknowledged": true, "index": name})
	case len(parts) == 1 && r.Method == http.MethodDelete:
		// action.destructive_requires_name=true
		if strings.ContainsAny(name, "*,") || name == "_all" {
			esError(w, 400, "illegal_argument_exception", "Wildcard expressions or all indices are not allowed")
			return
		}
		if _, ok := f.indices[name]; !ok {
			esError(w, 404, "index_not_found_exception", "no such index ["+name+"]")
			return
		}
		delete(f.indices, name)
		writeJSON(w, 200, map[string]any{"acknowledged": true})
	case len(parts) == 3 && parts[1] == "_alias" && r.Method == http.MethodPut:
		if _, ok := f.indices[name]; !ok {
			esError(w, 404, "index_not_found_exception", "no such index ["+name+"]")
			return
		}
		if !slices.Contains(f.indices[name], parts[2]) {
			f.indices[name] = append(f.indices[name], parts[2])
		}
		writeJSON(w, 200, map[string]any{"acknowledged": true})
	default:
		esError(w, 400, "illegal_argument_exception", fmt.Sprintf("unexpected %s /%s", r.Method, strings.Join(parts, "/")))
	}
}
