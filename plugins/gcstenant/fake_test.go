package gcstenant

import (
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeGCS is an in-memory subset of the GCS JSON API, with labels,
// metagenerations, object generations and preconditions.
type fakeGCS struct {
	t  *testing.T
	mu sync.Mutex
	// dropLabels mimics emulators that do not persist bucket labels.
	dropLabels bool
	// wantAuth, when set, is the required Authorization header.
	wantAuth string
	buckets  map[string]*fakeBucket
	nextGen  int64
	srv      *httptest.Server
}

type fakeBucket struct {
	Name           string
	Project        string
	Labels         map[string]string
	Metageneration int64
	Versioning     bool
	StorageClass   string
	Location       string
	Lifecycle      []any
	IAM            map[string]any
	Objects        []*fakeObject
}

type fakeObject struct {
	Name     string
	Gen      int64
	Content  []byte
	Metadata map[string]string
	Live     bool
}

func newFakeGCS(t *testing.T) *fakeGCS {
	f := &fakeGCS{t: t, buckets: map[string]*fakeBucket{}, nextGen: 1000}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /storage/v1/b", f.createBucket)
	mux.HandleFunc("GET /storage/v1/b", f.listBuckets)
	mux.HandleFunc("GET /storage/v1/b/{b}", f.bucketOp)
	mux.HandleFunc("PATCH /storage/v1/b/{b}", f.bucketOp)
	mux.HandleFunc("DELETE /storage/v1/b/{b}", f.bucketOp)
	mux.HandleFunc("GET /storage/v1/b/{b}/o", f.listObjects)
	// {o...}: object names contain "/" (sent as %2F); match names spanning
	// several path segments too (Go 1.26.9 splits them, 1.26.1 did not).
	mux.HandleFunc("GET /storage/v1/b/{b}/o/{o...}", f.objectOp)
	mux.HandleFunc("DELETE /storage/v1/b/{b}/o/{o...}", f.objectOp)
	mux.HandleFunc("POST /upload/storage/v1/b/{b}/o", f.upload)
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.wantAuth != "" && r.Header.Get("Authorization") != f.wantAuth {
			apiErr(w, http.StatusUnauthorized, "bad auth "+r.Header.Get("Authorization"))
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func apiErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{
		"code": code, "message": msg, "errors": []any{map[string]any{"reason": "fake", "message": msg}},
	}})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (b *fakeBucket) resource() map[string]any {
	r := map[string]any{
		"name": b.Name, "metageneration": strconv.FormatInt(b.Metageneration, 10),
		"storageClass": b.StorageClass, "location": b.Location,
		"versioning": map[string]any{"enabled": b.Versioning},
	}
	if len(b.Labels) > 0 {
		r["labels"] = b.Labels
	}
	if len(b.Lifecycle) > 0 {
		r["lifecycle"] = map[string]any{"rule": b.Lifecycle}
	}
	if b.IAM != nil {
		r["iamConfiguration"] = b.IAM
	}
	return r
}

func (f *fakeGCS) applyBucket(b *fakeBucket, in map[string]any) {
	if l, ok := in["labels"].(map[string]any); ok && !f.dropLabels {
		if b.Labels == nil {
			b.Labels = map[string]string{}
		}
		for k, v := range l {
			if v == nil {
				delete(b.Labels, k)
			} else {
				b.Labels[k] = v.(string)
			}
		}
	}
	if v, ok := in["versioning"].(map[string]any); ok {
		b.Versioning = v["enabled"] == true
	}
	if v, ok := in["storageClass"].(string); ok {
		b.StorageClass = v
	}
	if v, ok := in["location"].(string); ok {
		b.Location = strings.ToUpper(v)
	}
	if v, ok := in["lifecycle"].(map[string]any); ok {
		b.Lifecycle, _ = v["rule"].([]any)
	}
	if v, ok := in["iamConfiguration"].(map[string]any); ok {
		if b.IAM == nil {
			b.IAM = map[string]any{}
		}
		for k, x := range v {
			b.IAM[k] = x
		}
	}
}

func (f *fakeGCS) createBucket(w http.ResponseWriter, r *http.Request) {
	var in map[string]any
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		apiErr(w, 400, err.Error())
		return
	}
	name, _ := in["name"].(string)
	if r.URL.Query().Get("project") == "" {
		apiErr(w, 400, "project required")
		return
	}
	if _, ok := f.buckets[name]; ok {
		apiErr(w, http.StatusConflict, "exists")
		return
	}
	b := &fakeBucket{Name: name, Project: r.URL.Query().Get("project"), Metageneration: 1, StorageClass: "STANDARD", Location: "US"}
	f.applyBucket(b, in)
	f.buckets[name] = b
	writeJSON(w, b.resource())
}

func (f *fakeGCS) listBuckets(w http.ResponseWriter, r *http.Request) {
	var items []any
	for _, b := range f.buckets {
		if b.Project == r.URL.Query().Get("project") {
			items = append(items, b.resource())
		}
	}
	writeJSON(w, map[string]any{"items": items})
}

func (f *fakeGCS) bucketOp(w http.ResponseWriter, r *http.Request) {
	b, ok := f.buckets[r.PathValue("b")]
	if !ok {
		apiErr(w, 404, "no bucket")
		return
	}
	if m := r.URL.Query().Get("ifMetagenerationMatch"); m != "" && m != strconv.FormatInt(b.Metageneration, 10) {
		apiErr(w, http.StatusPreconditionFailed, "metageneration")
		return
	}
	switch r.Method {
	case http.MethodPatch:
		var in map[string]any
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			apiErr(w, 400, err.Error())
			return
		}
		f.applyBucket(b, in)
		b.Metageneration++
	case http.MethodDelete:
		if len(b.Objects) > 0 {
			apiErr(w, http.StatusConflict, "bucket not empty")
			return
		}
		delete(f.buckets, b.Name)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, b.resource())
}

func objRes(b string, o *fakeObject) map[string]any {
	return map[string]any{"name": o.Name, "bucket": b, "generation": strconv.FormatInt(o.Gen, 10), "metadata": o.Metadata}
}

func (f *fakeGCS) listObjects(w http.ResponseWriter, r *http.Request) {
	b, ok := f.buckets[r.PathValue("b")]
	if !ok {
		apiErr(w, 404, "no bucket")
		return
	}
	q := r.URL.Query()
	var all []*fakeObject
	for _, o := range b.Objects {
		if strings.HasPrefix(o.Name, q.Get("prefix")) && (o.Live || q.Get("versions") == "true") {
			all = append(all, o)
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Name != all[j].Name {
			return all[i].Name < all[j].Name
		}
		return all[i].Gen < all[j].Gen
	})
	start, _ := strconv.Atoi(q.Get("pageToken"))
	limit, _ := strconv.Atoi(q.Get("maxResults"))
	if limit <= 0 || limit > 2 {
		limit = 2 // small pages exercise pagination
	}
	end := min(start+limit, len(all))
	var items []any
	for _, o := range all[start:end] {
		items = append(items, objRes(b.Name, o))
	}
	resp := map[string]any{"items": items}
	if end < len(all) {
		resp["nextPageToken"] = strconv.Itoa(end)
	}
	writeJSON(w, resp)
}

func (b *fakeBucket) live(name string) *fakeObject {
	for _, o := range b.Objects {
		if o.Name == name && o.Live {
			return o
		}
	}
	return nil
}

func (f *fakeGCS) objectOp(w http.ResponseWriter, r *http.Request) {
	b, ok := f.buckets[r.PathValue("b")]
	if !ok {
		apiErr(w, 404, "no bucket")
		return
	}
	name, q := r.PathValue("o"), r.URL.Query()
	idx := -1
	for i, o := range b.Objects {
		if o.Name != name {
			continue
		}
		if g := q.Get("generation"); g != "" && strconv.FormatInt(o.Gen, 10) == g || g == "" && o.Live {
			idx = i
		}
	}
	if idx < 0 {
		apiErr(w, 404, "no object")
		return
	}
	o := b.Objects[idx]
	if m := q.Get("ifGenerationMatch"); m != "" && m != strconv.FormatInt(o.Gen, 10) {
		apiErr(w, http.StatusPreconditionFailed, "generation")
		return
	}
	switch {
	case r.Method == http.MethodDelete && q.Get("generation") == "" && b.Versioning:
		o.Live = false // becomes noncurrent
	case r.Method == http.MethodDelete:
		b.Objects = append(b.Objects[:idx], b.Objects[idx+1:]...)
	case q.Get("alt") == "media":
		_, _ = w.Write(o.Content)
		return
	default:
		writeJSON(w, objRes(b.Name, o))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeGCS) upload(w http.ResponseWriter, r *http.Request) {
	b, ok := f.buckets[r.PathValue("b")]
	if !ok {
		apiErr(w, 404, "no bucket")
		return
	}
	q := r.URL.Query()
	var meta struct {
		Name     string            `json:"name"`
		Metadata map[string]string `json:"metadata"`
	}
	var content []byte
	switch q.Get("uploadType") {
	case "media":
		meta.Name = q.Get("name")
		content, _ = io.ReadAll(r.Body)
	case "multipart":
		_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			apiErr(w, 400, err.Error())
			return
		}
		mr := multipart.NewReader(r.Body, params["boundary"])
		part, err := mr.NextPart()
		if err != nil || json.NewDecoder(part).Decode(&meta) != nil {
			apiErr(w, 400, "bad metadata part")
			return
		}
		part, err = mr.NextPart()
		if err != nil {
			apiErr(w, 400, "bad media part")
			return
		}
		content, _ = io.ReadAll(part)
	default:
		apiErr(w, 400, "uploadType")
		return
	}
	cur := b.live(meta.Name)
	if m := q.Get("ifGenerationMatch"); m != "" {
		if (m == "0") != (cur == nil) || cur != nil && m != strconv.FormatInt(cur.Gen, 10) {
			apiErr(w, http.StatusPreconditionFailed, "generation")
			return
		}
	}
	if cur != nil {
		if b.Versioning {
			cur.Live = false
		} else {
			for i, o := range b.Objects {
				if o == cur {
					b.Objects = append(b.Objects[:i], b.Objects[i+1:]...)
					break
				}
			}
		}
	}
	f.nextGen++
	o := &fakeObject{Name: meta.Name, Gen: f.nextGen, Content: content, Metadata: meta.Metadata, Live: true}
	b.Objects = append(b.Objects, o)
	writeJSON(w, objRes(b.Name, o))
}

// helpers for tests

func (f *fakeGCS) bucket(name string) *fakeBucket {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.buckets[name]
}

func (f *fakeGCS) addBucket(name string, labels map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.buckets[name] = &fakeBucket{Name: name, Project: "proj", Labels: labels, Metageneration: 1, StorageClass: "STANDARD", Location: "US"}
}

func (f *fakeGCS) put(bkt, name, content string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b := f.buckets[bkt]
	if cur := b.live(name); cur != nil {
		cur.Live = false
		if !b.Versioning {
			for i, o := range b.Objects {
				if o == cur {
					b.Objects = append(b.Objects[:i], b.Objects[i+1:]...)
					break
				}
			}
		}
	}
	f.nextGen++
	b.Objects = append(b.Objects, &fakeObject{Name: name, Gen: f.nextGen, Content: []byte(content), Live: true})
}

func (f *fakeGCS) object(bkt, name string) *fakeObject {
	f.mu.Lock()
	defer f.mu.Unlock()
	if b := f.buckets[bkt]; b != nil {
		return b.live(name)
	}
	return nil
}

func (f *fakeGCS) count(bkt string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if b := f.buckets[bkt]; b != nil {
		return len(b.Objects)
	}
	return -1
}
