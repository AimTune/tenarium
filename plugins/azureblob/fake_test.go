package azureblob

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// refStringToSign is an independent implementation of the Shared Key
// string-to-sign used by the fake server to verify requests. It works on the
// server-side view of the request (raw headers, decoded path, raw query).
func refStringToSign(r *http.Request, account string) string {
	get := func(name string) string { return strings.Join(r.Header.Values(name), ",") }
	length := ""
	if r.ContentLength > 0 {
		length = fmt.Sprint(r.ContentLength)
	}
	lines := []string{
		r.Method, get("Content-Encoding"), get("Content-Language"), length,
		get("Content-MD5"), get("Content-Type"), get("Date"),
		get("If-Modified-Since"), get("If-Match"), get("If-None-Match"),
		get("If-Unmodified-Since"), get("Range"),
	}
	var xms []string
	for k := range r.Header {
		if lk := strings.ToLower(k); strings.HasPrefix(lk, "x-ms-") {
			xms = append(xms, lk+":"+strings.TrimSpace(r.Header.Get(k)))
		}
	}
	sort.Strings(xms)
	res := "/" + account + r.URL.Path
	params := map[string][]string{}
	for _, kv := range strings.Split(r.URL.RawQuery, "&") {
		if kv == "" {
			continue
		}
		k, v, _ := strings.Cut(kv, "=")
		k, _ = url.QueryUnescape(k)
		v, _ = url.QueryUnescape(v)
		params[strings.ToLower(k)] = append(params[strings.ToLower(k)], v)
	}
	var names []string
	for k := range params {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		sort.Strings(params[k])
		res += "\n" + k + ":" + strings.Join(params[k], ",")
	}
	s := strings.Join(lines, "\n") + "\n"
	for _, h := range xms {
		s += h + "\n"
	}
	return s + res
}

func refSignature(stringToSign string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

type fakeContainer struct {
	meta    map[string]string
	access  string
	blobs   int
	acl     string
	lastMod time.Time
}

// fakeBlob is an in-memory Blob service for one account.
type fakeBlob struct {
	t       *testing.T
	account string
	key     []byte

	mu         sync.Mutex
	containers map[string]*fakeContainer
	// beingDeleted makes the next n creates of a container fail with
	// ContainerBeingDeleted.
	beingDeleted map[string]int
	// touchBeforeDelete changes the container just before a delete is
	// processed, to exercise If-Unmodified-Since.
	touchBeforeDelete bool
	clock             time.Time
	writes            []string // "METHOD container comp"
}

func newFakeBlob(t *testing.T) (*fakeBlob, *httptest.Server) {
	f := &fakeBlob{
		t: t, account: "testacct", key: []byte("0123456789abcdef0123456789abcdef"),
		containers:   map[string]*fakeContainer{},
		beingDeleted: map[string]int{},
		clock:        time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeBlob) keyB64() string { return base64.StdEncoding.EncodeToString(f.key) }

func (f *fakeBlob) tick() time.Time {
	f.clock = f.clock.Add(time.Second)
	return f.clock
}

func blobErr(w http.ResponseWriter, r *http.Request, status int, code string) {
	w.Header().Set("x-ms-error-code", code)
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?><Error><Code>%s</Code><Message>%s
RequestId:x</Message></Error>`, code, code)
	}
}

func (f *fakeBlob) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("x-ms-version") != APIVersion || r.Header.Get("x-ms-date") == "" {
		blobErr(w, r, http.StatusBadRequest, "MissingRequiredHeader")
		return
	}
	want := "SharedKey " + f.account + ":" + refSignature(refStringToSign(r, f.account), f.key)
	if r.Header.Get("Authorization") != want {
		f.t.Logf("signature mismatch for %s %s; string-to-sign:\n%s", r.Method, r.URL, refStringToSign(r, f.account))
		blobErr(w, r, http.StatusForbidden, "AuthenticationFailed")
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/"+f.account+"/")
	if !ok {
		blobErr(w, r, http.StatusBadRequest, "InvalidUri")
		return
	}
	q := r.URL.Query()
	body, _ := io.ReadAll(r.Body)
	if rest == "" {
		if r.Method == http.MethodGet && q.Get("comp") == "list" {
			fmt.Fprint(w, `<?xml version="1.0"?><EnumerationResults><Containers/></EnumerationResults>`)
			return
		}
		blobErr(w, r, http.StatusBadRequest, "UnsupportedQueryParameter")
		return
	}
	name := rest
	if q.Get("restype") != "container" {
		blobErr(w, r, http.StatusBadRequest, "UnsupportedQueryParameter")
		return
	}
	c := f.containers[name]
	comp := q.Get("comp")
	if r.Method != http.MethodHead && r.Method != http.MethodGet {
		f.writes = append(f.writes, strings.TrimSpace(r.Method+" "+name+" "+comp))
	}
	if c == nil && (comp != "" || r.Method != http.MethodPut) {
		blobErr(w, r, http.StatusNotFound, "ContainerNotFound")
		return
	}
	meta := func() map[string]string {
		m := map[string]string{}
		for k, v := range r.Header {
			if n, ok := strings.CutPrefix(strings.ToLower(k), "x-ms-meta-"); ok {
				m[n] = v[0]
			}
		}
		return m
	}
	access := r.Header.Get("x-ms-blob-public-access")
	if access == "" {
		access = PublicAccessNone
	}
	switch {
	case r.Method == http.MethodHead && comp == "":
		for k, v := range c.meta {
			w.Header()["x-ms-meta-"+k] = []string{v}
		}
		if c.access != PublicAccessNone {
			w.Header().Set("x-ms-blob-public-access", c.access)
		}
		w.Header().Set("Last-Modified", c.lastMod.Format(http.TimeFormat))
	case r.Method == http.MethodPut && comp == "":
		if c != nil {
			blobErr(w, r, http.StatusConflict, "ContainerAlreadyExists")
			return
		}
		if f.beingDeleted[name] > 0 {
			f.beingDeleted[name]--
			blobErr(w, r, http.StatusConflict, "ContainerBeingDeleted")
			return
		}
		f.containers[name] = &fakeContainer{meta: meta(), access: access, lastMod: f.tick()}
		w.WriteHeader(http.StatusCreated)
	case r.Method == http.MethodPut && comp == "metadata":
		c.meta = meta()
		c.lastMod = f.tick()
	case r.Method == http.MethodGet && comp == "acl":
		if c.access != PublicAccessNone {
			w.Header().Set("x-ms-blob-public-access", c.access)
		}
		if c.acl == "" {
			fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?><SignedIdentifiers />`)
		} else {
			fmt.Fprint(w, c.acl)
		}
	case r.Method == http.MethodPut && comp == "acl":
		c.access = access
		if len(body) > 0 && !strings.Contains(string(body), "<SignedIdentifiers />") {
			c.acl = string(body)
		} else {
			c.acl = ""
		}
		c.lastMod = f.tick()
	case r.Method == http.MethodGet && comp == "list":
		if q.Get("maxresults") != "1" {
			blobErr(w, r, http.StatusBadRequest, "InvalidQueryParameterValue")
			return
		}
		blobs := ""
		if c.blobs > 0 {
			blobs = "<Blob><Name>file.txt</Name></Blob>"
		}
		fmt.Fprintf(w, `<?xml version="1.0"?><EnumerationResults><Blobs>%s</Blobs><NextMarker/></EnumerationResults>`, blobs)
	case r.Method == http.MethodDelete && comp == "":
		if f.touchBeforeDelete {
			c.lastMod = f.tick()
		}
		if s := r.Header.Get("If-Unmodified-Since"); s != "" {
			since, err := http.ParseTime(s)
			if err != nil || c.lastMod.After(since) {
				blobErr(w, r, http.StatusPreconditionFailed, "ConditionNotMet")
				return
			}
		}
		delete(f.containers, name)
		w.WriteHeader(http.StatusAccepted)
	default:
		blobErr(w, r, http.StatusBadRequest, "UnsupportedHttpVerb")
	}
}

// put stores a container directly (test setup).
func (f *fakeBlob) put(name string, c *fakeContainer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c.meta == nil {
		c.meta = map[string]string{}
	}
	if c.access == "" {
		c.access = PublicAccessNone
	}
	c.lastMod = f.tick()
	f.containers[name] = c
}

func (f *fakeBlob) get(name string) *fakeContainer {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.containers[name]
}

func (f *fakeBlob) writeLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.writes...)
}
