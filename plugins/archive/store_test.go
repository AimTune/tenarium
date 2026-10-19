package archive

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// testStore checks the objectStore contract.
func testStore(t *testing.T, s objectStore) {
	t.Helper()
	ctx := context.Background()
	if err := s.Check(ctx); err != nil {
		t.Fatalf("Check: %v", err)
	}
	keys := []string{"p/2026/10/10/08/a.ndjson.gz", "p/2026/10/10/09/b.ndjson.gz", "p/2026/10/11/00/c.ndjson", "q/x"}
	for i, k := range keys {
		if err := s.Put(ctx, k, []byte(fmt.Sprintf("body-%d", i)), "application/gzip"); err != nil {
			t.Fatalf("Put %s: %v", k, err)
		}
	}
	// Overwrite is allowed.
	if err := s.Put(ctx, keys[0], []byte("body-0b"), "application/gzip"); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	b, err := s.Get(ctx, keys[0])
	if err != nil || string(b) != "body-0b" {
		t.Fatalf("Get = %q, %v", b, err)
	}
	if _, err := s.Get(ctx, "p/missing"); !errors.Is(err, errNotFound) {
		t.Fatalf("Get missing: %v", err)
	}
	got, err := s.List(ctx, "p/2026/10/10/")
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	if want := keys[:2]; !slices.Equal(got, want) {
		t.Fatalf("List = %v, want %v", got, want)
	}
	if got, err := s.List(ctx, "p/2026/12/"); err != nil || len(got) != 0 {
		t.Fatalf("List empty = %v, %v", got, err)
	}
	if err := s.Delete(ctx, keys[0]); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, keys[0]); err != nil {
		t.Fatalf("Delete missing: %v", err)
	}
	if got, _ := s.List(ctx, "p/2026/10/10/"); !slices.Equal(got, keys[1:2]) {
		t.Fatalf("List after delete = %v", got)
	}
}

func TestFileStore(t *testing.T) {
	s, err := newFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	testStore(t, s)
	if err := s.Put(context.Background(), "../escape", []byte("x"), ""); err == nil {
		t.Fatal("key leaving the directory accepted")
	}
}

// fakeGCS is an in-memory GCS JSON API.
type fakeGCS struct {
	mu      sync.Mutex
	bucket  string
	objects map[string][]byte
}

func (f *fakeGCS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := r.URL.EscapedPath()
	bucketPath := "/storage/v1/b/" + f.bucket
	switch {
	case r.Method == http.MethodPost && p == "/upload/storage/v1/b/"+f.bucket+"/o":
		if r.URL.Query().Get("uploadType") != "media" || r.Header.Get("Content-Type") == "" {
			http.Error(w, `{"error":{"message":"bad upload"}}`, http.StatusBadRequest)
			return
		}
		b, _ := io.ReadAll(r.Body)
		f.objects[r.URL.Query().Get("name")] = b
		_, _ = w.Write([]byte(`{}`))
	case r.Method == http.MethodGet && p == bucketPath:
		_, _ = w.Write([]byte(`{"name":"` + f.bucket + `"}`))
	case r.Method == http.MethodGet && p == bucketPath+"/o":
		prefix := r.URL.Query().Get("prefix")
		var names []string
		for k := range f.objects {
			if strings.HasPrefix(k, prefix) {
				names = append(names, `{"name":"`+k+`"}`)
			}
		}
		_, _ = w.Write([]byte(`{"items":[` + strings.Join(names, ",") + `]}`))
	case strings.HasPrefix(p, bucketPath+"/o/"):
		name, _ := url.PathUnescape(strings.TrimPrefix(p, bucketPath+"/o/"))
		b, ok := f.objects[name]
		if !ok {
			http.Error(w, `{"error":{"message":"No such object"}}`, http.StatusNotFound)
			return
		}
		if r.Method == http.MethodDelete {
			delete(f.objects, name)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = w.Write(b)
	default:
		http.Error(w, `{"error":{"message":"unexpected"}}`, http.StatusNotImplemented)
	}
}

func TestGCSStore(t *testing.T) {
	srv := httptest.NewServer(&fakeGCS{bucket: "arch", objects: map[string][]byte{}})
	t.Cleanup(srv.Close)
	s, err := newGCSStore(context.Background(), GCSConfig{Endpoint: srv.URL, Anonymous: true, Bucket: "arch"}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	testStore(t, s)
}

// fakeAzure is an in-memory Blob service that checks Shared Key signatures.
type fakeAzure struct {
	mu        sync.Mutex
	account   string
	key       []byte
	container string
	blobs     map[string][]byte
}

func (f *fakeAzure) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	mac := hmac.New(sha256.New, f.key)
	mac.Write([]byte(azureStringToSign(r, f.account)))
	want := "SharedKey " + f.account + ":" + base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if r.Header.Get("x-ms-version") == "" || r.Header.Get("Authorization") != want {
		w.Header().Set("x-ms-error-code", "AuthenticationFailed")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	base := "/" + f.account + "/" + f.container
	p := r.URL.Path
	q := r.URL.Query()
	switch {
	case p == base && q.Get("restype") == "container" && q.Get("comp") == "list":
		type blob struct {
			Name string `xml:"Name"`
		}
		var res struct {
			XMLName xml.Name `xml:"EnumerationResults"`
			Blobs   struct {
				Blob []blob `xml:"Blob"`
			} `xml:"Blobs"`
			NextMarker string `xml:"NextMarker"`
		}
		for k := range f.blobs {
			if strings.HasPrefix(k, q.Get("prefix")) {
				res.Blobs.Blob = append(res.Blobs.Blob, blob{k})
			}
		}
		_ = xml.NewEncoder(w).Encode(res)
	case p == base && q.Get("restype") == "container":
		w.WriteHeader(http.StatusOK)
	case strings.HasPrefix(p, base+"/"):
		name := strings.TrimPrefix(p, base+"/")
		switch r.Method {
		case http.MethodPut:
			if r.Header.Get("x-ms-blob-type") != "BlockBlob" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			f.blobs[name] = body
			w.WriteHeader(http.StatusCreated)
		case http.MethodGet, http.MethodDelete:
			b, ok := f.blobs[name]
			if !ok {
				w.Header().Set("x-ms-error-code", "BlobNotFound")
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if r.Method == http.MethodDelete {
				delete(f.blobs, name)
				w.WriteHeader(http.StatusAccepted)
				return
			}
			_, _ = w.Write(b)
		}
	default:
		w.WriteHeader(http.StatusNotImplemented)
	}
}

func TestAzureStore(t *testing.T) {
	key, _ := base64.StdEncoding.DecodeString(azureDevKey)
	f := &fakeAzure{account: azureDevAccount, key: key, container: "archive", blobs: map[string][]byte{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	s, err := newAzureStore(AzureConfig{
		ConnectionString: "UseDevelopmentStorage=true;DevelopmentStorageProxyUri=" + srv.URL,
		Container:        "archive",
	}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	testStore(t, s)
}

func TestAzureStringToSign(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/acct/c?restype=container&comp=list&prefix=a%2Fb", nil)
	req.Header.Set("x-ms-date", "Sat, 10 Oct 2026 08:00:00 GMT")
	req.Header.Set("x-ms-version", azureAPIVersion)
	want := "GET\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:Sat, 10 Oct 2026 08:00:00 GMT\nx-ms-version:" + azureAPIVersion +
		"\n/acct/acct/c\ncomp:list\nprefix:a/b\nrestype:container"
	if got := azureStringToSign(req, "acct"); got != want {
		t.Fatalf("string to sign:\n%q\nwant\n%q", got, want)
	}
}

func TestAzureConfig(t *testing.T) {
	for _, c := range []AzureConfig{
		{Container: "c"},
		{Container: "c", ConnectionString: "AccountName=a;AccountKey=a2V5", AccountName: "abc"},
		{Container: "c", ConnectionString: "AccountName=abc;SharedAccessSignature=x"},
		{Container: "c", AccountName: "abc", AccountKey: "not base64!"},
	} {
		if _, err := newAzureStore(c, time.Second); err == nil {
			t.Errorf("accepted %+v", c)
		}
	}
	s, err := newAzureStore(AzureConfig{Container: "c", ConnectionString: "AccountName=abc;AccountKey=a2V5;EndpointSuffix=core.chinacloudapi.cn"}, time.Second)
	if err != nil || s.endpoint.String() != "https://abc.blob.core.chinacloudapi.cn" {
		t.Fatalf("endpoint = %v, %v", s, err)
	}
}
