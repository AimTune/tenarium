package secrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"golang.org/x/oauth2"
)

// blobStore is the fake KMS's "key material": opaque handles mapped to the
// plaintext and the context they were bound to.
type blobStore struct {
	mu sync.Mutex
	m  map[string][2]string // handle -> {plaintext, context}
}

func newBlobStore() *blobStore { return &blobStore{m: map[string][2]string{}} }

func (b *blobStore) put(pt, bound string) string {
	h := make([]byte, 16)
	_, _ = rand.Read(h)
	id := hex.EncodeToString(h)
	b.mu.Lock()
	b.m[id] = [2]string{pt, bound}
	b.mu.Unlock()
	return id
}

func (b *blobStore) get(id, bound string) (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.m[id]
	if !ok || v[1] != bound {
		return "", false
	}
	return v[0], true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// exercise runs the shared provider checks through an Envelope keyring.
func exercise(t *testing.T, p KeyProvider) {
	t.Helper()
	ctx := context.Background()
	e, err := NewEnvelope(p, nil, EnvelopeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ct, err := e.Encrypt(ctx, []byte("top secret"), "signing_key:7")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ct, "enc:v1:"+p.Name()+":") {
		t.Fatalf("format: %q", ct)
	}
	// A fresh keyring (empty DEK cache) must go to the KMS to unwrap.
	e2, _ := NewEnvelope(p, nil, EnvelopeOptions{})
	got, err := e2.Decrypt(ctx, ct, "signing_key:7")
	if err != nil || string(got) != "top secret" {
		t.Fatalf("decrypt: %q %v", got, err)
	}
	if _, err := e2.Decrypt(ctx, ct, "signing_key:8"); err == nil {
		t.Fatal("aad mismatch should fail")
	}
}

// --- AWS KMS --------------------------------------------------------------

var sigv4AuthRE = regexp.MustCompile(`^AWS4-HMAC-SHA256 Credential=AKIDTEST/(\d{8})/us-east-1/kms/aws4_request, SignedHeaders=([a-z0-9;-]+), Signature=([0-9a-f]{64})$`)

const fakeKeyARN = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"

func fakeAWSKMS(t *testing.T, calls *atomic.Int64) *httptest.Server {
	store := newBlobStore()
	creds := aws.Credentials{AccessKeyID: "AKIDTEST", SecretAccessKey: "secret"}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.URL.Path != "/" {
			writeJSON(w, 404, map[string]string{"__type": "UnknownOperationException"})
			return
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-amz-json-1.1" {
			t.Errorf("content-type %q", ct)
		}
		auth := r.Header.Get("Authorization")
		m := sigv4AuthRE.FindStringSubmatch(auth)
		if m == nil {
			t.Errorf("Authorization header shape: %q", auth)
			writeJSON(w, 403, map[string]string{"__type": "IncompleteSignatureException"})
			return
		}
		signed := strings.Split(m[2], ";")
		for _, h := range []string{"host", "x-amz-date", "x-amz-target"} {
			if !contains(signed, h) {
				t.Errorf("SignedHeaders %q missing %s", m[2], h)
			}
		}
		// Recompute the signature server-side to prove it is valid.
		date, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
		if err != nil || !strings.HasPrefix(r.Header.Get("X-Amz-Date"), m[1]) {
			t.Errorf("X-Amz-Date %q", r.Header.Get("X-Amz-Date"))
		}
		clone, _ := http.NewRequest(r.Method, "http://"+r.Host+r.URL.RequestURI(), bytes.NewReader(body))
		for _, h := range signed {
			if h != "host" {
				clone.Header.Set(h, r.Header.Get(h))
			}
		}
		sum := sha256.Sum256(body)
		if err := v4.NewSigner().SignHTTP(context.Background(), creds, clone, hex.EncodeToString(sum[:]), "kms", "us-east-1", date); err != nil {
			t.Fatal(err)
		}
		if want := clone.Header.Get("Authorization"); want != auth {
			t.Errorf("signature mismatch:\n got %s\nwant %s", auth, want)
			writeJSON(w, 403, map[string]string{"__type": "InvalidSignatureException"})
			return
		}

		var req struct {
			KeyID             string            `json:"KeyId"`
			Plaintext         string            `json:"Plaintext"`
			CiphertextBlob    string            `json:"CiphertextBlob"`
			EncryptionContext map[string]string `json:"EncryptionContext"`
		}
		_ = json.Unmarshal(body, &req)
		ec, _ := json.Marshal(req.EncryptionContext)
		switch r.Header.Get("X-Amz-Target") {
		case "TrentService.Encrypt":
			if req.KeyID != "alias/tenarium" {
				writeJSON(w, 400, map[string]string{"__type": "NotFoundException"})
				return
			}
			h := store.put(req.Plaintext, string(ec))
			writeJSON(w, 200, map[string]string{
				"CiphertextBlob": base64.StdEncoding.EncodeToString([]byte(h)),
				"KeyId":          fakeKeyARN,
			})
		case "TrentService.Decrypt":
			if req.KeyID != fakeKeyARN {
				writeJSON(w, 400, map[string]string{"__type": "IncorrectKeyException"})
				return
			}
			h, _ := base64.StdEncoding.DecodeString(req.CiphertextBlob)
			pt, ok := store.get(string(h), string(ec))
			if !ok {
				writeJSON(w, 400, map[string]string{"__type": "InvalidCiphertextException"})
				return
			}
			writeJSON(w, 200, map[string]string{"Plaintext": pt, "KeyId": fakeKeyARN})
		default:
			writeJSON(w, 400, map[string]string{"__type": "UnknownOperationException"})
		}
	}))
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func TestAWSKMSProvider(t *testing.T) {
	var calls atomic.Int64
	srv := fakeAWSKMS(t, &calls)
	defer srv.Close()
	kr, err := New(context.Background(), Config{Provider: ProviderAWS, AWSKMS: AWSKMSConfig{
		KeyID: "alias/tenarium", Region: "us-east-1", Endpoint: srv.URL,
		AccessKeyID: "AKIDTEST", SecretAccessKey: "secret",
	}})
	if err != nil {
		t.Fatal(err)
	}
	p := kr.(*Envelope).primary
	exercise(t, p)
	if calls.Load() != 2 {
		t.Fatalf("want 1 Encrypt + 1 Decrypt, got %d calls", calls.Load())
	}
	// The ciphertext records the key ARN reported by KMS (escaped).
	ct, _ := kr.Encrypt(context.Background(), []byte("x"), "")
	if !strings.HasPrefix(ct, "enc:v1:awskms:arn%3Aaws%3Akms%3Aus-east-1%3A111122223333%3Akey%2F1234abcd") {
		t.Fatalf("key id not recorded: %q", ct)
	}
	// Wrapped DEK bound to a different key id is refused by KMS.
	env, _ := parseEnvelope(ct)
	if _, err := p.Unwrap(context.Background(), "arn:aws:kms:us-east-1:111122223333:key/other", env.wrapped); err == nil {
		t.Fatal("expected IncorrectKeyException")
	}
}

func TestAWSRegionFromARN(t *testing.T) {
	if r := regionFromARN(fakeKeyARN); r != "us-east-1" {
		t.Fatal(r)
	}
	if r := regionFromARN("alias/x"); r != "" {
		t.Fatal(r)
	}
}

// --- GCP Cloud KMS --------------------------------------------------------

const gcpKey = "projects/p1/locations/global/keyRings/r1/cryptoKeys/k1"

func TestGCPKMSProvider(t *testing.T) {
	store := newBlobStore()
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer gcp-test-token" {
			writeJSON(w, 401, map[string]any{"error": map[string]any{"code": 401}})
			return
		}
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		aad := req["additionalAuthenticatedData"]
		switch r.URL.Path {
		case "/v1/" + gcpKey + ":encrypt":
			h := store.put(req["plaintext"], aad)
			writeJSON(w, 200, map[string]string{
				"name":       gcpKey + "/cryptoKeyVersions/3",
				"ciphertext": base64.StdEncoding.EncodeToString([]byte(h)),
			})
		case "/v1/" + gcpKey + ":decrypt":
			h, _ := base64.StdEncoding.DecodeString(req["ciphertext"])
			pt, ok := store.get(string(h), aad)
			if !ok {
				writeJSON(w, 400, map[string]any{"error": map[string]any{"code": 400, "message": "Decryption failed"}})
				return
			}
			writeJSON(w, 200, map[string]string{"plaintext": pt})
		default:
			writeJSON(w, 404, map[string]any{"error": map[string]any{"code": 404, "path": r.URL.Path}})
		}
	}))
	defer srv.Close()

	kr, err := New(context.Background(), Config{Provider: ProviderGCP, GCPKMS: GCPKMSConfig{
		KeyName: gcpKey, Endpoint: srv.URL,
		TokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "gcp-test-token"}),
	}})
	if err != nil {
		t.Fatal(err)
	}
	p := kr.(*Envelope).primary
	exercise(t, p)
	if calls.Load() != 2 {
		t.Fatalf("calls = %d", calls.Load())
	}
	// Key names from the database are validated before any request.
	before := calls.Load()
	if _, err := p.Unwrap(context.Background(), "projects/p/../../evil", []byte("x")); err == nil {
		t.Fatal("expected invalid key name error")
	}
	if calls.Load() != before {
		t.Fatal("invalid key name must not reach the server")
	}
}

// --- Vault Transit --------------------------------------------------------

func fakeVault(t *testing.T, token string) *httptest.Server {
	store := newBlobStore()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != token {
			writeJSON(w, 403, map[string]any{"errors": []string{"permission denied"}})
			return
		}
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		switch r.URL.Path {
		case "/v1/transit/encrypt/tenarium":
			if _, err := base64.StdEncoding.DecodeString(req["plaintext"]); err != nil || req["plaintext"] == "" {
				writeJSON(w, 400, map[string]any{"errors": []string{"bad plaintext"}})
				return
			}
			h := store.put(req["plaintext"], "")
			writeJSON(w, 200, map[string]any{"data": map[string]any{"ciphertext": "vault:v1:" + h, "key_version": 1}})
		case "/v1/transit/decrypt/tenarium":
			pt, ok := store.get(strings.TrimPrefix(req["ciphertext"], "vault:v1:"), "")
			if !ok {
				writeJSON(w, 400, map[string]any{"errors": []string{"cipher: message authentication failed"}})
				return
			}
			writeJSON(w, 200, map[string]any{"data": map[string]any{"plaintext": pt}})
		default:
			writeJSON(w, 404, map[string]any{"errors": []string{"no handler for " + r.URL.Path}})
		}
	}))
}

func TestVaultTransitProvider(t *testing.T) {
	srv := fakeVault(t, "s.testtoken")
	defer srv.Close()
	kr, err := New(context.Background(), Config{Provider: ProviderVault, Vault: VaultTransitConfig{
		Address: srv.URL, Token: "s.testtoken", KeyName: "tenarium",
	}})
	if err != nil {
		t.Fatal(err)
	}
	exercise(t, kr.(*Envelope).primary)
	ct, _ := kr.Encrypt(context.Background(), []byte("x"), "")
	if !strings.HasPrefix(ct, "enc:v1:vault:transit%2Ftenarium:") {
		t.Fatalf("key id: %q", ct)
	}

	bad, _ := New(context.Background(), Config{Provider: ProviderVault, Vault: VaultTransitConfig{
		Address: srv.URL, Token: "wrong", KeyName: "tenarium",
	}})
	if _, err := bad.Encrypt(context.Background(), []byte("x"), ""); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want 403, got %v", err)
	}
	p := kr.(*Envelope).primary
	if _, err := p.Unwrap(context.Background(), "../sys/tenarium", []byte("vault:v1:x")); err == nil {
		t.Fatal("expected invalid key id")
	}
}

func TestVaultRetriesServerErrors(t *testing.T) {
	inner := fakeVault(t, "tok")
	defer inner.Close()
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			writeJSON(w, 503, map[string]any{"errors": []string{"sealed"}})
			return
		}
		req, _ := http.NewRequest(r.Method, inner.URL+r.URL.Path, r.Body)
		req.Header = r.Header.Clone()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Error(err)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	defer srv.Close()
	p, err := NewVaultTransitProvider(VaultTransitConfig{Address: srv.URL, Token: "tok", KeyName: "tenarium"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Wrap(context.Background(), make([]byte, 32)); err != nil {
		t.Fatalf("expected retry to succeed: %v", err)
	}
	if n.Load() != 2 {
		t.Fatalf("attempts = %d", n.Load())
	}
}

// --- Azure Key Vault ------------------------------------------------------

func TestAzureKeyVaultProvider(t *testing.T) {
	store := newBlobStore()
	var tokenCalls, kvCalls atomic.Int64
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tenant-1/oauth2/v2.0/token" {
			tokenCalls.Add(1)
			_ = r.ParseForm()
			if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_id") != "app-id" ||
				r.Form.Get("client_secret") != "app-secret" || r.Form.Get("scope") != "https://vault.azure.net/.default" {
				writeJSON(w, 400, map[string]string{"error": "invalid_client", "form": r.Form.Encode()})
				return
			}
			writeJSON(w, 200, map[string]any{"access_token": "az-token", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		kvCalls.Add(1)
		if r.Header.Get("Authorization") != "Bearer az-token" {
			writeJSON(w, 401, map[string]any{"error": map[string]string{"code": "Unauthorized"}})
			return
		}
		if r.URL.Query().Get("api-version") != "7.4" {
			writeJSON(w, 400, map[string]any{"error": map[string]string{"code": "MissingApiVersion"}})
			return
		}
		var req azureKeyOp
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Alg != "RSA-OAEP-256" {
			writeJSON(w, 400, map[string]any{"error": map[string]string{"code": "BadParameter"}})
			return
		}
		kid := srv.URL + "/keys/tenarium/0123456789abcdef"
		switch r.URL.Path {
		case "/keys/tenarium/wrapkey":
			h := store.put(req.Value, "")
			writeJSON(w, 200, azureKeyOpResult{Kid: kid, Value: base64.RawURLEncoding.EncodeToString([]byte(h))})
		case "/keys/tenarium/0123456789abcdef/unwrapkey":
			h, _ := base64.RawURLEncoding.DecodeString(req.Value)
			pt, ok := store.get(string(h), "")
			if !ok {
				writeJSON(w, 400, map[string]any{"error": map[string]string{"code": "BadParameter"}})
				return
			}
			writeJSON(w, 200, azureKeyOpResult{Kid: kid, Value: pt})
		default:
			writeJSON(w, 404, map[string]any{"error": map[string]string{"code": "NotFound", "path": r.URL.Path}})
		}
	}))
	defer srv.Close()

	kr, err := New(context.Background(), Config{Provider: ProviderAzure, AzureKeyVault: AzureKeyVaultConfig{
		VaultURL: srv.URL, KeyName: "tenarium",
		TenantID: "tenant-1", ClientID: "app-id", ClientSecret: "app-secret",
		AuthorityHost: srv.URL,
	}})
	if err != nil {
		t.Fatal(err)
	}
	p := kr.(*Envelope).primary
	exercise(t, p)
	if tokenCalls.Load() != 1 {
		t.Fatalf("token should be fetched once and reused, got %d", tokenCalls.Load())
	}
	if kvCalls.Load() != 2 {
		t.Fatalf("kv calls = %d", kvCalls.Load())
	}

	// A kid pointing at another host (tampered DB row) must be refused
	// before any request, so the bearer token is never sent elsewhere.
	before := kvCalls.Load()
	for _, id := range []string{
		"RSA-OAEP-256 https://evil.example/keys/tenarium/abc",
		"RSA-OAEP-256 " + srv.URL + "/keys/other/abc",
		"RSA-OAEP-256 " + srv.URL + "/keys/tenarium/abc/../../x",
		"RSA1_5 " + srv.URL + "/keys/tenarium/abc",
		srv.URL + "/keys/tenarium/abc",
	} {
		if _, err := p.Unwrap(context.Background(), id, []byte("x")); err == nil {
			t.Errorf("%q should be refused", id)
		}
	}
	if kvCalls.Load() != before {
		t.Fatal("refused key ids must not reach the server")
	}
}

func TestHTTPErrorsAreReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 400, map[string]string{"__type": "AccessDeniedException", "message": "nope"})
	}))
	defer srv.Close()
	p, err := NewAWSKMSProvider(context.Background(), AWSKMSConfig{
		KeyID: "alias/x", Region: "us-east-1", Endpoint: srv.URL, AccessKeyID: "a", SecretAccessKey: "b",
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = p.Wrap(context.Background(), make([]byte, 32))
	if err == nil || !strings.Contains(err.Error(), "AccessDeniedException") {
		t.Fatalf("got %v", err)
	}
}
