package oktadir

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

const apiToken = "00test-api-token"

// fakeOkta reproduces the Okta Users API, lifecycle operations, the org
// authorization server's token endpoint (private_key_jwt) and the Authn API.
type fakeOkta struct {
	*httptest.Server
	t   *testing.T
	mu  sync.Mutex
	seq int
	// users by ID; "password" and "mfa" are kept beside the API fields.
	users  map[string]*fakeUser
	emails []string // "op:userID" for lifecycle calls with sendEmail=true
	// pub verifies client assertions.
	pub      crypto.PublicKey
	clientID string
	tokens   int
}

type fakeUser struct {
	ID       string         `json:"id"`
	Status   string         `json:"status"`
	Profile  map[string]any `json:"profile"`
	password string
	mfa      bool
}

func newFakeOkta(t *testing.T) *fakeOkta {
	f := &fakeOkta{t: t, users: map[string]*fakeUser{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth2/v1/token", f.token)
	mux.HandleFunc("POST /api/v1/authn", f.authn)
	api := http.NewServeMux()
	api.HandleFunc("GET /api/v1/users", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, []any{}) })
	api.HandleFunc("POST /api/v1/users", f.create)
	api.HandleFunc("GET /api/v1/users/{id}", f.get)
	api.HandleFunc("POST /api/v1/users/{id}", f.update)
	api.HandleFunc("DELETE /api/v1/users/{id}", f.del)
	api.HandleFunc("POST /api/v1/users/{id}/lifecycle/{op}", f.lifecycle)
	mux.Handle("/api/v1/users", f.auth(api))
	mux.Handle("/api/v1/users/", f.auth(api))
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func (f *fakeOkta) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		if h != "SSWS "+apiToken && h != "Bearer oauth-token" {
			oktaErr(w, 401, "E0000011", "Invalid token provided")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func oktaErr(w http.ResponseWriter, status int, code, summary string, causes ...string) {
	cs := []map[string]string{}
	for _, c := range causes {
		cs = append(cs, map[string]string{"errorSummary": c})
	}
	writeJSON(w, status, map[string]any{"errorCode": code, "errorSummary": summary, "errorCauses": cs})
}

func (f *fakeOkta) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if r.PostForm.Get("grant_type") != "client_credentials" ||
		r.PostForm.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" ||
		r.PostForm.Get("scope") != "okta.users.read okta.users.manage" {
		writeJSON(w, 400, map[string]any{"error": "invalid_request", "error_description": "bad request"})
		return
	}
	if err := f.verifyAssertion(r.PostForm.Get("client_assertion")); err != nil {
		writeJSON(w, 401, map[string]any{"error": "invalid_client", "error_description": err.Error()})
		return
	}
	f.mu.Lock()
	f.tokens++
	f.mu.Unlock()
	writeJSON(w, 200, map[string]any{"access_token": "oauth-token", "token_type": "Bearer", "expires_in": 3600,
		"scope": "okta.users.read okta.users.manage"})
}

func (f *fakeOkta) verifyAssertion(jwt string) error {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return errors.New("malformed assertion")
	}
	enc := base64.RawURLEncoding
	var header map[string]string
	var claims map[string]any
	hb, _ := enc.DecodeString(parts[0])
	cb, _ := enc.DecodeString(parts[1])
	sig, _ := enc.DecodeString(parts[2])
	if json.Unmarshal(hb, &header) != nil || json.Unmarshal(cb, &claims) != nil {
		return errors.New("malformed assertion")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch k := f.pub.(type) {
	case *rsa.PublicKey:
		if header["alg"] != "RS256" || rsa.VerifyPKCS1v15(k, crypto.SHA256, sum[:], sig) != nil {
			return errors.New("bad signature")
		}
	case *ecdsa.PublicKey:
		if header["alg"] != "ES256" || len(sig) != 64 ||
			!ecdsa.Verify(k, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return errors.New("bad signature")
		}
	default:
		return errors.New("no key")
	}
	exp, _ := claims["exp"].(float64)
	if header["kid"] != "key-1" || claims["iss"] != f.clientID || claims["sub"] != f.clientID ||
		claims["aud"] != f.URL+"/oauth2/v1/token" || claims["jti"] == "" || int64(exp) < time.Now().Unix() {
		return fmt.Errorf("bad claims %v %v", header, claims)
	}
	return nil
}

// find returns the user with the ID or (case-insensitive) login.
func (f *fakeOkta) find(idOrLogin string) *fakeUser {
	if u := f.users[idOrLogin]; u != nil {
		return u
	}
	for _, u := range f.users {
		if strings.EqualFold(fmt.Sprint(u.Profile["login"]), idOrLogin) {
			return u
		}
	}
	return nil
}

func (f *fakeOkta) create(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Profile map[string]any `json:"profile"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Query().Get("activate") != "false" {
		oktaErr(w, 400, "E0000001", "test expects activate=false")
		return
	}
	for _, req := range []string{"login", "email", "firstName", "lastName"} {
		if s, _ := in.Profile[req].(string); s == "" {
			oktaErr(w, 400, "E0000001", "Api validation failed: "+req, req+": The field cannot be left blank")
			return
		}
	}
	if f.find(fmt.Sprint(in.Profile["login"])) != nil {
		oktaErr(w, 400, "E0000001", "Api validation failed: login", "login: An object with this field already exists in the current organization")
		return
	}
	f.seq++
	u := &fakeUser{ID: fmt.Sprintf("00u%04d", f.seq), Status: "STAGED", Profile: in.Profile}
	f.users[u.ID] = u
	writeJSON(w, 200, u)
}

func (f *fakeOkta) get(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.find(r.PathValue("id"))
	if u == nil {
		oktaErr(w, 404, "E0000007", "Not found: Resource not found: "+r.PathValue("id")+" (User)")
		return
	}
	writeJSON(w, 200, u)
}

func (f *fakeOkta) update(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Profile     map[string]any `json:"profile"`
		Credentials *struct {
			Password struct {
				Value string `json:"value"`
			} `json:"password"`
		} `json:"credentials"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.users[r.PathValue("id")]
	if u == nil {
		oktaErr(w, 404, "E0000007", "Not found")
		return
	}
	if in.Credentials != nil {
		if len(in.Credentials.Password.Value) < 8 {
			oktaErr(w, 400, "E0000001", "Api validation failed: password",
				"password: Password requirements were not met. Password requirements: at least 8 characters.")
			return
		}
		u.password = in.Credentials.Password.Value
		if u.Status == "PROVISIONED" {
			u.Status = "ACTIVE"
		}
	}
	for k, v := range in.Profile {
		if v == nil {
			delete(u.Profile, k)
		} else {
			u.Profile[k] = v
		}
	}
	writeJSON(w, 200, u)
}

func (f *fakeOkta) lifecycle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.users[r.PathValue("id")]
	if u == nil {
		oktaErr(w, 404, "E0000007", "Not found")
		return
	}
	op := r.PathValue("op")
	bad := func() { oktaErr(w, 400, "E0000001", fmt.Sprintf("Cannot %s a user that is %s", op, u.Status)) }
	switch op {
	case "activate":
		if u.Status != "STAGED" && u.Status != "DEPROVISIONED" {
			oktaErr(w, 403, "E0000016", "Activation failed because the user is already active")
			return
		}
		u.Status = "PROVISIONED"
		if u.password != "" {
			u.Status = "ACTIVE"
		}
	case "reactivate":
		if u.Status != "PROVISIONED" {
			bad()
			return
		}
	case "suspend":
		if u.Status != "ACTIVE" {
			bad()
			return
		}
		u.Status = "SUSPENDED"
	case "unsuspend":
		if u.Status != "SUSPENDED" {
			bad()
			return
		}
		u.Status = "ACTIVE"
	case "deactivate":
		if u.Status == "DEPROVISIONED" {
			bad()
			return
		}
		u.Status = "DEPROVISIONED"
	default:
		oktaErr(w, 404, "E0000022", "unknown operation")
		return
	}
	if r.URL.Query().Get("sendEmail") == "true" {
		f.emails = append(f.emails, op+":"+u.ID)
	}
	writeJSON(w, 200, map[string]any{})
}

func (f *fakeOkta) del(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.users[r.PathValue("id")]
	if u == nil {
		oktaErr(w, 404, "E0000007", "Not found")
		return
	}
	if u.Status != "DEPROVISIONED" {
		u.Status = "DEPROVISIONED"
	} else {
		delete(f.users, u.ID)
	}
	w.WriteHeader(204)
}

func (f *fakeOkta) authn(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "" {
		oktaErr(w, 400, "E0000001", "authn must not carry the API token")
		return
	}
	var in struct{ Username, Password string }
	_ = json.NewDecoder(r.Body).Decode(&in)
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.find(in.Username)
	if u == nil || u.Status != "ACTIVE" || u.password == "" || u.password != in.Password {
		oktaErr(w, 401, "E0000004", "Authentication failed")
		return
	}
	if u.mfa {
		writeJSON(w, 200, map[string]any{"status": "MFA_REQUIRED", "stateToken": "x"})
		return
	}
	writeJSON(w, 200, map[string]any{"status": "SUCCESS", "sessionToken": "x"})
}

func (f *fakeOkta) user(id string) fakeUser {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u := f.users[id]; u != nil {
		return *u
	}
	return fakeUser{}
}

func setup(t *testing.T, extra map[string]any) (*fakeOkta, sdk.UserDirectory, *Plugin) {
	t.Helper()
	f := newFakeOkta(t)
	cfg := map[string]any{"org_url": f.URL, "api_token": apiToken}
	for k, v := range extra {
		cfg[k] = v
	}
	reg := sdktest.NewRegistrar(cfg)
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if reg.Directory == nil {
		t.Fatal("no directory registered")
	}
	return f, reg.Directory, p
}

var ada = sdk.User{ID: "u-1", Email: "Ada@Example.com", Name: "Ada King Lovelace",
	Status: sdk.UserInvited, Attributes: map[string]string{"dept": "math"}}

var fullCfg = map[string]any{"user_id_attribute": "tenariumUserId", "attribute_map": map[string]any{"dept": "department"}}

func TestRegistration(t *testing.T) {
	_, dir, p := setup(t, nil)
	if dir.Name() != "okta" {
		t.Fatalf("Name = %q", dir.Name())
	}
	if _, ok := dir.(sdk.PasswordVerifier); ok {
		t.Fatal("PasswordVerifier offered without verify_passwords")
	}
	if err := p.Health(context.Background()); err != nil {
		t.Fatalf("Health: %v", err)
	}
	_, dir, _ = setup(t, map[string]any{"verify_passwords": true})
	if _, ok := dir.(sdk.PasswordVerifier); !ok {
		t.Fatal("PasswordVerifier not offered with verify_passwords")
	}
	if _, ok := dir.(sdk.InvitationSender); !ok {
		t.Fatal("not an InvitationSender")
	}
}

func TestCreateUser(t *testing.T) {
	f, dir, _ := setup(t, fullCfg)
	ctx := context.Background()
	id, err := dir.CreateUser(ctx, ada)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	u := f.user(id)
	if u.Status != "STAGED" || u.Profile["login"] != "Ada@Example.com" || u.Profile["email"] != "Ada@Example.com" ||
		u.Profile["firstName"] != "Ada" || u.Profile["lastName"] != "King Lovelace" ||
		u.Profile["tenariumUserId"] != "u-1" || u.Profile["department"] != "math" {
		t.Fatalf("user = %+v", u)
	}
	if again, err := dir.CreateUser(ctx, ada); err != nil || again != id {
		t.Fatalf("re-create = %q, %v", again, err)
	}
	other := ada
	other.ID = "u-2"
	if _, err := dir.CreateUser(ctx, other); err == nil || !strings.Contains(err.Error(), "another Tenarium user") {
		t.Fatalf("conflict err = %v", err)
	}
	// Single names and missing names still satisfy Okta's required fields.
	id2, err := dir.CreateUser(ctx, sdk.User{ID: "u-3", Email: "grace@example.com", Status: sdk.UserDisabled})
	if err != nil {
		t.Fatal(err)
	}
	if u := f.user(id2); u.Profile["firstName"] != "grace" || u.Profile["lastName"] != "-" || u.Status != "DEPROVISIONED" {
		t.Fatalf("user = %+v", u)
	}
	if _, err := dir.CreateUser(ctx, sdk.User{ID: "u-4"}); err == nil {
		t.Fatal("want error without email")
	}
}

func TestLifecycle(t *testing.T) {
	f, dir, _ := setup(t, fullCfg)
	ctx := context.Background()
	u := ada
	var err error
	if u.ExternalID, err = dir.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	// Setting the first password activates the staged user.
	if err := dir.SetPassword(ctx, u, "short"); err == nil || !strings.Contains(err.Error(), "requirements were not met") || strings.Contains(err.Error(), "short") {
		t.Fatalf("policy err = %v", err)
	}
	if err := dir.SetPassword(ctx, u, "correct horse"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if got := f.user(u.ExternalID); got.Status != "ACTIVE" || got.password != "correct horse" {
		t.Fatalf("user = %+v", got)
	}

	// Update: email (login follows), name, attributes cleared, suspend.
	u.Email, u.Name, u.Attributes, u.Status = "ada@lovelace.org", "Ada", nil, sdk.UserDisabled
	if err := dir.UpdateUser(ctx, u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	got := f.user(u.ExternalID)
	if got.Status != "SUSPENDED" || got.Profile["login"] != "ada@lovelace.org" || got.Profile["email"] != "ada@lovelace.org" ||
		got.Profile["firstName"] != "Ada" || got.Profile["lastName"] != "-" || got.Profile["department"] != nil ||
		got.Profile["tenariumUserId"] != "u-1" {
		t.Fatalf("user = %+v", got)
	}
	if err := dir.UpdateUser(ctx, u); err != nil || f.user(u.ExternalID).Status != "SUSPENDED" {
		t.Fatalf("idempotent disable: %v", err)
	}
	u.Status = sdk.UserActive
	if err := dir.UpdateUser(ctx, u); err != nil || f.user(u.ExternalID).Status != "ACTIVE" {
		t.Fatalf("unsuspend: %v, %+v", err, f.user(u.ExternalID))
	}

	// A login that is not the email is kept.
	f.mu.Lock()
	f.users[u.ExternalID].Profile["login"] = "ada.k"
	f.mu.Unlock()
	u.Email = "ada@example.org"
	if err := dir.UpdateUser(ctx, u); err != nil || f.user(u.ExternalID).Profile["login"] != "ada.k" {
		t.Fatalf("login changed: %v %+v", err, f.user(u.ExternalID))
	}

	for range 2 {
		if err := dir.DeleteUser(ctx, u); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}
	}
	if f.user(u.ExternalID).ID != "" {
		t.Fatal("user still exists")
	}
	u.ExternalID = ""
	if err := dir.DeleteUser(ctx, u); err != nil {
		t.Fatalf("DeleteUser by login: %v", err)
	}
}

func TestDeactivateMode(t *testing.T) {
	f, dir, _ := setup(t, map[string]any{"disable_action": "deactivate"})
	ctx := context.Background()
	u := ada
	u.Status = sdk.UserActive
	var err error
	if u.ExternalID, err = dir.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := dir.SetPassword(ctx, u, "correct horse"); err != nil {
		t.Fatal(err)
	}
	u.Status = sdk.UserDisabled
	if err := dir.UpdateUser(ctx, u); err != nil || f.user(u.ExternalID).Status != "DEPROVISIONED" {
		t.Fatalf("deactivate: %v %+v", err, f.user(u.ExternalID))
	}
	u.Status = sdk.UserActive
	if err := dir.UpdateUser(ctx, u); err != nil || f.user(u.ExternalID).Status != "ACTIVE" {
		t.Fatalf("reactivate: %v %+v", err, f.user(u.ExternalID))
	}
}

func TestInvitationsAndPasswords(t *testing.T) {
	f, dir, _ := setup(t, map[string]any{"send_invitation": true, "verify_passwords": true})
	ctx := context.Background()
	u := ada
	var err error
	if u.ExternalID, err = dir.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	inv := dir.(sdk.InvitationSender)
	if err := inv.SendInvitation(ctx, u); err != nil {
		t.Fatalf("SendInvitation: %v", err)
	}
	if err := inv.SendInvitation(ctx, u); err != nil { // resend
		t.Fatalf("resend: %v", err)
	}
	if f.user(u.ExternalID).Status != "PROVISIONED" || len(f.emails) != 2 ||
		f.emails[0] != "activate:"+u.ExternalID || f.emails[1] != "reactivate:"+u.ExternalID {
		t.Fatalf("emails = %v, user = %+v", f.emails, f.user(u.ExternalID))
	}

	v := dir.(sdk.PasswordVerifier)
	if err := v.VerifyPassword(ctx, u, "correct horse"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("no password yet err = %v", err)
	}
	if err := dir.SetPassword(ctx, u, "correct horse"); err != nil {
		t.Fatal(err)
	}
	if err := v.VerifyPassword(ctx, u, "correct horse"); err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if err := v.VerifyPassword(ctx, u, "wrong password"); !errors.Is(err, ErrInvalidCredentials) || strings.Contains(err.Error(), "wrong") {
		t.Fatalf("wrong password err = %v", err)
	}
	f.mu.Lock()
	f.users[u.ExternalID].mfa = true
	f.mu.Unlock()
	if err := v.VerifyPassword(ctx, u, "correct horse"); !errors.Is(err, ErrMFARequired) {
		t.Fatalf("mfa err = %v", err)
	}
	if err := inv.SendInvitation(ctx, u); err == nil {
		t.Fatal("invitation sent to an active user")
	}

	_, dir, _ = setup(t, nil)
	if err := dir.(sdk.InvitationSender).SendInvitation(ctx, u); !errors.Is(err, sdk.ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
}

func writeKey(t *testing.T, key any) string {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestOAuth(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]crypto.Signer{"rsa": rsaKey, "ec": ecKey} {
		t.Run(name, func(t *testing.T) {
			f := newFakeOkta(t)
			f.pub, f.clientID = key.Public(), "0oa-service"
			keyFile := filepath.Join(t.TempDir(), "key.pem")
			if err := os.WriteFile(keyFile, []byte(writeKey(t, key)), 0o600); err != nil {
				t.Fatal(err)
			}
			reg := sdktest.NewRegistrar(map[string]any{"org_url": f.URL, "oauth": map[string]any{
				"client_id": "0oa-service", "private_key_file": keyFile, "key_id": "key-1"}})
			p := &Plugin{}
			if err := p.Init(context.Background(), reg); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if err := p.Health(ctx); err != nil {
				t.Fatalf("Health: %v", err)
			}
			if _, err := reg.Directory.CreateUser(ctx, ada); err != nil {
				t.Fatalf("CreateUser: %v", err)
			}
			if f.tokens != 1 {
				t.Fatalf("tokens = %d, want 1 (cached)", f.tokens)
			}
		})
	}
	// A key the server does not know is rejected.
	f := newFakeOkta(t)
	f.pub, f.clientID = rsaKey.Public(), "0oa-service"
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	reg := sdktest.NewRegistrar(map[string]any{"org_url": f.URL, "oauth": map[string]any{
		"client_id": "0oa-service", "private_key": writeKey(t, other), "key_id": "key-1"}})
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if err := p.Health(context.Background()); err == nil || !strings.Contains(err.Error(), "bad signature") {
		t.Fatalf("Health err = %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	smallRSA, _ := rsa.GenerateKey(rand.Reader, 1024)
	pemKey := writeKey(t, ecKey)
	base := func(extra map[string]any) map[string]any {
		c := map[string]any{"org_url": "https://acme.okta.com", "api_token": "x"}
		for k, v := range extra {
			c[k] = v
		}
		return c
	}
	bad := map[string]map[string]any{
		"bad url":           {"org_url": "acme.okta.com"},
		"url with path":     {"org_url": "https://acme.okta.com/api"},
		"no credentials":    {"api_token": ""},
		"both credentials":  {"oauth": map[string]any{"client_id": "c", "private_key": pemKey}},
		"oauth without key": {"api_token": "", "oauth": map[string]any{"client_id": "c"}},
		"oauth bad key":     {"api_token": "", "oauth": map[string]any{"client_id": "c", "private_key": "nope"}},
		"oauth small rsa":   {"api_token": "", "oauth": map[string]any{"client_id": "c", "private_key": writeKey(t, smallRSA)}},
		"oauth two keys":    {"api_token": "", "oauth": map[string]any{"client_id": "c", "private_key": pemKey, "private_key_file": "x"}},
		"oauth no file":     {"api_token": "", "oauth": map[string]any{"client_id": "c", "private_key_file": "/nonexistent/key.pem"}},
		"bad disable":       {"disable_action": "delete"},
		"reserved owner":    {"user_id_attribute": "login"},
		"reserved mapped":   {"attribute_map": map[string]any{"x": "email"}},
		"duplicate mapped":  {"attribute_map": map[string]any{"x": "department", "y": "department"}},
		"bad timeout":       {"timeout": "0s"},
		"unknown key":       {"nope": 1},
	}
	for name, extra := range bad {
		t.Run(name, func(t *testing.T) {
			if err := (&Plugin{}).Init(context.Background(), sdktest.NewRegistrar(base(extra))); err == nil {
				t.Fatal("want error")
			}
		})
	}
	ok := base(map[string]any{"api_token": "", "oauth": map[string]any{"client_id": "c", "private_key": pemKey}})
	if err := (&Plugin{}).Init(context.Background(), sdktest.NewRegistrar(ok)); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	sch, err := schema.Compile((&Plugin{}).Manifest().ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(base(fullCfg)); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for _, c := range []map[string]any{base(map[string]any{"nope": 1}), base(map[string]any{"disable_action": "x"}),
		base(map[string]any{"oauth": map[string]any{"private_key": "x"}}), {"api_token": "x"}} {
		if err := sch.Validate(c); err == nil {
			t.Fatalf("config %v accepted", c)
		}
	}
}
