package natsaccount

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

const testSecret = "0123456789abcdef-test-secret"

// testOperator returns a fresh operator identity, a signing key and the
// operator JWT listing it.
func testOperator(t *testing.T) (opPub, skSeed, opJWT string) {
	t.Helper()
	op, _ := nkeys.CreateOperator()
	opPub, _ = op.PublicKey()
	sk, _ := nkeys.CreateOperator()
	skPub, _ := sk.PublicKey()
	seed, _ := sk.Seed()
	oc := jwt.NewOperatorClaims(opPub)
	oc.SigningKeys.Add(skPub)
	tok, err := oc.Encode(op)
	if err != nil {
		t.Fatal(err)
	}
	return opPub, string(seed), tok
}

func TestAccountKeyPair(t *testing.T) {
	kp, err := AccountKeyPair(testSecret, "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := kp.PublicKey()
	if !nkeys.IsValidPublicAccountKey(pub) {
		t.Fatalf("not an account key: %s", pub)
	}
	seed, _ := kp.Seed()
	if !strings.HasPrefix(string(seed), "SA") {
		t.Fatalf("seed %q", seed)
	}
	// The derivation is documented: HMAC-SHA256(secret, "nats-account:"+id).
	m := hmac.New(sha256.New, []byte(testSecret))
	m.Write([]byte("nats-account:tenant-1"))
	want, _ := nkeys.FromRawSeed(nkeys.PrefixByteAccount, m.Sum(nil))
	if wp, _ := want.PublicKey(); wp != pub {
		t.Fatalf("derivation mismatch %s vs %s", wp, pub)
	}
	again, _ := TenantAccountPublicKey(testSecret, "tenant-1")
	other, _ := TenantAccountPublicKey(testSecret, "tenant-2")
	otherSecret, _ := TenantAccountPublicKey(testSecret+"x", "tenant-1")
	if again != pub || other == pub || otherSecret == pub {
		t.Fatalf("keys: %s %s %s %s", pub, again, other, otherSecret)
	}
	if _, err := AccountKeyPair("", "x"); err == nil {
		t.Fatal("expected error for empty secret")
	}
	// The key can sign user JWTs that verify against the account.
	u, _ := nkeys.CreateUser()
	upub, _ := u.PublicKey()
	uc := jwt.NewUserClaims(upub)
	tok, err := uc.Encode(kp)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := jwt.DecodeUserClaims(tok)
	if err != nil || dec.Issuer != pub {
		t.Fatalf("user JWT issuer %v, %v", dec, err)
	}
}

func TestSanitizeAndRenderName(t *testing.T) {
	for in, want := range map[string]string{
		"tenant-acme":       "tenant-acme",
		"Tenant Acme/Corp!": "Tenant-Acme-Corp",
		"a..b__c":           "a..b__c",
		"--x--":             "x",
		"ümlaut":            "mlaut",
		"":                  "",
	} {
		if got := SanitizeName(in); got != want {
			t.Errorf("SanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
	tmpl, err := parseNameTemplate(DefaultNameTemplate)
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("long-slug-", 10)
	a, _ := renderName(tmpl, sdk.Tenant{ID: "a", Slug: long})
	b, _ := renderName(tmpl, sdk.Tenant{ID: "b", Slug: long})
	if a == b || len(a) > maxNameLen || !strings.HasPrefix(a, "tenant-long-slug") {
		t.Fatalf("long names %q %q", a, b)
	}
}

func TestConfigValidation(t *testing.T) {
	opPub, skSeed, opJWT := testOperator(t)
	acc, _ := nkeys.CreateAccount()
	accSeed, _ := acc.Seed()
	otherOp, otherSeed, _ := testOperator(t)
	_ = otherOp

	strictOp, _ := nkeys.CreateOperator()
	strictPub, _ := strictOp.PublicKey()
	strictSeed, _ := strictOp.Seed()
	soc := jwt.NewOperatorClaims(strictPub)
	soc.StrictSigningKeyUsage = true
	strictJWT, _ := soc.Encode(strictOp)

	sysAcc, _ := nkeys.CreateAccount()
	user, _ := nkeys.CreateUser()
	userPub, _ := user.PublicKey()
	userSeed, _ := user.Seed()
	userJWT, _ := jwt.NewUserClaims(userPub).Encode(sysAcc)
	user2, _ := nkeys.CreateUser()
	user2Seed, _ := user2.Seed()

	credsFile := filepath.Join(t.TempDir(), "sys.creds")
	if err := os.WriteFile(credsFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	natsRes := ResolverConfig{Mode: ModeNATS, URLs: []string{"nats://localhost:4222"}}
	httpRes := ResolverConfig{Mode: ModeHTTP, URL: "http://localhost:9090/jwt/v1/"}
	base := func(c Config) Config {
		if c.OperatorSigningKey == "" {
			c.OperatorSigningKey = skSeed
		}
		if c.AccountSeedSecret == "" {
			c.AccountSeedSecret = testSecret
		}
		if c.Resolver.Mode == "" && c.Resolver.URL == "" && len(c.Resolver.URLs) == 0 {
			c.Resolver = natsRes
		}
		return c
	}
	withRes := func(r ResolverConfig) Config { return base(Config{Resolver: r}) }

	for i, tc := range []struct {
		cfg     Config
		wantErr string
	}{
		{base(Config{}), ""},
		{base(Config{OperatorPublicKey: opPub, OperatorJWT: opJWT}), ""},
		{base(Config{OperatorJWT: opJWT}), ""},
		{withRes(httpRes), ""},
		{withRes(ResolverConfig{Mode: ModeHTTP, URL: "https://acct:9090/jwt/v1", Token: "t"}), ""},
		{Config{AccountSeedSecret: testSecret, Resolver: natsRes}, "operator_signing_key is required"},
		{base(Config{OperatorSigningKey: "SOnotaseed"}), "not a valid nkey seed"},
		{base(Config{OperatorSigningKey: string(accSeed)}), "must be an operator seed"},
		{base(Config{OperatorPublicKey: "ABC"}), "operator_public_key"},
		{base(Config{OperatorJWT: "nope"}), "operator_jwt"},
		{base(Config{OperatorJWT: opJWT, OperatorPublicKey: strictPub}), "not operator_public_key"},
		{base(Config{OperatorSigningKey: otherSeed, OperatorJWT: opJWT}), "is not a signing key"},
		{base(Config{OperatorSigningKey: string(strictSeed), OperatorJWT: strictJWT}), "strict_signing_key_usage"},
		{Config{OperatorSigningKey: skSeed, Resolver: natsRes}, "account_seed_secret is required"},
		{base(Config{AccountSeedSecret: "short"}), "at least 16"},
		{Config{OperatorSigningKey: skSeed, AccountSeedSecret: testSecret}, "resolver.mode is required"},
		{withRes(ResolverConfig{Mode: "memory", URL: "x"}), "resolver.mode must be"},
		{withRes(ResolverConfig{Mode: ModeNATS, URL: "nats://x:4222"}), "resolver.urls is required"},
		{withRes(ResolverConfig{Mode: ModeNATS, URLs: []string{"http://x:4222"}}), "is not a nats://"},
		{withRes(ResolverConfig{Mode: ModeNATS, URLs: []string{"nats://x"}, URL: "http://y"}), "only used in http mode"},
		{withRes(ResolverConfig{Mode: ModeNATS, URLs: []string{"nats://x"}, Timeout: "soon"}), "resolver.timeout"},
		{withRes(ResolverConfig{Mode: ModeNATS, URLs: []string{"nats://x"}, Timeout: "-1s"}), "resolver.timeout"},
		{withRes(ResolverConfig{Mode: ModeNATS, URLs: []string{"nats://x"}, CredentialsFile: credsFile}), ""},
		{withRes(ResolverConfig{Mode: ModeNATS, URLs: []string{"nats://x"}, CredentialsFile: credsFile + ".missing"}), "credentials_file"},
		{withRes(ResolverConfig{Mode: ModeNATS, URLs: []string{"nats://x"}, UserJWT: userJWT, UserSeed: string(userSeed)}), ""},
		{withRes(ResolverConfig{Mode: ModeNATS, URLs: []string{"nats://x"}, UserJWT: userJWT}), "set together"},
		{withRes(ResolverConfig{Mode: ModeNATS, URLs: []string{"nats://x"}, UserJWT: userJWT, UserSeed: string(user2Seed)}), "must be the user seed"},
		{withRes(ResolverConfig{Mode: ModeNATS, URLs: []string{"nats://x"}, UserJWT: "bad", UserSeed: string(userSeed)}), "resolver.user_jwt"},
		{withRes(ResolverConfig{Mode: ModeNATS, URLs: []string{"nats://x"}, User: "sys", Password: "pw"}), ""},
		{withRes(ResolverConfig{Mode: ModeNATS, URLs: []string{"nats://x"}, Password: "pw"}), "requires resolver.user"},
		{withRes(ResolverConfig{Mode: ModeNATS, URLs: []string{"nats://x"}, User: "sys", Token: "t"}), "only one of"},
		{withRes(ResolverConfig{Mode: ModeNATS, URLs: []string{"nats://x"}, CAFile: "missing.pem"}), "resolver.ca_file"},
		{withRes(ResolverConfig{Mode: ModeHTTP}), "resolver.url is required"},
		{withRes(ResolverConfig{Mode: ModeHTTP, URL: "nats://x"}), "must be an http(s) URL"},
		{withRes(ResolverConfig{Mode: ModeHTTP, URL: "http://x", URLs: []string{"nats://x"}}), "only used in nats mode"},
		{withRes(ResolverConfig{Mode: ModeHTTP, URL: "http://x", User: "u"}), "only used in nats mode"},
		{base(Config{Resolver: httpRes, OnDeprovision: DeprovisionDelete}), "not supported by the http resolver"},
		{base(Config{Resolver: httpRes, OnDeprovision: DeprovisionDisable}), ""},
		{base(Config{OnDeprovision: "retain"}), "on_deprovision"},
		{base(Config{Limits: map[string]string{"conn": "connections", "data": "bytes"}}), ""},
		{base(Config{Limits: map[string]string{"cpu": "x"}}), "unknown NATS limit"},
		{base(Config{Limits: map[string]string{"conn": ""}}), "must not be empty"},
		{base(Config{Limits: map[string]string{"streams": "streams"}}), "set jetstream: true"},
		{base(Config{JetStream: true, Limits: map[string]string{"streams": "streams"}}), ""},
		{base(Config{JetStreamFeature: "js"}), "requires jetstream: true"},
		{base(Config{NameTemplate: "t-{{.Slug"}), "name_template"},
		{base(Config{NameTemplate: "t-{{.Nope}}"}), "name_template"},
		{base(Config{NameTemplate: "{{if false}}x{{end}}"}), "empty name"},
		{base(Config{NameTemplate: "static"}), "must depend on the tenant"},
	} {
		p := &Plugin{cfg: tc.cfg}
		err := p.validate()
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("case %d: unexpected error %v", i, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("case %d: error %v, want containing %q", i, err, tc.wantErr)
		}
	}

	p := &Plugin{cfg: base(Config{OperatorJWT: opJWT})}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	if p.cfg.OnDeprovision != DeprovisionDelete || p.cfg.NameTemplate != DefaultNameTemplate ||
		p.timeout != DefaultTimeout || p.operatorPub != opPub {
		t.Fatalf("defaults not applied: %+v", p.cfg)
	}
	p = &Plugin{cfg: withRes(httpRes)}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	if p.cfg.OnDeprovision != DeprovisionDisable || p.cfg.Resolver.URL != "http://localhost:9090/jwt/v1" {
		t.Fatalf("http defaults not applied: %+v", p.cfg)
	}
}

func TestConfigSchemaCompiles(t *testing.T) {
	m := (&Plugin{}).Manifest()
	if m.ID != "nats-tenant" {
		t.Fatalf("id %q", m.ID)
	}
	s, err := schema.Compile(m.ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	_, skSeed, _ := testOperator(t)
	ok := map[string]any{
		"operator_signing_key": skSeed,
		"account_seed_secret":  testSecret,
		"resolver":             map[string]any{"mode": "nats", "urls": []any{"nats://n:4222"}, "credentials_file": "/sys.creds"},
		"limits":               map[string]any{"conn": "connections", "mem_storage": "js_mem"},
		"jetstream":            true,
		"on_deprovision":       "disable",
	}
	if err := s.Validate(ok); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]map[string]any{
		"missing keys":   {"operator_signing_key": skSeed},
		"mode":           {"operator_signing_key": skSeed, "account_seed_secret": testSecret, "resolver": map[string]any{"mode": "memory"}},
		"resolver extra": {"operator_signing_key": skSeed, "account_seed_secret": testSecret, "resolver": map[string]any{"mode": "nats", "foo": 1}},
		"limits extra":   {"operator_signing_key": skSeed, "account_seed_secret": testSecret, "resolver": map[string]any{"mode": "nats"}, "limits": map[string]any{"cpu": "x"}},
		"seed":           {"operator_signing_key": "SAXX", "account_seed_secret": testSecret, "resolver": map[string]any{"mode": "nats"}},
		"deprovision":    {"operator_signing_key": skSeed, "account_seed_secret": testSecret, "resolver": map[string]any{"mode": "nats"}, "on_deprovision": "retain"},
	} {
		if err := s.Validate(bad); err == nil {
			t.Errorf("%s: expected schema error", name)
		}
	}
}

func TestInitRegisters(t *testing.T) {
	_, skSeed, _ := testOperator(t)
	for _, res := range []map[string]any{
		{"mode": "nats", "urls": []any{"nats://127.0.0.1:1"}},
		{"mode": "http", "url": "http://127.0.0.1:1/jwt/v1"},
	} {
		reg := sdktest.NewRegistrar(map[string]any{
			"operator_signing_key": skSeed, "account_seed_secret": testSecret, "resolver": res,
		})
		p := &Plugin{}
		if err := p.Init(context.Background(), reg); err != nil {
			t.Fatal(err)
		}
		if len(reg.Provisioners) != 1 || reg.Provisioners[0].Name() != "nats-account" {
			t.Fatalf("provisioners %v", reg.Provisioners)
		}
		if len(reg.Routes) != 1 || reg.Routes[0] != "GET /tenants/{tenant}" {
			t.Fatalf("routes %v", reg.Routes)
		}
		var _ sdk.HealthChecker = p
		var _ sdk.Stopper = p
		if err := p.Health(context.Background()); err == nil {
			t.Fatal("expected health error for unreachable resolver")
		}
		if err := p.Stop(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	reg := sdktest.NewRegistrar(map[string]any{"operator_signing_key": skSeed, "account_seed_secret": testSecret, "resolver": map[string]any{"mode": "nats", "urls": []any{"nats://x:1"}}, "bogus": 1})
	if err := (&Plugin{}).Init(context.Background(), reg); err == nil {
		t.Fatal("expected strict config error")
	}
}

// accountServer is a fake nats-account-server.
type accountServer struct {
	mu    sync.Mutex
	jwts  map[string]string
	posts int
}

func newAccountServer(t *testing.T) (*accountServer, *httptest.Server) {
	s := &accountServer{jwts: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /jwt/v1/{$}", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /jwt/v1/accounts/{pub}", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		tok, ok := s.jwts[r.PathValue("pub")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, tok)
	})
	mux.HandleFunc("POST /jwt/v1/accounts/{pub}", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ac, err := jwt.DecodeAccountClaims(string(b))
		if err != nil || ac.Subject != r.PathValue("pub") {
			http.Error(w, "bad jwt", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.jwts[ac.Subject] = string(b)
		s.posts++
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return s, srv
}

func (s *accountServer) get(t *testing.T, pub string) *jwt.AccountClaims {
	t.Helper()
	s.mu.Lock()
	tok, ok := s.jwts[pub]
	s.mu.Unlock()
	if !ok {
		return nil
	}
	ac, err := jwt.DecodeAccountClaims(tok)
	if err != nil {
		t.Fatal(err)
	}
	return ac
}

func (s *accountServer) put(t *testing.T, ac *jwt.AccountClaims, kp nkeys.KeyPair) {
	t.Helper()
	tok, err := ac.Encode(kp)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.jwts[ac.Subject] = tok
	s.mu.Unlock()
}

func newHTTPPlugin(t *testing.T, extra map[string]any) (*Plugin, *sdktest.Registrar, *accountServer) {
	t.Helper()
	s, srv := newAccountServer(t)
	_, skSeed, opJWT := testOperator(t)
	cfg := map[string]any{
		"operator_signing_key": skSeed,
		"operator_jwt":         opJWT,
		"account_seed_secret":  testSecret,
		"resolver":             map[string]any{"mode": "http", "url": srv.URL + "/jwt/v1"},
	}
	for k, v := range extra {
		cfg[k] = v
	}
	reg := sdktest.NewRegistrar(cfg)
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	return p, reg, s
}

func TestProvisionHTTP(t *testing.T) {
	ctx := context.Background()
	p, reg, s := newHTTPPlugin(t, map[string]any{
		"limits":            map[string]any{"conn": "connections", "data": "bytes", "payload": "payload", "disk_storage": "storage", "streams": "streams"},
		"jetstream":         true,
		"jetstream_feature": "jetstream",
	})
	if err := p.Health(ctx); err != nil {
		t.Fatal(err)
	}
	reg.HostImpl.AddPlan(sdk.Plan{ID: "pro", Features: map[string]bool{"jetstream": true},
		Limits: map[string]int64{"connections": 10, "bytes": -1, "storage": 1 << 30, "streams": 5}})
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})
	if err := p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	pub, _ := TenantAccountPublicKey(testSecret, tn.ID)
	ac := s.get(t, pub)
	if ac == nil {
		t.Fatal("account not pushed")
	}
	if ac.Issuer != p.signerPub || ac.Name != "tenant-acme" || ac.IssuedAt == 0 {
		t.Fatalf("claims %+v", ac.ClaimsData)
	}
	if !ac.Tags.Contains(TenantTag(tn.ID)) {
		t.Fatalf("tags %v", ac.Tags)
	}
	l := ac.Limits
	if l.Conn != 10 || l.Data != jwt.NoLimit || l.Payload != jwt.NoLimit || l.Subs != jwt.NoLimit ||
		l.DiskStorage != 1<<30 || l.MemoryStorage != jwt.NoLimit || l.Streams != 5 || l.Consumer != jwt.NoLimit {
		t.Fatalf("limits %+v", l)
	}
	if !l.IsJSEnabled() {
		t.Fatal("JetStream should be enabled")
	}
	// The operator trusts the signer.
	oc, _ := jwt.DecodeOperatorClaims(p.cfg.OperatorJWT)
	if !oc.DidSign(ac) {
		t.Fatal("operator does not trust the account JWT issuer")
	}

	// Idempotent.
	if err := p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if s.posts != 2 {
		t.Fatalf("posts %d", s.posts)
	}

	// Without the feature JetStream stays off; without a plan everything
	// is unlimited.
	free := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "free"})
	if err := p.Provision(ctx, free); err != nil {
		t.Fatal(err)
	}
	fpub, _ := TenantAccountPublicKey(testSecret, free.ID)
	fl := s.get(t, fpub).Limits
	if fl.IsJSEnabled() || fl.Conn != jwt.NoLimit || fl.Imports != jwt.NoLimit {
		t.Fatalf("free limits %+v", fl)
	}
}

func TestProvisionJetStreamDefault(t *testing.T) {
	p, reg, s := newHTTPPlugin(t, map[string]any{"jetstream": true})
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "js"})
	if err := p.Provision(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
	pub, _ := TenantAccountPublicKey(testSecret, tn.ID)
	l := s.get(t, pub).Limits
	if !l.IsJSEnabled() || l.DiskStorage != jwt.NoLimit || l.MemoryStorage != jwt.NoLimit {
		t.Fatalf("limits %+v", l)
	}
}

func TestOwnershipConflicts(t *testing.T) {
	ctx := context.Background()
	p, reg, s := newHTTPPlugin(t, nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "victim"})
	pub, _ := TenantAccountPublicKey(testSecret, tn.ID)

	foreign := jwt.NewAccountClaims(pub)
	foreign.Name = "someone-else"
	foreign.Tags.Add(TenantTag("other-tenant"))
	s.put(t, foreign, p.signer)
	err := p.Provision(ctx, tn)
	if !errors.Is(err, errForeign) || !strings.Contains(err.Error(), "other-tenant") {
		t.Fatalf("provision over foreign account: %v", err)
	}
	if err := p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if got := s.get(t, pub); got.Name != "someone-else" || got.Tags.Contains(TagDisabled) {
		t.Fatalf("foreign account modified: %+v", got)
	}

	unmarked := jwt.NewAccountClaims(pub)
	unmarked.Name = "manual"
	s.put(t, unmarked, p.signer)
	if err := p.Provision(ctx, tn); !errors.Is(err, errForeign) || !strings.Contains(err.Error(), "not created by Tenarium") {
		t.Fatalf("provision over unmarked account: %v", err)
	}
	if err := p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if got := s.get(t, pub); got.Name != "manual" {
		t.Fatalf("unmarked account modified: %+v", got)
	}
}

func TestDeprovisionDisableHTTP(t *testing.T) {
	ctx := context.Background()
	p, reg, s := newHTTPPlugin(t, nil)
	if p.cfg.OnDeprovision != DeprovisionDisable {
		t.Fatalf("default %q", p.cfg.OnDeprovision)
	}
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "gone"})
	// Never provisioned: nothing to do.
	if err := p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if s.posts != 0 {
		t.Fatal("deprovision of unknown account pushed a JWT")
	}
	if err := p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if err := p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	pub, _ := TenantAccountPublicKey(testSecret, tn.ID)
	ac := s.get(t, pub)
	if !ac.Tags.Contains(TagDisabled) || !ac.Tags.Contains(TenantTag(tn.ID)) || ac.Name != "tenant-gone" {
		t.Fatalf("disabled claims %+v tags %v", ac.ClaimsData, ac.Tags)
	}
	l := ac.Limits
	if l.Conn != 0 || l.Subs != 0 || l.Data != 0 || l.LeafNodeConn != 0 || l.IsJSEnabled() {
		t.Fatalf("disabled limits %+v", l)
	}
	if _, ok := ac.Revocations[jwt.All]; !ok {
		t.Fatalf("revocations %v", ac.Revocations)
	}
	posts := s.posts
	if err := p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if s.posts != posts {
		t.Fatal("second deprovision pushed again")
	}
}

func TestDeprovisionKeep(t *testing.T) {
	ctx := context.Background()
	p, reg, s := newHTTPPlugin(t, map[string]any{"on_deprovision": "keep"})
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "keep"})
	if err := p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if err := p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	pub, _ := TenantAccountPublicKey(testSecret, tn.ID)
	if ac := s.get(t, pub); ac.Tags.Contains(TagDisabled) || s.posts != 1 {
		t.Fatalf("keep modified the account")
	}
}

// memResolver is an in-memory resolver that implements delete like the
// NATS full resolver.
type memResolver struct {
	jwts        map[string]string
	allowDelete bool
	deletes     []*jwt.GenericClaims
}

func (m *memResolver) Lookup(_ context.Context, pub string) (string, error) { return m.jwts[pub], nil }
func (m *memResolver) Push(_ context.Context, pub, tok string) error {
	m.jwts[pub] = tok
	return nil
}
func (m *memResolver) Delete(_ context.Context, req string) error {
	gc, err := jwt.DecodeGeneric(req)
	if err != nil {
		return err
	}
	m.deletes = append(m.deletes, gc)
	if !m.allowDelete {
		return parseClaimsResponse([]byte(`{"error":{"account":"n/a","code":500,"description":"delete must be enabled in server config"}}`))
	}
	for _, a := range gc.Data["accounts"].([]any) {
		delete(m.jwts, a.(string))
	}
	return nil
}
func (m *memResolver) Health(context.Context) error { return nil }
func (m *memResolver) Close() error                 { return nil }

func TestDeprovisionDelete(t *testing.T) {
	ctx := context.Background()
	for _, allow := range []bool{true, false} {
		p, reg, _ := newHTTPPlugin(t, map[string]any{"on_deprovision": "keep"})
		p.cfg.OnDeprovision = DeprovisionDelete // as in nats mode
		mem := &memResolver{jwts: map[string]string{}, allowDelete: allow}
		p.res = mem
		tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "del"})
		pub, _ := TenantAccountPublicKey(testSecret, tn.ID)
		if err := p.Provision(ctx, tn); err != nil {
			t.Fatal(err)
		}
		if err := p.Deprovision(ctx, tn); err != nil {
			t.Fatal(err)
		}
		if len(mem.deletes) != 1 {
			t.Fatalf("deletes %d", len(mem.deletes))
		}
		gc := mem.deletes[0]
		if gc.Issuer != p.signerPub || gc.Subject != p.signerPub {
			t.Fatalf("delete request issuer %s subject %s", gc.Issuer, gc.Subject)
		}
		if accs, _ := gc.Data["accounts"].([]any); len(accs) != 1 || accs[0] != pub {
			t.Fatalf("delete accounts %v", gc.Data)
		}
		if allow {
			if _, ok := mem.jwts[pub]; ok {
				t.Fatal("account not deleted")
			}
		} else {
			ac, err := jwt.DecodeAccountClaims(mem.jwts[pub])
			if err != nil || !ac.Tags.Contains(TagDisabled) {
				t.Fatalf("fallback did not disable: %v %v", ac, err)
			}
		}
		// Retrying is harmless.
		if err := p.Deprovision(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParseClaimsResponse(t *testing.T) {
	for in, want := range map[string]string{
		`{"server":{},"data":{"account":"A","code":200,"message":"jwt updated"}}`:                                 "",
		`{"data":{"code":200,"message":"deleted 1 accounts"}}`:                                                    "",
		`{"error":{"account":"n/a","code":500,"description":"jwt update resulted in error - expected 3 chunks"}}`: "expected 3 chunks",
		`{"error":{"code":500,"description":"delete must be enabled in server config"}}`:                          "does not support deleting",
		`{}`:       "unexpected resolver response",
		`not json`: "unexpected resolver response",
	} {
		err := parseClaimsResponse([]byte(in))
		if want == "" {
			if err != nil {
				t.Errorf("%s: %v", in, err)
			}
		} else if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", in, err, want)
		}
	}
}

func TestTenantRoute(t *testing.T) {
	ctx := context.Background()
	p, reg, _ := newHTTPPlugin(t, nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	other := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "other"})

	get := func(principal *sdk.Principal, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if principal != nil {
			req = req.WithContext(sdk.WithPrincipal(req.Context(), principal))
		}
		rec := httptest.NewRecorder()
		reg.Mux.ServeHTTP(rec, req)
		return rec
	}
	admin := &sdk.Principal{Subject: "admin", Kind: "user"}

	rec := get(admin, "/tenants/acme")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var info TenantInfo
	_ = json.Unmarshal(rec.Body.Bytes(), &info)
	pub, _ := TenantAccountPublicKey(testSecret, tn.ID)
	if info.AccountPublicKey != pub || info.Provisioned || info.AccountJWT != "" || info.AccountName != "tenant-acme" ||
		info.SigningKey != p.signerPub || info.OperatorPublicKey != p.operatorPub || info.ResolverMode != ModeHTTP {
		t.Fatalf("info %+v", info)
	}

	if err := p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	rec = get(&sdk.Principal{Subject: "u", Kind: "user", TenantID: tn.ID}, "/tenants/"+tn.ID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	info = TenantInfo{}
	_ = json.Unmarshal(rec.Body.Bytes(), &info)
	if !info.Provisioned || info.AccountJWT == "" {
		t.Fatalf("info %+v", info)
	}
	if ac, err := jwt.DecodeAccountClaims(info.AccountJWT); err != nil || ac.Subject != pub {
		t.Fatalf("jwt %v %v", ac, err)
	}
	if strings.Contains(rec.Body.String(), testSecret) || strings.Contains(rec.Body.String(), p.cfg.OperatorSigningKey) {
		t.Fatal("response leaks a secret")
	}

	// Another tenant's principal and unknown tenants get 404.
	if rec := get(&sdk.Principal{Subject: "u", Kind: "user", TenantID: other.ID}, "/tenants/acme"); rec.Code != http.StatusNotFound {
		t.Fatalf("foreign principal: %d", rec.Code)
	}
	if rec := get(admin, "/tenants/missing"); rec.Code != http.StatusNotFound {
		t.Fatalf("missing tenant: %d", rec.Code)
	}
	if rec := get(nil, "/tenants/acme"); rec.Code != http.StatusNotFound {
		t.Fatalf("anonymous: %d", rec.Code)
	}
}

func TestHTTPResolverErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	r, err := newHTTPResolver(&ResolverConfig{URL: srv.URL, Token: "tok"}, DefaultTimeout)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := r.Lookup(ctx, "A"); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("lookup: %v", err)
	}
	if err := r.Push(ctx, "A", "x.y.z"); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("push: %v", err)
	}
	if err := r.Health(ctx); err == nil {
		t.Fatal("health should fail on 5xx")
	}
	if err := r.Delete(ctx, "x"); !errors.Is(err, errDeleteUnsupported) {
		t.Fatalf("delete: %v", err)
	}
}
