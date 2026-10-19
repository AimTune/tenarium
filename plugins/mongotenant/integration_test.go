package mongotenant

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Integration tests run against the MongoDB server named by
// TENARIUM_TEST_MONGODB_URI, an administrative connection string such as
// mongodb://root:pw@127.0.0.1:27017/?authSource=admin. The server must
// have authentication enabled so the tenant users' logins are checked.

func testURI(t *testing.T) string {
	t.Helper()
	u := os.Getenv("TENARIUM_TEST_MONGODB_URI")
	if u == "" {
		t.Skip("TENARIUM_TEST_MONGODB_URI not set")
	}
	return u
}

func randHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func newRealPlugin(t *testing.T, cfg map[string]any) (*Plugin, *sdktest.Registrar) {
	t.Helper()
	full := map[string]any{"uri": testURI(t), "password_secret": "integration-secret-0123456789"}
	for k, v := range cfg {
		full[k] = v
	}
	reg := sdktest.NewRegistrar(full)
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Stop(context.Background()) })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := p.Health(ctx); err != nil {
		t.Fatalf("health: %v", err)
	}
	return p, reg
}

// adminClient connects with the admin URI for assertions and cleanup.
func adminClient(t *testing.T) *mongo.Client {
	t.Helper()
	c, err := mongo.Connect(options.Client().ApplyURI(testURI(t)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Disconnect(context.Background()) })
	return c
}

// cleanup drops db and the user at the end of the test.
func cleanup(t *testing.T, c *mongo.Client, db, authDB, user string) {
	t.Cleanup(func() {
		ctx := context.Background()
		_ = c.Database(authDB).RunCommand(ctx, bson.D{{Key: "dropUser", Value: user}}).Err()
		_ = c.Database(db).Drop(ctx)
	})
}

// tenantInfo calls the plugin route as a platform admin.
func tenantInfo(t *testing.T, reg *sdktest.Registrar, slug string) TenantInfo {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/tenants/"+slug+"?include_password=true", nil)
	req = req.WithContext(sdk.WithPrincipal(req.Context(), &sdk.Principal{Subject: "admin", Kind: "user"}))
	rec := httptest.NewRecorder()
	reg.Mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("route: %d %s", rec.Code, rec.Body)
	}
	var info TenantInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	return info
}

// loginAndWrite connects as the tenant user and inserts a document into
// its database. It returns the connection error, if any.
func loginAndWrite(ctx context.Context, info TenantInfo, password string) error {
	opts := options.Client().ApplyURI(info.URI).
		SetAuth(options.Credential{Username: info.User, Password: password, AuthSource: info.AuthDatabase}).
		SetServerSelectionTimeout(5 * time.Second)
	c, err := mongo.Connect(opts)
	if err != nil {
		return err
	}
	defer func() { _ = c.Disconnect(ctx) }()
	_, err = c.Database(info.Database).Collection("items").InsertOne(ctx, bson.D{{Key: "hello", Value: "world"}})
	return err
}

func collections(t *testing.T, c *mongo.Client, db string) []string {
	t.Helper()
	names, err := c.Database(db).ListCollectionNames(context.Background(), bson.D{})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(names)
	return names
}

func TestIntegrationLifecycle(t *testing.T) {
	ctx := context.Background()
	p, reg := newRealPlugin(t, map[string]any{"roles": []any{"readWrite", "dbAdmin"}})
	c := adminClient(t)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "it-" + randHex(t)})
	tg, err := p.target(tn)
	if err != nil {
		t.Fatal(err)
	}
	cleanup(t, c, tg.Database, tg.AuthDatabase, tg.User)

	for range 2 {
		if err := p.Provision(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	info := tenantInfo(t, reg, tn.Slug)
	if strings.Contains(info.URI, "root") || info.Password == "" {
		t.Fatalf("info %+v", info)
	}
	if err := loginAndWrite(ctx, info, info.Password); err != nil {
		t.Fatalf("tenant login/write: %v", err)
	}
	if err := loginAndWrite(ctx, info, "wrong-password"); err == nil {
		t.Fatal("wrong password accepted")
	}
	if got := collections(t, c, tg.Database); !slices.Equal(got, []string{MarkerCollection, "items"}) {
		t.Fatalf("collections %v", got)
	}
	u, err := p.db.User(ctx, tg.AuthDatabase, tg.User)
	if err != nil || u == nil || u.tenantID() != tn.ID || len(u.Roles) != 2 {
		t.Fatalf("user %+v, %v", u, err)
	}

	// Rotating the secret: the old password stops working.
	p.cfg.PasswordSecret = "rotated-integration-secret"
	if err := p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if err := loginAndWrite(ctx, info, info.Password); err == nil {
		t.Fatal("old password still accepted after rotation")
	}
	if err := loginAndWrite(ctx, info, TenantPassword("rotated-integration-secret", tn.ID)); err != nil {
		t.Fatalf("rotated password: %v", err)
	}

	// Another tenant with the same name cannot take it over.
	clash := reg.HostImpl.AddTenant(sdk.Tenant{Slug: tn.Slug})
	if err := p.Provision(ctx, clash); err == nil || !strings.Contains(err.Error(), "belongs to another tenant") {
		t.Fatalf("clash: %v", err)
	}
	if err := p.Deprovision(ctx, clash); err != nil {
		t.Fatal(err)
	}
	if got := collections(t, c, tg.Database); len(got) != 2 {
		t.Fatalf("other tenant's deprovision touched data: %v", got)
	}

	for range 2 {
		if err := p.Deprovision(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	if got := collections(t, c, tg.Database); len(got) != 0 {
		t.Fatalf("database not dropped: %v", got)
	}
	if u, err := p.db.User(ctx, tg.AuthDatabase, tg.User); err != nil || u != nil {
		t.Fatalf("user not dropped: %+v, %v", u, err)
	}
}

func TestIntegrationAdminAuthRetain(t *testing.T) {
	ctx := context.Background()
	p, reg := newRealPlugin(t, map[string]any{
		"auth_database": "admin", "user_template": "app_{{.Slug}}", "on_deprovision": "retain",
		"quota_from_limit": "storage_gb",
	})
	c := adminClient(t)
	reg.HostImpl.AddPlan(sdk.Plan{ID: "pro", Limits: map[string]int64{"storage_gb": 10}})
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "it-" + randHex(t), Plan: "pro"})
	tg, err := p.target(tn)
	if err != nil {
		t.Fatal(err)
	}
	if tg.AuthDatabase != "admin" || !strings.HasPrefix(tg.User, "app_") {
		t.Fatalf("target %+v", tg)
	}
	cleanup(t, c, tg.Database, tg.AuthDatabase, tg.User)

	if err := p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	info := tenantInfo(t, reg, tn.Slug)
	if !strings.Contains(info.URI, "authSource=admin") {
		t.Fatalf("uri %s", info.URI)
	}
	if err := loginAndWrite(ctx, info, info.Password); err != nil {
		t.Fatalf("tenant login/write: %v", err)
	}
	// The tenant user cannot write to another database.
	other := info
	other.Database = "tenarium_it_forbidden"
	if err := loginAndWrite(ctx, other, info.Password); err == nil {
		_ = c.Database(other.Database).Drop(ctx)
		t.Fatal("tenant user could write outside its database")
	}
	ms, err := p.markers(ctx, tg.Database)
	if err != nil || ms.owner == nil || ms.owner.QuotaLimit == nil || *ms.owner.QuotaLimit != 10 {
		t.Fatalf("owner marker %+v, %v", ms.owner, err)
	}

	for range 2 {
		if err := p.Deprovision(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	ms, err = p.markers(ctx, tg.Database)
	if err != nil || ms.owner != nil || ms.retained == nil || ms.retained.DeletedTenantID != tn.ID {
		t.Fatalf("markers %+v, %v", ms, err)
	}
	if got := collections(t, c, tg.Database); !slices.Contains(got, "items") {
		t.Fatalf("data not retained: %v", got)
	}
	if u, err := p.db.User(ctx, tg.AuthDatabase, tg.User); err != nil || u != nil {
		t.Fatalf("user not dropped: %+v, %v", u, err)
	}
	again := reg.HostImpl.AddTenant(sdk.Tenant{Slug: tn.Slug})
	if err := p.Provision(ctx, again); err == nil || !strings.Contains(err.Error(), "retained from deleted tenant") {
		t.Fatalf("retained data adopted: %v", err)
	}
}

func TestIntegrationUnmanaged(t *testing.T) {
	ctx := context.Background()
	p, reg := newRealPlugin(t, nil)
	c := adminClient(t)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "it-" + randHex(t)})
	tg, err := p.target(tn)
	if err != nil {
		t.Fatal(err)
	}
	cleanup(t, c, tg.Database, tg.AuthDatabase, tg.User)

	if _, err := c.Database(tg.Database).Collection("foreign").InsertOne(ctx, bson.D{{Key: "x", Value: 1}}); err != nil {
		t.Fatal(err)
	}
	if err := p.Provision(ctx, tn); err == nil || !strings.Contains(err.Error(), "not managed by tenarium") {
		t.Fatalf("unmarked data adopted: %v", err)
	}
	if err := p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if got := collections(t, c, tg.Database); !slices.Equal(got, []string{"foreign"}) {
		t.Fatalf("unmanaged database touched: %v", got)
	}

	// An unmarked user is not adopted either.
	if err := c.Database(tg.Database).Collection("foreign").Drop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Database(tg.AuthDatabase).RunCommand(ctx, bson.D{
		{Key: "createUser", Value: tg.User}, {Key: "pwd", Value: "x"}, {Key: "roles", Value: bson.A{}},
	}).Err(); err != nil {
		t.Fatal(err)
	}
	if err := p.Provision(ctx, tn); err == nil || !strings.Contains(err.Error(), "is not managed by tenarium") {
		t.Fatalf("unmarked user adopted: %v", err)
	}
}
