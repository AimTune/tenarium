package mongotenant

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

// MarkerCollection holds the ownership marker documents of a tenant
// database.
const MarkerCollection = "_tenarium"

// Marker document IDs.
const (
	markerOwner    = "owner"
	markerRetained = "retained"
)

// CustomDataTenantID is the customData field recording the tenant a user
// belongs to.
const CustomDataTenantID = "tenarium_tenant_id"

// marker is a document of the _tenarium collection: {_id: "owner"} while a
// tenant owns the database, {_id: "retained"} after on_deprovision: retain.
type marker struct {
	ID         string    `bson:"_id" json:"-"`
	TenantID   string    `bson:"tenant_id,omitempty" json:"tenant_id,omitempty"`
	TenantSlug string    `bson:"tenant_slug,omitempty" json:"tenant_slug,omitempty"`
	CreatedAt  time.Time `bson:"created_at,omitempty" json:"created_at,omitzero"`
	// QuotaMetric and QuotaLimit record the tenant's quota_from_limit
	// entitlement for downstream tooling; MongoDB does not enforce it.
	QuotaMetric     string    `bson:"quota_metric,omitempty" json:"quota_metric,omitempty"`
	QuotaLimit      *int64    `bson:"quota_limit,omitempty" json:"quota_limit,omitempty"`
	DeletedAt       time.Time `bson:"deleted_at,omitempty" json:"deleted_at,omitzero"`
	DeletedTenantID string    `bson:"deleted_tenant_id,omitempty" json:"deleted_tenant_id,omitempty"`
}

// role is a MongoDB role grant.
type role struct {
	Role string `bson:"role" json:"role"`
	DB   string `bson:"db" json:"db"`
}

// userInfo is what usersInfo reports about a user.
type userInfo struct {
	User       string         `bson:"user"`
	DB         string         `bson:"db"`
	Roles      []role         `bson:"roles"`
	CustomData map[string]any `bson:"customData"`
}

// tenantID returns the tenant recorded in the user's customData.
func (u userInfo) tenantID() string {
	s, _ := u.CustomData[CustomDataTenantID].(string)
	return s
}

// backend is the subset of MongoDB the plugin uses. It is an interface so
// the provisioning logic can be unit-tested without a server.
type backend interface {
	Ping(ctx context.Context) error
	// Collections lists the collections of db (none if db does not exist).
	Collections(ctx context.Context, db string) ([]string, error)
	// Markers returns the documents of db's marker collection.
	Markers(ctx context.Context, db string) ([]marker, error)
	// InsertMarker inserts m, failing with errDuplicate if its _id exists.
	InsertMarker(ctx context.Context, db string, m marker) error
	// PutMarker inserts or replaces m.
	PutMarker(ctx context.Context, db string, m marker) error
	DeleteMarker(ctx context.Context, db, id string) error
	DropDatabase(ctx context.Context, db string) error
	// User returns the user, or nil if it does not exist.
	User(ctx context.Context, authDB, name string) (*userInfo, error)
	// CreateUser fails with errDuplicate if the user exists.
	CreateUser(ctx context.Context, authDB, name, password string, roles []role, customData map[string]any) error
	UpdateUser(ctx context.Context, authDB, name, password string, roles []role, customData map[string]any) error
	// DropUser succeeds if the user does not exist.
	DropUser(ctx context.Context, authDB, name string) error
	Close(ctx context.Context) error
}

// errDuplicate reports that a marker or user already exists.
var errDuplicate = errors.New("already exists")

// MongoDB server error codes.
const (
	codeUserNotFound = 11
	codeUserExists   = 51003
)

// mongoBackend implements backend with the official driver.
type mongoBackend struct {
	client *mongo.Client
}

func connect(uri string) (*mongoBackend, error) {
	opts := options.Client().ApplyURI(uri).SetAppName("tenarium-mongodb-tenant")
	// Connect does not contact the server; failures show up in Health and
	// in provisioning.
	c, err := mongo.Connect(opts)
	if err != nil {
		return nil, err
	}
	return &mongoBackend{client: c}, nil
}

func hasCode(err error, code int) bool {
	var se mongo.ServerError
	return errors.As(err, &se) && se.HasErrorCode(code)
}

func (b *mongoBackend) Ping(ctx context.Context) error {
	return b.client.Ping(ctx, readpref.Primary())
}

func (b *mongoBackend) Close(ctx context.Context) error { return b.client.Disconnect(ctx) }

func (b *mongoBackend) Collections(ctx context.Context, db string) ([]string, error) {
	names, err := b.client.Database(db).ListCollectionNames(ctx, bson.D{})
	if err != nil {
		return nil, fmt.Errorf("list collections of %s: %w", db, err)
	}
	return names, nil
}

func (b *mongoBackend) Markers(ctx context.Context, db string) ([]marker, error) {
	cur, err := b.client.Database(db).Collection(MarkerCollection).Find(ctx, bson.D{})
	if err != nil {
		return nil, fmt.Errorf("read %s.%s: %w", db, MarkerCollection, err)
	}
	var out []marker
	if err := cur.All(ctx, &out); err != nil {
		return nil, fmt.Errorf("read %s.%s: %w", db, MarkerCollection, err)
	}
	return out, nil
}

func (b *mongoBackend) InsertMarker(ctx context.Context, db string, m marker) error {
	_, err := b.client.Database(db).Collection(MarkerCollection).InsertOne(ctx, m)
	if mongo.IsDuplicateKeyError(err) {
		return errDuplicate
	} else if err != nil {
		return fmt.Errorf("write %s.%s: %w", db, MarkerCollection, err)
	}
	return nil
}

func (b *mongoBackend) PutMarker(ctx context.Context, db string, m marker) error {
	_, err := b.client.Database(db).Collection(MarkerCollection).ReplaceOne(ctx,
		bson.D{{Key: "_id", Value: m.ID}}, m, options.Replace().SetUpsert(true))
	if err != nil {
		return fmt.Errorf("write %s.%s: %w", db, MarkerCollection, err)
	}
	return nil
}

func (b *mongoBackend) DeleteMarker(ctx context.Context, db, id string) error {
	_, err := b.client.Database(db).Collection(MarkerCollection).DeleteOne(ctx, bson.D{{Key: "_id", Value: id}})
	if err != nil {
		return fmt.Errorf("delete marker %s in %s: %w", id, db, err)
	}
	return nil
}

func (b *mongoBackend) DropDatabase(ctx context.Context, db string) error {
	if err := b.client.Database(db).Drop(ctx); err != nil {
		return fmt.Errorf("drop database %s: %w", db, err)
	}
	return nil
}

func (b *mongoBackend) User(ctx context.Context, authDB, name string) (*userInfo, error) {
	var res struct {
		Users []userInfo `bson:"users"`
	}
	cmd := bson.D{{Key: "usersInfo", Value: bson.D{{Key: "user", Value: name}, {Key: "db", Value: authDB}}}}
	if err := b.client.Database(authDB).RunCommand(ctx, cmd).Decode(&res); err != nil {
		return nil, fmt.Errorf("usersInfo %s@%s: %w", name, authDB, err)
	}
	for i := range res.Users {
		if res.Users[i].User == name && res.Users[i].DB == authDB {
			return &res.Users[i], nil
		}
	}
	return nil, nil
}

func rolesDoc(roles []role) bson.A {
	a := make(bson.A, len(roles))
	for i, r := range roles {
		a[i] = bson.D{{Key: "role", Value: r.Role}, {Key: "db", Value: r.DB}}
	}
	return a
}

func (b *mongoBackend) CreateUser(ctx context.Context, authDB, name, password string, roles []role, customData map[string]any) error {
	cmd := bson.D{
		{Key: "createUser", Value: name},
		{Key: "pwd", Value: password},
		{Key: "roles", Value: rolesDoc(roles)},
		{Key: "customData", Value: customData},
	}
	err := b.client.Database(authDB).RunCommand(ctx, cmd).Err()
	if hasCode(err, codeUserExists) {
		return errDuplicate
	} else if err != nil {
		return fmt.Errorf("createUser %s@%s: %w", name, authDB, err)
	}
	return nil
}

func (b *mongoBackend) UpdateUser(ctx context.Context, authDB, name, password string, roles []role, customData map[string]any) error {
	cmd := bson.D{
		{Key: "updateUser", Value: name},
		{Key: "pwd", Value: password},
		{Key: "roles", Value: rolesDoc(roles)},
		{Key: "customData", Value: customData},
	}
	if err := b.client.Database(authDB).RunCommand(ctx, cmd).Err(); err != nil {
		return fmt.Errorf("updateUser %s@%s: %w", name, authDB, err)
	}
	return nil
}

func (b *mongoBackend) DropUser(ctx context.Context, authDB, name string) error {
	err := b.client.Database(authDB).RunCommand(ctx, bson.D{{Key: "dropUser", Value: name}}).Err()
	if err != nil && !hasCode(err, codeUserNotFound) {
		return fmt.Errorf("dropUser %s@%s: %w", name, authDB, err)
	}
	return nil
}
