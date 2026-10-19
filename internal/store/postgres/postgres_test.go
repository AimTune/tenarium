package postgres_test

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/internal/store/postgres"
	"github.com/AimTune/tenarium/internal/store/storetest"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/jackc/pgx/v5"
)

// TestDSN returns an admin DSN from TENARIUM_TEST_POSTGRES_DSN or skips.
func testDSN(t *testing.T) string {
	dsn := os.Getenv("TENARIUM_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TENARIUM_TEST_POSTGRES_DSN not set")
	}
	return dsn
}

// freshDB creates a throwaway database and returns its DSN.
func freshDB(t *testing.T, adminDSN string) string {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	name := fmt.Sprintf("tenarium_test_%d", time.Now().UnixNano())
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(ctx, adminDSN)
		if err != nil {
			return
		}
		defer c.Close(ctx)
		_, _ = c.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	})
	u, err := url.Parse(adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + strings.TrimPrefix(name, "/")
	return u.String()
}

func open(t *testing.T, dsn string) *postgres.Store {
	t.Helper()
	s, err := postgres.Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestConformance(t *testing.T) {
	admin := testDSN(t)
	storetest.Run(t, func(t *testing.T) store.Store { return open(t, freshDB(t, admin)) })
}

func TestMigrationsAreIdempotent(t *testing.T) {
	dsn := freshDB(t, testDSN(t))
	open(t, dsn)
	open(t, dsn) // second open must not re-apply migrations
}

func TestNotify(t *testing.T) {
	s := open(t, freshDB(t, testDSN(t)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan struct{}, 1)
	go func() {
		_ = s.Listen(ctx, func() {
			select {
			case got <- struct{}{}:
			default:
			}
		})
	}()
	time.Sleep(200 * time.Millisecond) // let LISTEN register
	if err := s.InTx(ctx, func(tx store.Tx) error {
		_, err := tx.AppendEvents(ctx, storetest.Event("x"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("no notification received")
	}
}

func TestReadReplicaServesLists(t *testing.T) {
	admin := testDSN(t)
	ctx := context.Background()
	primary, err := postgres.Open(ctx, freshDB(t, admin))
	if err != nil {
		t.Fatal(err)
	}
	defer primary.Close()
	if err := primary.UseReadReplica(ctx, "postgres://nobody@127.0.0.1:1/x?connect_timeout=1"); err == nil {
		t.Fatal("unreachable replica accepted")
	}
	// A second database stands in for a replica that has not caught up.
	replicaDSN := freshDB(t, admin)
	if r, err := postgres.Open(ctx, replicaDSN); err != nil { // migrate the schema
		t.Fatal(err)
	} else {
		r.Close()
	}
	if err := primary.UseReadReplica(ctx, replicaDSN); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	tn := sdk.Tenant{ID: "01a00000-0000-7000-8000-000000000001", Slug: "rr", Name: "RR", Status: sdk.StatusActive, Version: 1, CreatedAt: now, UpdatedAt: now}
	if err := primary.InTx(ctx, func(tx store.Tx) error { return tx.CreateTenant(ctx, tn) }); err != nil {
		t.Fatal(err)
	}
	if _, err := primary.GetTenant(ctx, tn.ID); err != nil {
		t.Fatalf("single reads use the primary: %v", err)
	}
	if ts, err := primary.ListTenants(ctx, store.ListTenantsQuery{}); err != nil || len(ts) != 0 {
		t.Fatalf("lists should come from the replica: %v %v", ts, err)
	}
}
