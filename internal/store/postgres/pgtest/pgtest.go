// Package pgtest creates throwaway PostgreSQL databases for tests. Tests
// using it are skipped unless TENARIUM_TEST_POSTGRES_DSN points at a server
// where the user may create databases.
package pgtest

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/store/postgres"
	"github.com/jackc/pgx/v5"
)

var counter atomic.Int64

// DSN returns the admin DSN or skips the test.
func DSN(t testing.TB) string {
	t.Helper()
	dsn := os.Getenv("TENARIUM_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TENARIUM_TEST_POSTGRES_DSN not set")
	}
	return dsn
}

// FreshDB creates an empty database, dropped when the test ends, and
// returns its DSN.
func FreshDB(t testing.TB) string {
	t.Helper()
	admin := DSN(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	name := fmt.Sprintf("tenarium_test_%d_%d", time.Now().UnixNano(), counter.Add(1))
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(ctx, admin)
		if err != nil {
			return
		}
		defer c.Close(ctx)
		_, _ = c.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	})
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	return u.String()
}

// Open returns a migrated store on a fresh database.
func Open(t testing.TB) *postgres.Store {
	t.Helper()
	s, err := postgres.Open(context.Background(), FreshDB(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
