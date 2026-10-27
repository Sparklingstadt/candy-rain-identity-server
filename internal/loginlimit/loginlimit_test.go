package loginlimit

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// testStore runs the same checks on every Store implementation.
func testStore(t *testing.T, s Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)
	key := "test:loginlimit-" + now.Format("150405.000000000")
	window := 15 * time.Minute

	if n, err := s.Failures(ctx, key, now); err != nil || n != 0 {
		t.Fatalf("no failures yet: %d %v", n, err)
	}
	for i := 0; i < 3; i++ {
		if err := s.Fail(ctx, key, now.Add(time.Duration(i)*time.Minute), window); err != nil {
			t.Fatal(err)
		}
	}
	if n, _ := s.Failures(ctx, key, now.Add(5*time.Minute)); n != 3 {
		t.Fatalf("failures within the window: %d", n)
	}
	// The window is counted from the first failure, not the latest.
	if n, _ := s.Failures(ctx, key, now.Add(window)); n != 0 {
		t.Fatalf("failures after the window closed: %d", n)
	}
	if err := s.Fail(ctx, key, now.Add(window+time.Minute), window); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Failures(ctx, key, now.Add(window+2*time.Minute)); n != 1 {
		t.Fatalf("a failure after the window opens a new one: %d", n)
	}
	if err := s.Reset(ctx, key); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Failures(ctx, key, now.Add(window+2*time.Minute)); n != 0 {
		t.Fatalf("after reset: %d", n)
	}
}

func TestMemoryStore(t *testing.T) {
	testStore(t, NewMemoryStore())
}

// TestPostgresStore runs against a real database when TEST_DATABASE_URL is
// set. It applies the migration twice (it must be idempotent) and uses keys
// no real sign-in produces.
func TestPostgresStore(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	sql, err := os.ReadFile("../../migrations/002_login_failure.sql")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := pool.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("migration: %v", err)
		}
	}
	testStore(t, NewPostgresStore(pool))
}
