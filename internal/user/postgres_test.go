package user

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestIDPServerRoleCannotModifyUsers connects as the idp_server role of
// migrations/003 and checks that it can read "User" but not change it. It is
// skipped unless TEST_IDP_SERVER_DATABASE_URL is set.
func TestIDPServerRoleCannotModifyUsers(t *testing.T) {
	dsn := os.Getenv("TEST_IDP_SERVER_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_IDP_SERVER_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	s := NewPostgresStore(pool)

	writable, err := s.CanModifyUsers(ctx)
	if err != nil || writable {
		t.Fatalf("CanModifyUsers: %v %v", writable, err)
	}
	var email string
	if err := pool.QueryRow(ctx, `SELECT email FROM "User" ORDER BY id LIMIT 1`).Scan(&email); err != nil {
		t.Fatalf("idp_server cannot read \"User\": %v", err)
	}
	if _, err := s.FindByEmail(ctx, email); err != nil {
		t.Fatalf("FindByEmail: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE "User" SET email = email`); err == nil {
		t.Fatal("idp_server must not be able to update \"User\"")
	}
}
