// Package user reads the accounts that candy-rain-store keeps in PostgreSQL.
package user

import (
	"context"
	"errors"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when no user matches the lookup.
var ErrNotFound = errors.New("user not found")

// User mirrors the columns of the "User" table that the identity server needs.
type User struct {
	ID           int64
	Email        string
	PasswordHash string
	FirstName    string
	LastName     string
	Role         string
}

// Subject is the stable OIDC subject. It matches the session.user.id that
// candy-rain-store already uses, so existing carts and orders stay attached.
func (u User) Subject() string {
	return strconv.FormatInt(u.ID, 10)
}

// DisplayName follows the Japanese family-name-first order used by the store.
func (u User) DisplayName() string {
	switch {
	case u.LastName == "":
		return u.FirstName
	case u.FirstName == "":
		return u.LastName
	default:
		return u.LastName + " " + u.FirstName
	}
}

// Store looks up users.
type Store interface {
	FindByEmail(ctx context.Context, email string) (User, error)
	FindByID(ctx context.Context, id int64) (User, error)
}

// PostgresStore reads the table that Prisma manages in candy-rain-store.
// It never writes: the store remains the owner of the schema and its migrations.
type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

const selectUser = `SELECT id, email, "passwordHash", "firstName", "lastName", role::text FROM "User" `

func (s *PostgresStore) FindByEmail(ctx context.Context, email string) (User, error) {
	return s.queryOne(ctx, selectUser+`WHERE email = $1`, email)
}

func (s *PostgresStore) FindByID(ctx context.Context, id int64) (User, error) {
	return s.queryOne(ctx, selectUser+`WHERE id = $1`, id)
}

func (s *PostgresStore) queryOne(ctx context.Context, sql string, arg any) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx, sql, arg).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.FirstName, &u.LastName, &u.Role)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// CanModifyUsers reports whether the connected role could change the "User"
// table. The identity server only reads it, so a true result means it runs
// with more privilege than it needs (see migrations/003_idp_server_role.sql).
func (s *PostgresStore) CanModifyUsers(ctx context.Context) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx,
		`SELECT has_table_privilege(current_user, 'public."User"', 'INSERT, UPDATE, DELETE, TRUNCATE')`,
	).Scan(&ok)
	return ok, err
}
