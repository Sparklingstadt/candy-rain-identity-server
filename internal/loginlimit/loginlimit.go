// Package loginlimit counts failed sign-ins so that passwords cannot be
// guessed without limit. The counters live in PostgreSQL (idp.login_failure,
// migrations/002_login_failure.sql), because Vercel Functions run several
// instances and an in-memory counter would reset with each of them.
package loginlimit

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Store keeps fixed-window failure counters by key, such as "email:<addr>"
// or "ip:<addr>". Callers pass now so tests control the clock.
type Store interface {
	// Failures returns the failures counted for key in the window that is
	// still open at now, or 0.
	Failures(ctx context.Context, key string, now time.Time) (int, error)
	// Fail counts one failure for key. A window opens at the first failure
	// and lasts for window; a failure after it closed opens a new one.
	Fail(ctx context.Context, key string, now time.Time, window time.Duration) error
	// Reset forgets key, e.g. after a successful sign-in.
	Reset(ctx context.Context, key string) error
}

// PostgresStore reads and writes idp.login_failure.
type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (s *PostgresStore) Failures(ctx context.Context, key string, now time.Time) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT COALESCE(max(failures), 0) FROM idp.login_failure WHERE key = $1 AND reset_at > $2`, key, now,
	).Scan(&n)
	return n, err
}

func (s *PostgresStore) Fail(ctx context.Context, key string, now time.Time, window time.Duration) error {
	// One statement, so concurrent failures on several instances all count.
	_, err := s.pool.Exec(ctx, `
		INSERT INTO idp.login_failure AS f (key, failures, reset_at) VALUES ($1, 1, $3)
		ON CONFLICT (key) DO UPDATE SET
		  failures = CASE WHEN f.reset_at <= $2 THEN 1 ELSE f.failures + 1 END,
		  reset_at = CASE WHEN f.reset_at <= $2 THEN EXCLUDED.reset_at ELSE f.reset_at END`,
		key, now, now.Add(window))
	if err != nil {
		return err
	}
	// Expired rows are only noise; remove a few on each failure so the table
	// stays small without a scheduled job.
	_, err = s.pool.Exec(ctx, `
		DELETE FROM idp.login_failure WHERE key IN (
		  SELECT key FROM idp.login_failure WHERE reset_at <= $1 LIMIT 100)`, now)
	return err
}

func (s *PostgresStore) Reset(ctx context.Context, key string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM idp.login_failure WHERE key = $1`, key)
	return err
}

// MemoryStore keeps counters in memory. It is meant for tests.
type MemoryStore struct {
	mu       sync.Mutex
	counters map[string]counter
	// Err, when set, is returned by every method (to test failures).
	Err error
}

type counter struct {
	failures int
	resetAt  time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{counters: map[string]counter{}}
}

func (m *MemoryStore) Failures(_ context.Context, key string, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Err != nil {
		return 0, m.Err
	}
	c, ok := m.counters[key]
	if !ok || !c.resetAt.After(now) {
		return 0, nil
	}
	return c.failures, nil
}

func (m *MemoryStore) Fail(_ context.Context, key string, now time.Time, window time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Err != nil {
		return m.Err
	}
	c, ok := m.counters[key]
	if !ok || !c.resetAt.After(now) {
		c = counter{resetAt: now.Add(window)}
	}
	c.failures++
	m.counters[key] = c
	return nil
}

func (m *MemoryStore) Reset(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Err != nil {
		return m.Err
	}
	delete(m.counters, key)
	return nil
}
