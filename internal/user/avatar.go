package user

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNoAvatar is returned when the user has not registered a profile image.
var ErrNoAvatar = errors.New("user has no avatar")

// Avatar is a profile image stored by the identity server itself.
type Avatar struct {
	ContentType string
	Data        []byte
	// ETag identifies the image bytes. It is also the ?v= value of the
	// picture URL, so a new image gets a new URL.
	ETag      string
	UpdatedAt time.Time
}

// AvatarETag derives the version tag from the image bytes.
func AvatarETag(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:16])
}

// AvatarStore keeps profile images in a table owned by the identity server
// (idp_user_avatar), never in the "User" table, which belongs to
// candy-rain-store.
type AvatarStore interface {
	// Get returns the image, or ErrNoAvatar.
	Get(ctx context.Context, userID int64) (Avatar, error)
	// ETag returns only the version tag, or ErrNoAvatar. It is used to build
	// the picture claim without loading the bytes.
	ETag(ctx context.Context, userID int64) (string, error)
	// Put stores or replaces the image.
	Put(ctx context.Context, userID int64, contentType string, data []byte) (Avatar, error)
	// Delete removes the image. Deleting a missing image is not an error.
	Delete(ctx context.Context, userID int64) error
}

// PostgresAvatarStore reads and writes idp_user_avatar
// (migrations/001_user_avatar.sql). The table is created by hand, not at
// startup.
type PostgresAvatarStore struct {
	pool *pgxpool.Pool
}

func NewPostgresAvatarStore(pool *pgxpool.Pool) *PostgresAvatarStore {
	return &PostgresAvatarStore{pool: pool}
}

func (s *PostgresAvatarStore) Get(ctx context.Context, userID int64) (Avatar, error) {
	var a Avatar
	err := s.pool.QueryRow(ctx,
		`SELECT content_type, data, etag, updated_at FROM idp_user_avatar WHERE user_id = $1`, userID,
	).Scan(&a.ContentType, &a.Data, &a.ETag, &a.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Avatar{}, ErrNoAvatar
	}
	return a, err
}

func (s *PostgresAvatarStore) ETag(ctx context.Context, userID int64) (string, error) {
	var etag string
	err := s.pool.QueryRow(ctx, `SELECT etag FROM idp_user_avatar WHERE user_id = $1`, userID).Scan(&etag)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNoAvatar
	}
	return etag, err
}

func (s *PostgresAvatarStore) Put(ctx context.Context, userID int64, contentType string, data []byte) (Avatar, error) {
	a := Avatar{ContentType: contentType, Data: data, ETag: AvatarETag(data)}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO idp_user_avatar (user_id, content_type, data, etag, updated_at)
		VALUES ($1, $2, $3, $4, now())
		ON CONFLICT (user_id) DO UPDATE
		SET content_type = EXCLUDED.content_type, data = EXCLUDED.data, etag = EXCLUDED.etag, updated_at = now()
		RETURNING updated_at`,
		userID, a.ContentType, a.Data, a.ETag,
	).Scan(&a.UpdatedAt)
	return a, err
}

func (s *PostgresAvatarStore) Delete(ctx context.Context, userID int64) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM idp_user_avatar WHERE user_id = $1`, userID)
	return err
}

// MemoryAvatarStore keeps images in memory. It is meant for tests.
type MemoryAvatarStore struct {
	mu      sync.Mutex
	avatars map[int64]Avatar
	// Now is overridable in tests.
	Now func() time.Time
}

func NewMemoryAvatarStore() *MemoryAvatarStore {
	return &MemoryAvatarStore{avatars: map[int64]Avatar{}, Now: time.Now}
}

func (m *MemoryAvatarStore) Get(_ context.Context, userID int64) (Avatar, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.avatars[userID]
	if !ok {
		return Avatar{}, ErrNoAvatar
	}
	a.Data = append([]byte(nil), a.Data...)
	return a, nil
}

func (m *MemoryAvatarStore) ETag(ctx context.Context, userID int64) (string, error) {
	a, err := m.Get(ctx, userID)
	return a.ETag, err
}

func (m *MemoryAvatarStore) Put(_ context.Context, userID int64, contentType string, data []byte) (Avatar, error) {
	a := Avatar{
		ContentType: contentType,
		Data:        append([]byte(nil), data...),
		ETag:        AvatarETag(data),
		UpdatedAt:   m.Now().UTC().Truncate(time.Second),
	}
	m.mu.Lock()
	m.avatars[userID] = a
	m.mu.Unlock()
	return a, nil
}

func (m *MemoryAvatarStore) Delete(_ context.Context, userID int64) error {
	m.mu.Lock()
	delete(m.avatars, userID)
	m.mu.Unlock()
	return nil
}
