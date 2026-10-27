package user

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNoAvatar is returned when no avatar matches the lookup.
var ErrNoAvatar = errors.New("avatar not found")

// Avatar is a profile image stored by the identity server itself.
type Avatar struct {
	UserID int64
	// Email is the user's email at upload time. An avatar is only shown
	// while it still matches the current "User".email, so a row left behind
	// for a deleted user is never attached to a new user who reuses the id.
	Email string
	// ID is random and changes on every upload. It is the only handle on
	// the image (<ISSUER>/avatars/<ID>), so avatars cannot be enumerated.
	ID          string
	ContentType string
	Data        []byte
	UpdatedAt   time.Time
}

// BelongsTo reports whether the avatar may be shown for u.
func (a Avatar) BelongsTo(u User) bool {
	return a.UserID == u.ID && a.Email == u.Email
}

// avatarIDLen is the length of a 128-bit id in unpadded base64url.
const avatarIDLen = 22

// NewAvatarID returns a random 128-bit id in unpadded base64url.
func NewAvatarID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// ValidAvatarID reports whether id has the shape NewAvatarID produces.
func ValidAvatarID(id string) bool {
	if len(id) != avatarIDLen {
		return false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(id)
	return err == nil && len(b) == 16
}

// AvatarStore keeps profile images in the identity server's own schema
// (idp.user_avatar). It never touches the "User" table, which belongs to
// candy-rain-store.
type AvatarStore interface {
	// ForUser returns the avatar of a user without its bytes, or ErrNoAvatar.
	ForUser(ctx context.Context, userID int64) (Avatar, error)
	// ByID returns the avatar with its bytes, or ErrNoAvatar.
	ByID(ctx context.Context, id string) (Avatar, error)
	// Put stores or replaces the user's image under a new random id.
	Put(ctx context.Context, userID int64, email, contentType string, data []byte) (Avatar, error)
	// Delete removes the user's image. Deleting a missing image is not an error.
	Delete(ctx context.Context, userID int64) error
	// DeleteByID removes the image only while it still has this id, so a
	// stale row can be cleaned up without racing a new upload.
	DeleteByID(ctx context.Context, id string) error
}

// PostgresAvatarStore reads and writes idp.user_avatar
// (migrations/001_user_avatar.sql). The table is created by hand, not at
// startup.
type PostgresAvatarStore struct {
	pool *pgxpool.Pool
}

func NewPostgresAvatarStore(pool *pgxpool.Pool) *PostgresAvatarStore {
	return &PostgresAvatarStore{pool: pool}
}

func (s *PostgresAvatarStore) ForUser(ctx context.Context, userID int64) (Avatar, error) {
	a := Avatar{UserID: userID}
	err := s.pool.QueryRow(ctx,
		`SELECT email, avatar_id, content_type, updated_at FROM idp.user_avatar WHERE user_id = $1`, userID,
	).Scan(&a.Email, &a.ID, &a.ContentType, &a.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Avatar{}, ErrNoAvatar
	}
	return a, err
}

func (s *PostgresAvatarStore) ByID(ctx context.Context, id string) (Avatar, error) {
	a := Avatar{ID: id}
	err := s.pool.QueryRow(ctx,
		`SELECT user_id, email, content_type, data, updated_at FROM idp.user_avatar WHERE avatar_id = $1`, id,
	).Scan(&a.UserID, &a.Email, &a.ContentType, &a.Data, &a.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Avatar{}, ErrNoAvatar
	}
	return a, err
}

func (s *PostgresAvatarStore) Put(ctx context.Context, userID int64, email, contentType string, data []byte) (Avatar, error) {
	a := Avatar{UserID: userID, Email: email, ID: NewAvatarID(), ContentType: contentType, Data: data}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO idp.user_avatar (user_id, email, avatar_id, content_type, data, updated_at)
		VALUES ($1, $2, $3, $4, $5, now())
		ON CONFLICT (user_id) DO UPDATE
		SET email = EXCLUDED.email, avatar_id = EXCLUDED.avatar_id, content_type = EXCLUDED.content_type,
		    data = EXCLUDED.data, updated_at = now()
		RETURNING updated_at`,
		a.UserID, a.Email, a.ID, a.ContentType, a.Data,
	).Scan(&a.UpdatedAt)
	return a, err
}

func (s *PostgresAvatarStore) Delete(ctx context.Context, userID int64) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM idp.user_avatar WHERE user_id = $1`, userID)
	return err
}

func (s *PostgresAvatarStore) DeleteByID(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM idp.user_avatar WHERE avatar_id = $1`, id)
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

func (m *MemoryAvatarStore) ForUser(_ context.Context, userID int64) (Avatar, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.avatars[userID]
	if !ok {
		return Avatar{}, ErrNoAvatar
	}
	a.Data = nil
	return a, nil
}

func (m *MemoryAvatarStore) ByID(_ context.Context, id string) (Avatar, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.avatars {
		if a.ID == id {
			a.Data = append([]byte(nil), a.Data...)
			return a, nil
		}
	}
	return Avatar{}, ErrNoAvatar
}

func (m *MemoryAvatarStore) Put(_ context.Context, userID int64, email, contentType string, data []byte) (Avatar, error) {
	a := Avatar{
		UserID:      userID,
		Email:       email,
		ID:          NewAvatarID(),
		ContentType: contentType,
		Data:        append([]byte(nil), data...),
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

func (m *MemoryAvatarStore) DeleteByID(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for uid, a := range m.avatars {
		if a.ID == id {
			delete(m.avatars, uid)
		}
	}
	return nil
}
