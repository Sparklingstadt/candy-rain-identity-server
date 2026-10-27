package user

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAvatarID(t *testing.T) {
	a, b := NewAvatarID(), NewAvatarID()
	if a == b || !ValidAvatarID(a) || !ValidAvatarID(b) {
		t.Fatalf("ids %q %q", a, b)
	}
	for _, bad := range []string{"", "1", a + "A", a[:21], a[:21] + "!", a[:21] + "="} {
		if ValidAvatarID(bad) {
			t.Errorf("ValidAvatarID(%q) = true", bad)
		}
	}
}

// TestPostgresAvatarStore runs against a real database when
// TEST_DATABASE_URL is set. It applies the migration twice (it must be
// idempotent) and uses a user id that no real user has.
func TestPostgresAvatarStore(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	sql, err := os.ReadFile("../../migrations/001_user_avatar.sql")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := pool.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("migration: %v", err)
		}
	}

	const uid = -424242
	s := NewPostgresAvatarStore(pool)
	t.Cleanup(func() { s.Delete(ctx, uid) })
	if _, err := s.ForUser(ctx, uid); !errors.Is(err, ErrNoAvatar) {
		t.Fatalf("ForUser before Put: %v", err)
	}
	a, err := s.Put(ctx, uid, "it@mail.test", "image/png", []byte("first"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.ByID(ctx, a.ID)
	if err != nil || got.UserID != uid || got.Email != "it@mail.test" || got.ContentType != "image/png" || !bytes.Equal(got.Data, []byte("first")) {
		t.Fatalf("ByID: %+v %v", got, err)
	}
	b, err := s.Put(ctx, uid, "it@mail.test", "image/jpeg", []byte("second"))
	if err != nil || b.ID == a.ID {
		t.Fatalf("re-upload: %v, id %q", err, b.ID)
	}
	if _, err := s.ByID(ctx, a.ID); !errors.Is(err, ErrNoAvatar) {
		t.Errorf("old id still served: %v", err)
	}
	meta, err := s.ForUser(ctx, uid)
	if err != nil || meta.ID != b.ID || meta.ContentType != "image/jpeg" || meta.Data != nil {
		t.Fatalf("ForUser: %+v %v", meta, err)
	}
	// DeleteByID removes only that version of the image.
	if err := s.DeleteByID(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ByID(ctx, b.ID); err != nil {
		t.Fatalf("DeleteByID of an old id removed the current image: %v", err)
	}
	if err := s.DeleteByID(ctx, b.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ForUser(ctx, uid); !errors.Is(err, ErrNoAvatar) {
		t.Fatalf("DeleteByID kept the row: %v", err)
	}
	if _, err := s.Put(ctx, uid, "it@mail.test", "image/png", []byte("third")); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, uid); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ForUser(ctx, uid); !errors.Is(err, ErrNoAvatar) {
		t.Errorf("deleted avatar still stored: %v", err)
	}
}
