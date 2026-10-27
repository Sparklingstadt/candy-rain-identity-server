-- Candy Rain ID のプロフィール画像。ID サーバーが所有するテーブルで、
-- candy-rain-store の "User" テーブル自体は変更しない（参照するだけ）。
-- 起動時には作成しないので、デプロイ前に手動で一度だけ適用する:
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/001_user_avatar.sql

CREATE TABLE IF NOT EXISTS idp_user_avatar (
  user_id      integer     PRIMARY KEY REFERENCES "User"(id) ON DELETE CASCADE,
  content_type text        NOT NULL,
  data         bytea       NOT NULL,
  etag         text        NOT NULL,
  updated_at   timestamptz NOT NULL DEFAULT now()
);

-- Supabase では public スキーマのテーブルが Data API（PostgREST）から見えるため、
-- RLS を有効にしてポリシーは作らない（anon / authenticated からは読み書きできない）。
-- ID サーバーはテーブル所有者のロールで接続するので RLS の影響を受けない。
ALTER TABLE idp_user_avatar ENABLE ROW LEVEL SECURITY;
