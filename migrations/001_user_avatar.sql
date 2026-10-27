-- Candy Rain ID のプロフィール画像。ID サーバーが所有する idp スキーマに置く。
-- candy-rain-store の Prisma は public スキーマだけを管理するので、このスキーマは
-- 見えない（migrate dev のドリフト検出や db push の削除対象にならない）。
-- public."User" は参照するだけで変更しない。
-- 起動時には作成しないので、デプロイ前に手動で適用する（再実行しても壊れない）:
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/001_user_avatar.sql

CREATE SCHEMA IF NOT EXISTS idp;

CREATE TABLE IF NOT EXISTS idp.user_avatar (
  user_id      integer     PRIMARY KEY REFERENCES public."User"(id) ON DELETE CASCADE,
  content_type text        NOT NULL,
  data         bytea       NOT NULL,
  etag         text        NOT NULL,
  updated_at   timestamptz NOT NULL DEFAULT now()
);

-- Supabase の Data API から読み書きされないよう RLS を有効にし、ポリシーは作らない。
-- ID サーバーはテーブル所有者のロールで接続するので RLS の影響を受けない。
ALTER TABLE idp.user_avatar ENABLE ROW LEVEL SECURITY;
