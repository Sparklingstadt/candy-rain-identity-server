-- Candy Rain ID のプロフィール画像。ID サーバーが所有する idp スキーマにだけ置き、
-- candy-rain-store が管理する public スキーマ（"User" テーブルを含む）には
-- 外部キー・トリガーを含め何も作らない。candy-rain-store の Prisma は public だけを
-- 管理するので、このスキーマは見えない。
-- 起動時には作成しないので、デプロイ前に手動で適用する（再実行しても壊れない）:
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/001_user_avatar.sql

CREATE SCHEMA IF NOT EXISTS idp;

-- 以前の下書き（外部キー付き・etag 列のもの）を適用済みだと、下の
-- CREATE TABLE IF NOT EXISTS は何もせずに通り、実行時に列がないエラーになる。
-- そうならないよう、ここで止める。
DO $$
BEGIN
  IF to_regclass('idp.user_avatar') IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'idp' AND table_name = 'user_avatar' AND column_name = 'avatar_id'
  ) THEN
    RAISE EXCEPTION 'idp.user_avatar is from an earlier draft: DROP TABLE idp.user_avatar (and public.idp_user_avatar), then apply this file again';
  END IF;
END
$$;

-- user_id は "User".id だが、外部キーにはしない。代わりにアップロード時の
-- email を保存し、現在の "User".email と一致するときだけ画像を出す
-- （ユーザー削除や開発 DB の作り直しで id が再利用されても、別人に付かない）。
-- avatar_id は 128 ビットの乱数（base64url）で、アップロードのたびに変わる。
CREATE TABLE IF NOT EXISTS idp.user_avatar (
  user_id      integer     PRIMARY KEY,
  email        text        NOT NULL,
  avatar_id    text        NOT NULL UNIQUE,
  content_type text        NOT NULL,
  data         bytea       NOT NULL,
  updated_at   timestamptz NOT NULL DEFAULT now()
);

-- Supabase の Data API から読み書きされないよう RLS を有効にし、ポリシーは作らない。
-- ID サーバーは専用ロール idp_server で接続し、003_idp_server_role.sql で作るポリシーで読み書きする。
ALTER TABLE idp.user_avatar ENABLE ROW LEVEL SECURITY;
