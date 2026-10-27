-- サインイン失敗の回数（総当たり・リスト型攻撃の対策）。001 と同じく idp スキーマにだけ置く。
-- Vercel では複数インスタンスが動くため、回数はメモリではなく DB で数える。
-- 起動時には作成しないので、デプロイ前に手動で適用する（再実行しても壊れない）:
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/002_login_failure.sql
-- 適用前にデプロイしても、サインインは止めずに回数制限だけが効かない（エラーログが出る）。

CREATE SCHEMA IF NOT EXISTS idp;

-- key は "email:<小文字のメールアドレス>" または "ip:<IP アドレス>"。
-- 最初の失敗から reset_at までを 1 つの区間として数える。
CREATE TABLE IF NOT EXISTS idp.login_failure (
  key      text        PRIMARY KEY,
  failures integer     NOT NULL,
  reset_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS login_failure_reset_at ON idp.login_failure (reset_at);

-- 001 と同じく、Supabase の Data API から読み書きされないよう RLS を有効にし、
-- 公開ロール向けのポリシーは作らない。
ALTER TABLE idp.login_failure ENABLE ROW LEVEL SECURITY;
