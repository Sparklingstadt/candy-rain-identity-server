-- ID サーバー専用の DB ロール idp_server。ストアと同じ所有者ロールで接続すると、
-- ID サーバーが侵害されたときに注文・ロール・パスワードハッシュまで書き換えられるため、
-- 必要な権限だけを持つロールで接続する:
--   - public."User": サインインに使う列の SELECT だけ（書き込みは一切できない）
--   - idp スキーマ（ID サーバー自身のテーブル）: 読み書き
--
-- 001・002 を適用した後、テーブル所有者のロール（Supabase なら postgres）で適用する。
-- パスワードは psql の変数で渡し、ファイルやシェル履歴に残さない。再実行するとパスワードを更新する:
--   read -rs IDP_SERVER_PASSWORD   # openssl rand -base64 32 などで作った値を貼り付ける
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -v idp_server_password="$IDP_SERVER_PASSWORD" \
--     -f migrations/003_idp_server_role.sql
-- その後、ID サーバーの DATABASE_URL のユーザーを idp_server に替える
-- （Supabase の接続プーラー経由なら、ユーザー名は idp_server.<プロジェクト ref>）。

SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'idp_server') AS create_idp_server \gset
\if :create_idp_server
CREATE ROLE idp_server LOGIN NOINHERIT PASSWORD :'idp_server_password';
\else
ALTER ROLE idp_server LOGIN NOINHERIT PASSWORD :'idp_server_password';
\endif

-- "User" はストア（Prisma）の所有。読む列だけを許可する。
GRANT USAGE ON SCHEMA public TO idp_server;
REVOKE ALL ON public."User" FROM idp_server;
GRANT SELECT (id, email, "passwordHash", "firstName", "lastName", role) ON public."User" TO idp_server;

-- ストア側で "User" に RLS を有効にしている場合だけ、idp_server が読めるポリシーを足す
-- （RLS が無効なら何も作らない）。
DO $$
BEGIN
  IF (SELECT relrowsecurity FROM pg_class WHERE oid = 'public."User"'::regclass)
     AND NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'User' AND policyname = 'idp_server_read') THEN
    CREATE POLICY idp_server_read ON public."User" FOR SELECT TO idp_server USING (true);
  END IF;
END
$$;

-- idp スキーマは ID サーバーのもの。今後のテーブルにも同じ権限が付くようにする。
GRANT USAGE ON SCHEMA idp TO idp_server;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA idp TO idp_server;
ALTER DEFAULT PRIVILEGES IN SCHEMA idp GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO idp_server;

-- idp のテーブルは RLS を有効にしてある（Supabase の Data API 対策）。所有者でない
-- idp_server には、自分用のポリシーが要る。テーブルを足したらここにも足す。
DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['user_avatar', 'login_failure'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'idp' AND tablename = t AND policyname = 'idp_server_all') THEN
      EXECUTE format('CREATE POLICY idp_server_all ON idp.%I TO idp_server USING (true) WITH CHECK (true)', t);
    END IF;
  END LOOP;
END
$$;
