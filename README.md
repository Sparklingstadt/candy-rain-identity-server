# Candy Rain ID（candy-rain-identity-server）

[Candy Rain Store](https://github.com/Sparklingstadt/candy-rain-store) や [Candy Rain Stores](https://github.com/Sparklingstadt/candy-rain-stores) 向けの認証サーバーです。Go で書いた小さな **OpenID Connect プロバイダー**で、各サービスは「Candy Rain ID でサインイン」からこのサーバーを経由してログインします。

![ログイン画面](docs/idp-login.png)

## しくみ

```text
ブラウザ ──①サインイン──▶ candy-rain-store (Auth.js)
   │                          │
   │ ②/authorize へリダイレクト（PKCE S256）
   ▼                          │
Candy Rain ID ─③メール・パスワード照合─▶ PostgreSQL "User" テーブル（ストアと共有・読み取りのみ）
   │                          │
   │ ④認可コードを付けてストアへ戻す
   ▼                          ▼
candy-rain-store ──⑤/token でコードを ID トークンに交換（client_secret_basic）
```

- **認可コードフロー + PKCE（S256 必須）**。client は複数登録でき、それぞれに client secret・`redirect_uri`・ログアウト後の戻り先を持たせます（[複数のクライアントを登録する](#複数のクライアントを登録する)）
- ユーザーはストアの PostgreSQL の `User` テーブルを **そのまま参照**し、bcrypt でパスワードを照合します。ユーザー移行は不要で、スキーマとマイグレーションの管理はストア側のままです
- ID トークンの `sub` はストアの `User.id` なので、カート・注文はそのまま引き継がれます。`role`（`CUSTOMER` / `ADMIN`）も返すため、管理画面の権限判定も変わりません
- ID サーバー自身のサインイン状態（Cookie, 8 時間）を持つので、再ログイン時はパスワード入力を省略します（SSO）。このサインイン状態はクライアント間で共有されるため、ストアでログインした後は Candy Rain Stores にもパスワードなしでログインできます。どれかのサービスでサインアウトすると `/logout` でこの状態も消えます

## エンドポイント

| パス | 内容 |
| --- | --- |
| `GET /.well-known/openid-configuration` | Discovery |
| `GET /jwks` | ID トークン検証用の公開鍵（RS256） |
| `GET /authorize` / `POST /authorize` | ログイン画面と送信 |
| `POST /token` | 認可コード → ID トークン・アクセストークン |
| `GET/POST /userinfo` | アクセストークンでユーザー情報 |
| `GET /logout` | サインアウト（RP-Initiated Logout） |
| `GET /account` | アカウント画面（プロフィール画像の登録・削除）。未サインインならログインフォーム |
| `POST /account/avatar` | プロフィール画像のアップロード（multipart, `avatar` と `csrf_token`） |
| `POST /account/avatar/delete` | プロフィール画像の削除（`csrf_token`） |
| `GET /avatars/{sub}` | プロフィール画像（`picture` クレームの URL） |
| `GET /healthz` | ヘルスチェック |

## セキュリティ上の配慮

- `redirect_uri` は、その client に登録したものと完全一致のみ（別の client の URI は使えない）。一致しないときはリダイレクトせずエラー画面を出す（オープンリダイレクト対策）
- 認可コードは 60 秒・1 回限りで、発行先の client しか交換できない。PKCE の検証に失敗したら `invalid_grant`
- ログインフォームは CSRF トークン（ダブルサブミット Cookie）で保護
- 存在しないメールアドレスでもダミーハッシュで bcrypt 照合を行い、応答時間からアカウントの有無を推測されにくくする
- client secret・PKCE の比較は定数時間。Cookie は `HttpOnly` / `SameSite=Lax`、`ISSUER` が https のときは `Secure`
- CSP・`X-Frame-Options: DENY` などのヘッダーを付与
- `/account` の未サインイン時のログインは、フォームに URL ではなく固定の値 `next=account` を持たせ、サーバー側で固定パス `/account` にだけ戻す（任意の戻り先を受け取らないのでオープンリダイレクトにならない）。`next` がそれ以外の値なら通常の認可リクエストとして扱い、登録済みの client・`redirect_uri` でなければエラー画面になる
- 画像のアップロード・削除は、サインイン状態に加えて CSRF トークン（サインイン Cookie に紐づけた HMAC）が必要。画像の種類はファイル名や Content-Type ではなく先頭のバイト列で判定し、PNG・JPEG・WebP 以外（SVG・HTML など）は受け付けない。リクエスト全体を `http.MaxBytesReader` で制限

**認可コード**：サーバーに保存せず、`SESSION_SECRET` から作った鍵で暗号化（AES-GCM）した値をそのまま認可コードにしています。そのため複数インスタンスやサーバーレス（Vercel Functions）でも、別のインスタンスが発行したコードを交換できます。使用済みコードの記録はインスタンスごとのベストエフォートですが、再利用するには client secret と PKCE の verifier も必要です。

**制約**：ログイン試行回数の制限は未実装です。

## プロフィール画像

ユーザーは `<ISSUER>/account` でプロフィール画像を登録・削除できます（PNG・JPEG・WebP、1MB 以下）。画像は ID サーバーが所有する `idp` スキーマの `idp.user_avatar` テーブルに保存し、ストアの `User` テーブルには書き込みません。

### クライアントから使う

scope に `profile` を含めて認可すると、画像が登録されているユーザーの ID トークンと `/userinfo` に、OIDC 標準の `picture` クレームが入ります。未登録なら `picture` はありません。

```text
picture = <ISSUER>/avatars/<sub>?v=<etag>
```

- 画像を変えると `v` が変わるので、クライアントは URL をそのまま `<img src>` に使えます。`v` が現在の画像と一致するときは `Cache-Control: public, max-age=31536000, immutable`、それ以外は `public, max-age=300` で返します
- `Cross-Origin-Resource-Policy: cross-origin` を付けているので、別オリジンのページ（COEP を有効にしたページを含む）から `<img>` で表示できます。`X-Content-Type-Options: nosniff` と `ETag` も付き、`If-None-Match` には 304 を返します
- 画像がなければ 404
- `picture` はサインイン時点の値です。画像を変えた後は、クライアントで再サインインするかトークンを取り直すと新しい URL になります

Auth.js（candy-rain-stores）の OIDC プロバイダーは、既定の `profile()` で `picture` を `user.image` に入れます。

### マイグレーション（手動で一度だけ）

`idp` スキーマと `idp.user_avatar` は起動時には作成しません。デプロイ前に [migrations/001_user_avatar.sql](migrations/001_user_avatar.sql) を `DATABASE_URL` と同じデータベースに適用してください（`IF NOT EXISTS` なので、二度実行しても壊れません）。

```bash
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/001_user_avatar.sql
```

```sql
CREATE SCHEMA IF NOT EXISTS idp;

CREATE TABLE IF NOT EXISTS idp.user_avatar (
  user_id      integer     PRIMARY KEY REFERENCES public."User"(id) ON DELETE CASCADE,
  content_type text        NOT NULL,
  data         bytea       NOT NULL,
  etag         text        NOT NULL,
  updated_at   timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE idp.user_avatar ENABLE ROW LEVEL SECURITY;
```

- `idp` スキーマは ID サーバーが所有します。candy-rain-store の Prisma は `public` スキーマだけを管理するので、`idp` は見えません（`prisma migrate dev` のドリフト検出や `prisma db push` の削除対象になりません）
- `public."User"` は参照するだけで変更しません（外部キーで、ユーザーを削除すると画像も消えます）
- Supabase では Data API（PostgREST）から見えないよう RLS を有効にし、ポリシーは作りません。ID サーバーはテーブル所有者のロールで接続する前提です（別のロールで接続する場合は、そのロールに `SELECT, INSERT, UPDATE, DELETE` を付与し、RLS を回避できるようにしてください）
- 適用前にデプロイしても、サインインは止まりません（`picture` が出ないだけ）。`/account` と `/avatars` はエラーになります
- ストアの開発 DB を `prisma migrate reset` などで作り直すと、`public` スキーマごと削除されるため外部キーが外れます（`idp.user_avatar` 自体は残ります）。作り直した後は、テーブルを削除してからこのマイグレーションを再適用してください

## ローカルで動かす

Go 1.26 以降。candy-rain-store の DB（`npm run db:setup`）が起動している前提です。

```bash
cp .env.example .env   # 値を確認
set -a; . ./.env; set +a
go run ./cmd/server
```

candy-rain-store 側の `.env` に以下を追加し、`npm run dev` で起動すると、サインイン画面に「Candy Rain ID でサインイン」が表示されます。

```bash
AUTH_CANDY_RAIN_ID_ISSUER="http://localhost:8080"
AUTH_CANDY_RAIN_ID_ID="candy-rain-store"
AUTH_CANDY_RAIN_ID_SECRET="<OIDC_CLIENT_SECRET と同じ値>"
```

ストア側の変更は [docs/candy-rain-store-integration.patch](docs/candy-rain-store-integration.patch) にあります（`git am` で適用できます）。

## テスト

```bash
go test ./...
```

Discovery・JWKS、ログインから ID トークン発行・userinfo までの一連の流れ、誤ったパスワード、コードの再利用、PKCE 不一致、未登録の `redirect_uri`、CSRF、SSO とログアウトを検証しています。プロフィール画像は、`picture` クレームの有無、`/avatars` のヘッダーと 404、アップロードの検証（種類・サイズ・CSRF・未サインイン）、削除、`/account` の未サインイン時のログインとオープンリダイレクト対策を検証しています。データベースは使わず、`user.Store` と `user.AvatarStore` をメモリ上の実装に差し替えています。

## 環境変数

| 変数 | 必須 | 内容 |
| --- | --- | --- |
| `ISSUER` | ○ | 公開 URL（末尾スラッシュなし） |
| `DATABASE_URL` | ○ | ストアと同じ PostgreSQL |
| `OIDC_CLIENTS` | ※ | 複数のクライアント（JSON 配列。[下記](#複数のクライアントを登録する)） |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | ※ | クライアントを 1 つだけ登録するときの書き方 |
| `OIDC_REDIRECT_URIS` | ※ | `<ストア>/api/auth/callback/candy-rain-id`（カンマ区切り） |
| `OIDC_POST_LOGOUT_REDIRECT_URIS` | | `<ストア>/signout` |
| `SIGNING_KEY_PEM` | 本番 ○ | RSA 秘密鍵（PKCS#1 / PKCS#8）。未設定時は起動ごとに生成 |
| `SESSION_SECRET` | 本番 ○ | 32 文字以上。未設定時は起動ごとに生成 |
| `PORT` / `ADDR` | | 既定は `:8080` |
| `LOGIN_HINT` | | ログイン画面に表示する補足 |

※ `OIDC_CLIENTS` か `OIDC_CLIENT_ID` 系のどちらかで、少なくとも 1 つのクライアントが必要です。

### 複数のクライアントを登録する

`OIDC_CLIENTS` に JSON 配列で書きます。`OIDC_CLIENT_ID` 系の変数と併用でき、その場合は両方のクライアントが登録されます（既存の candy-rain-store の設定はそのままで、Candy Rain Stores を `OIDC_CLIENTS` に足せます）。client ID が重複していたり、secret・`redirect_uris` が欠けていたりすると起動しません。

```bash
OIDC_CLIENTS='[
  {
    "id": "candy-rain-stores",
    "secret": "<openssl rand -base64 32>",
    "redirect_uris": ["http://localhost:3001/api/auth/callback/candy-rain-id"],
    "post_logout_redirect_uris": ["http://localhost:3001/"]
  }
]'
```

`/logout` に `client_id` を付けると、`post_logout_redirect_uri` はその client に登録したものだけが許可されます。付けない場合はいずれかの client に登録されていれば許可されます。

## デプロイ

### Vercel

`vercel.json` で Go のフレームワークプリセットを指定しており、Vercel が `cmd/server/main.go` をそのまま Vercel Function として動かします。Vercel 上では `SIGNING_KEY_PEM` と `SESSION_SECRET` が必須です（インスタンスごとに鍵が変わるのを防ぐため、未設定だと起動しません）。

### コンテナ

`Dockerfile` でビルドできます（distroless・非 root）。Cloud Run / Fly.io / Render などでも動かせます。
