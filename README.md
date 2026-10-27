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
| `GET /avatars/{id}` | プロフィール画像（`picture` クレームの URL。`id` は推測できない乱数） |
| `GET /healthz` | ヘルスチェック |

## セキュリティ上の配慮

- `redirect_uri` は、その client に登録したものと完全一致のみ（別の client の URI は使えない）。一致しないときはリダイレクトせずエラー画面を出す（オープンリダイレクト対策）
- 認可コードは 60 秒・1 回限りで、発行先の client しか交換できない。PKCE の検証に失敗したら `invalid_grant`
- ログインフォームは CSRF トークン（ダブルサブミット Cookie）で保護
- 存在しないメールアドレスでもダミーハッシュで bcrypt 照合を行い、応答時間からアカウントの有無を推測されにくくする
- client secret・PKCE の比較は定数時間。Cookie は `HttpOnly` / `SameSite=Lax`、`ISSUER` が https のときは `Secure`
- CSP・`X-Frame-Options: DENY` などのヘッダーを付与
- `/account` の未サインイン時のログインは、フォームに URL ではなく固定の値 `next=account` を持たせ、サーバー側で固定パス `/account` にだけ戻す（任意の戻り先を受け取らないのでオープンリダイレクトにならない）。`next` がそれ以外の値なら通常の認可リクエストとして扱い、登録済みの client・`redirect_uri` でなければエラー画面になる
- `/account` のログインフォームは、クライアントのログインフォームとは別の CSRF Cookie を使う（別タブで開いているストアのログインを壊さない）
- 画像のアップロード・削除は、サインイン状態に加えて CSRF トークン（サインイン Cookie に紐づけた HMAC）が必要。結果はすべて固定のコード付きで `/account` へリダイレクトし、URL の値をそのまま画面に出さない
- 画像の種類はファイル名や Content-Type ではなく先頭のバイト列で判定し、PNG・JPEG・WebP 以外（SVG・HTML など）は受け付けない。デコードの前に縦横 2048 ピクセル・300 万画素を超えるものを拒否し、デコード・縮小・再エンコードした画像だけを保存する（[プロフィール画像](#プロフィール画像)）。デコードは多くのメモリを使うため、同時に 2 件までに制限し、空きを 5 秒待っても空かなければ「混み合っています」と表示して断る（待ち行列を無制限に伸ばさない）。リクエスト全体を `http.MaxBytesReader` で制限

**認可コード**：サーバーに保存せず、`SESSION_SECRET` から作った鍵で暗号化（AES-GCM）した値をそのまま認可コードにしています。そのため複数インスタンスやサーバーレス（Vercel Functions）でも、別のインスタンスが発行したコードを交換できます。使用済みコードの記録はインスタンスごとのベストエフォートですが、再利用するには client secret と PKCE の verifier も必要です。

**制約**：ログイン試行回数の制限は未実装です。

## プロフィール画像

ユーザーは `<ISSUER>/account` でプロフィール画像を登録・削除できます（PNG・JPEG・WebP、1MB 以下、縦横 2048 ピクセル以下かつ 300 万画素（2048×1536）以下）。スマートフォンの写真は、端末やアプリで縮小してからアップロードしてください。

画像は ID サーバー自身の `idp` スキーマ（`idp.user_avatar` テーブル）にだけ保存します。ID サーバーが書き込むのはこのスキーマだけです。ストアの `User` テーブルには、書き込みも、外部キー・トリガーの追加もしません（読み取るだけです）。

### クライアントから使う

scope に `profile` を含めて認可すると、画像が登録されているユーザーの ID トークンと `/userinfo` に、OIDC 標準の `picture` クレームが入ります。未登録なら `picture` はありません。

```text
picture = <ISSUER>/avatars/<id>
```

- `<id>` は 128 ビットの乱数（base64url）で、アップロードのたびに変わります。`sub` からは推測できないので、画像を総当たりで集めることはできません
- id が変われば URL も変わるため、`Cache-Control: public, max-age=31536000, immutable` で返します。クライアントは URL をそのまま `<img src>` に使えます
- `Cross-Origin-Resource-Policy: cross-origin` を付けているので、別オリジンのページ（COEP を有効にしたページを含む）から `<img>` で表示できます。ほかに `X-Content-Type-Options: nosniff`、`Content-Security-Policy: default-src 'none'; sandbox`、`ETag` も付き、`If-None-Match` には 304 を返します
- 存在しない id、差し替え・削除済みの id は 404
- `picture` はサインイン時点の値です。画像を変えた後は、クライアントで再サインインするかトークンを取り直すと新しい URL になります
- 画像の読み込みに失敗したとき（DB の障害やマイグレーション前など）は、サインインを止めずに `picture` を省きます（ログには ERROR を出します）。クライアントからは「画像なし」と区別できません

Auth.js（candy-rain-stores）の OIDC プロバイダーは、既定の `profile()` で `picture` を `user.image` に入れます。

### プライバシー

- 画像は URL を知っていれば誰でも見られます。サインインしたすべてのクライアント（ストアなど）に `picture` として渡ります
- アップロードされた画像はいったんデコードし、512×512 に収まるよう縮小して再エンコードしたものだけを保存・配信します（JPEG は品質 85 の JPEG、PNG・WebP は PNG）。JPEG の EXIF の向き（Orientation）は再エンコードの前に画素へ反映するので、スマートフォンの写真も正しい向きで表示されます（PNG・WebP に埋め込まれた EXIF の向きは反映しません。まれですが、その場合は横向きのまま保存されます）。EXIF（撮影場所の GPS・機種・日時など）や、その他のメタデータは残りません。デコードできない画像は「画像を読み込めませんでした」で拒否します
- 削除・差し替えた画像はサーバーからは配信されなくなりますが、ブラウザーや共有キャッシュに残ったコピーは最長 1 年残ることがあります（URL を知っている人のキャッシュに限られます）
- 画像にはアップロード時のメールアドレスを記録し、現在の `User.email` と一致するときだけ表示します。ユーザー削除や開発 DB の作り直しで同じ id が別の人に再利用されても、前の人の画像は表示されません

### マイグレーション（手動で一度だけ）

`idp` スキーマと `idp.user_avatar` は起動時には作成しません。デプロイ前に [migrations/001_user_avatar.sql](migrations/001_user_avatar.sql) を `DATABASE_URL` と同じデータベースに適用してください（`IF NOT EXISTS` なので、二度実行しても壊れません）。開発中の古い版（外部キー付きや `etag` 列のもの）を適用済みのデータベースでは、マイグレーションがエラーで止まります。その場合は `DROP TABLE idp.user_avatar;`（と、あれば `DROP TABLE public.idp_user_avatar;`）を実行してから適用し直してください。

```bash
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/001_user_avatar.sql
```

```sql
CREATE SCHEMA IF NOT EXISTS idp;
-- （実際のファイルには、古い版のテーブルを検出して止めるチェックもあります）

CREATE TABLE IF NOT EXISTS idp.user_avatar (
  user_id      integer     PRIMARY KEY,
  email        text        NOT NULL,
  avatar_id    text        NOT NULL UNIQUE,
  content_type text        NOT NULL,
  data         bytea       NOT NULL,
  updated_at   timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE idp.user_avatar ENABLE ROW LEVEL SECURITY;
```

- `idp` スキーマは ID サーバーが所有します。candy-rain-store の Prisma は `public` スキーマだけを管理するので、`idp` は見えません（`prisma migrate dev` のドリフト検出や `prisma db push` の削除対象になりません）
- `user_id` は `"User".id` ですが、外部キーにはしていません。`public` スキーマには何も作らないので、ストア側の `TRUNCATE`・`DROP`・`prisma migrate reset` にも影響しません。ユーザーの削除やメールアドレスの変更で持ち主と一致しなくなった行は表示せず、見つけた時点（`/avatars`・`picture` の発行・`/account`）で削除します。一度も参照されない行をまとめて消すには、`DELETE FROM idp.user_avatar a WHERE NOT EXISTS (SELECT 1 FROM public."User" u WHERE u.id = a.user_id AND u.email = a.email);` を実行します（"User" は読むだけです）
- Supabase では Data API（PostgREST）から見えないよう RLS を有効にし、ポリシーは作りません。ID サーバーはテーブル所有者のロール（Supabase の `postgres` など）で接続する前提です。別のロールで接続する場合は、`idp` スキーマの `USAGE` とテーブルの `SELECT, INSERT, UPDATE, DELETE` を付与したうえで、そのロールに `BYPASSRLS` を付けるか、そのロール用のポリシーを作ってください（権限の付与だけでは RLS により 0 行になります）
- 適用前にデプロイしても、サインインは止まりません（`picture` が出ないだけ）。`/account` と `/avatars` はエラーになります

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

Discovery・JWKS、ログインから ID トークン発行・userinfo までの一連の流れ、誤ったパスワード、コードの再利用、PKCE 不一致、未登録の `redirect_uri`、CSRF、SSO とログアウトを検証しています。プロフィール画像は、`picture` クレームの有無（画像ストアの障害時に省かれることを含む）、`/avatars` のヘッダーと 404、アップロードの検証（種類・サイズ・ピクセル数・壊れた画像・CSRF・別セッションのトークン・未サインイン）、EXIF の除去と縮小、削除、`/account` の未サインイン時のログインとオープンリダイレクト対策、別タブのストアのログインを壊さないことを検証しています。データベースは使わず、`user.Store` と `user.AvatarStore` をメモリ上の実装に差し替えています。

`TEST_DATABASE_URL` を設定すると、実際の PostgreSQL でマイグレーション（2 回適用）と `PostgresAvatarStore` も検証します（`idp` スキーマに作成し、存在しない user_id の行だけを使います）。

```bash
TEST_DATABASE_URL=postgresql://user@localhost:5432/candyrain go test ./internal/user/
```

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
