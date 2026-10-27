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
| `GET /healthz` | ヘルスチェック |

## セキュリティ上の配慮

- `redirect_uri` は、その client に登録したものと完全一致のみ（別の client の URI は使えない）。一致しないときはリダイレクトせずエラー画面を出す（オープンリダイレクト対策）
- 認可コードは 60 秒・1 回限りで、発行先の client しか交換できない。PKCE の検証に失敗したら `invalid_grant`
- ログインフォームは CSRF トークン（ダブルサブミット Cookie）で保護
- 存在しないメールアドレスでもダミーハッシュで bcrypt 照合を行い、応答時間からアカウントの有無を推測されにくくする
- client secret・PKCE の比較は定数時間。Cookie は `HttpOnly` / `SameSite=Lax`、`ISSUER` が https のときは `Secure`
- CSP・`X-Frame-Options: DENY` などのヘッダーを付与

**認可コード**：サーバーに保存せず、`SESSION_SECRET` から作った鍵で暗号化（AES-GCM）した値をそのまま認可コードにしています。そのため複数インスタンスやサーバーレス（Vercel Functions）でも、別のインスタンスが発行したコードを交換できます。使用済みコードの記録はインスタンスごとのベストエフォートですが、再利用するには client secret と PKCE の verifier も必要です。

**制約**：ログイン試行回数の制限は未実装です。

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

Discovery・JWKS、ログインから ID トークン発行・userinfo までの一連の流れ、誤ったパスワード、コードの再利用、PKCE 不一致、未登録の `redirect_uri`、CSRF、SSO とログアウトを検証しています。

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
