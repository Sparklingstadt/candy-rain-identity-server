// Package oidc implements a small OpenID Connect provider: the authorization
// code flow with PKCE for confidential clients such as candy-rain-store and
// candy-rain-stores. The sign-in session is shared, so signing in to one
// client signs the user in to the others too (SSO).
package oidc

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/Sparklingstadt/candy-rain-identity-server/internal/config"
	"github.com/Sparklingstadt/candy-rain-identity-server/internal/user"
)

const (
	codeTTL     = time.Minute
	tokenTTL    = time.Hour
	sessionTTL  = 8 * time.Hour
	sessionName = "crs_session"
	csrfName    = "crs_csrf"
)

//go:embed templates/*.html
var templateFS embed.FS

var pages = template.Must(template.ParseFS(templateFS, "templates/*.html"))

// storeBcryptCost is the cost candy-rain-store hashes passwords with
// (bcryptjs, cost 12). dummyHash must use the same cost: at a lower one, an
// unknown email is rejected several times faster than a wrong password, which
// tells whether an account exists.
const storeBcryptCost = 12

// dummyHash is compared against when the email is unknown, so a missing
// account takes as long to reject as a wrong password. It is the hash of a
// random password that was thrown away, precomputed so that startup does not
// pay for a cost-12 hash.
var dummyHash = []byte("$2a$12$lJH7Xl23lvnfhRG0LSeFsuxsSwt7TIV.z9o2esEx09m0ZNDoHz3IS")

type Options struct {
	Issuer        string
	Clients       []config.Client
	Users         user.Store
	Avatars       user.AvatarStore // required
	Signer        *Signer
	SessionSecret []byte
	LoginHint     string
	Logger        *slog.Logger
	// Now is overridable in tests.
	Now func() time.Time
}

type Server struct {
	opts          Options
	clients       map[string]config.Client
	codes         *codeStore
	sessions      sessionCodec
	decodes       *decodeLimiter
	secureCookies bool
	handler       http.Handler
}

func New(opts Options) *Server {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Avatars == nil {
		panic("oidc: Options.Avatars is required")
	}
	s := &Server{
		opts:          opts,
		clients:       make(map[string]config.Client, len(opts.Clients)),
		codes:         newCodeStore(opts.SessionSecret),
		sessions:      sessionCodec{secret: opts.SessionSecret},
		decodes:       newServerDecodeLimiter(),
		secureCookies: strings.HasPrefix(opts.Issuer, "https://"),
	}
	for _, c := range opts.Clients {
		s.clients[c.ID] = c
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("GET /jwks", s.handleJWKS)
	mux.HandleFunc("GET /authorize", s.handleAuthorize)
	mux.HandleFunc("POST /authorize", s.handleLogin)
	mux.HandleFunc("POST /token", s.handleToken)
	mux.HandleFunc("GET /userinfo", s.handleUserinfo)
	mux.HandleFunc("POST /userinfo", s.handleUserinfo)
	mux.HandleFunc("GET /logout", s.handleLogout)
	mux.HandleFunc("GET /avatars/{id}", s.handleAvatar)
	mux.HandleFunc("GET /account", s.handleAccount)
	mux.HandleFunc("POST /account/avatar", s.handleAvatarUpload)
	mux.HandleFunc("POST /account/avatar/delete", s.handleAvatarDelete)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	s.handler = securityHeaders(mux)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
		next.ServeHTTP(w, r)
	})
}

// ---- discovery ----

func (s *Server) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	iss := s.opts.Issuer
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         iss,
		"authorization_endpoint":                         iss + "/authorize",
		"token_endpoint":                                 iss + "/token",
		"userinfo_endpoint":                              iss + "/userinfo",
		"jwks_uri":                                       iss + "/jwks",
		"end_session_endpoint":                           iss + "/logout",
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code"},
		"subject_types_supported":                        []string{"public"},
		"id_token_signing_alg_values_supported":          []string{"RS256"},
		"scopes_supported":                               []string{"openid", "email", "profile"},
		"token_endpoint_auth_methods_supported":          []string{"client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":               []string{"S256"},
		"claims_supported":                               []string{"sub", "email", "name", "given_name", "family_name", "picture", "role", "auth_time", "nonce"},
		"authorization_response_iss_parameter_supported": true,
	})
}

func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.opts.Signer.JWKS())
}

// ---- authorization ----

type authRequest struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              string
}

func parseAuthRequest(v url.Values) authRequest {
	return authRequest{
		ResponseType:        v.Get("response_type"),
		ClientID:            v.Get("client_id"),
		RedirectURI:         v.Get("redirect_uri"),
		Scope:               v.Get("scope"),
		State:               v.Get("state"),
		Nonce:               v.Get("nonce"),
		CodeChallenge:       v.Get("code_challenge"),
		CodeChallengeMethod: v.Get("code_challenge_method"),
		Prompt:              v.Get("prompt"),
	}
}

func (a authRequest) hasScope(scope string) bool {
	return slices.Contains(strings.Fields(a.Scope), scope)
}

// validate returns ok=true when the request can proceed. When it cannot, it
// has already answered: by redirecting the error back to a trusted
// redirect_uri, or by showing an error page when the client or redirect_uri
// itself is untrusted (redirecting there would make this an open redirector).
func (s *Server) validate(w http.ResponseWriter, r *http.Request, a authRequest) bool {
	client, ok := s.clients[a.ClientID]
	if !ok || !slices.Contains(client.RedirectURIs, a.RedirectURI) {
		s.renderError(w, http.StatusBadRequest, "ログイン要求が正しくありません。ストアからもう一度サインインしてください。")
		return false
	}
	switch {
	case a.ResponseType != "code":
		s.redirectError(w, r, a, "unsupported_response_type", "only response_type=code is supported")
	case !a.hasScope("openid"):
		s.redirectError(w, r, a, "invalid_scope", "the openid scope is required")
	case a.CodeChallenge == "" || a.CodeChallengeMethod != "S256":
		s.redirectError(w, r, a, "invalid_request", "PKCE with code_challenge_method=S256 is required")
	default:
		return true
	}
	return false
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	a := parseAuthRequest(r.URL.Query())
	if !s.validate(w, r, a) {
		return
	}
	if a.Prompt != "login" {
		sess, _, ok, err := s.signedInUser(w, r)
		if err != nil {
			s.opts.Logger.Error("session user lookup failed", "err", err)
			s.renderError(w, http.StatusInternalServerError, "サインインできませんでした。時間をおいてもう一度お試しください。")
			return
		}
		if ok {
			s.issueCode(w, r, a, sess.UserID, sess.AuthTime)
			return
		}
	}
	if a.Prompt == "none" {
		s.redirectError(w, r, a, "login_required", "the user is not signed in")
		return
	}
	s.renderLogin(w, r, http.StatusOK, loginForm{Request: a}, "", "")
}

// nextAccount is the only place a standalone sign-in (one without an OIDC
// client) can continue to. The form carries this fixed token, never a URL,
// and the handler maps it to the fixed path /account, so the login form
// cannot be turned into an open redirector.
const nextAccount = "account"

// loginForm says where the login form continues: to a client through the
// authorization request, or to the account page.
type loginForm struct {
	Request authRequest
	Account bool
}

// csrfCookie names the double-submit cookie of the form and its path. The
// account form has its own cookie, so that opening /account never replaces
// the token of a client's login form open in another tab (crs_csrf is
// scoped to /authorize and so cannot be read, and reused, on /account).
func (f loginForm) csrfCookie() (name, path string) {
	if f.Account {
		return accountCSRFName, "/"
	}
	return csrfName, "/authorize"
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		s.renderError(w, http.StatusBadRequest, "送信内容を読み取れませんでした。")
		return
	}
	// Only the exact token selects the account page. Any other value of next
	// is ignored and the form is treated as an authorization request, which
	// validate rejects unless client_id and redirect_uri are registered.
	form := loginForm{Account: r.PostForm.Get("next") == nextAccount}
	if !form.Account {
		form.Request = parseAuthRequest(r.PostForm)
		if !s.validate(w, r, form.Request) {
			return
		}
	}
	csrfCookie, _ := form.csrfCookie()
	cookie, err := r.Cookie(csrfCookie)
	if err != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(r.PostForm.Get("csrf_token"))) != 1 {
		msg := "画面の有効期限が切れました。ストアからもう一度サインインしてください。"
		if form.Account {
			msg = "画面の有効期限が切れました。アカウント画面を開き直してください。"
		}
		s.renderError(w, http.StatusBadRequest, msg)
		return
	}

	email := strings.TrimSpace(r.PostForm.Get("email"))
	password := r.PostForm.Get("password")
	u, err := s.authenticate(r.Context(), email, password)
	if errors.Is(err, errBadCredentials) {
		s.opts.Logger.Info("sign-in failed", "email", email)
		s.renderLogin(w, r, http.StatusUnauthorized, form, email, "メールアドレスまたはパスワードが違います。")
		return
	}
	if err != nil {
		s.opts.Logger.Error("sign-in lookup failed", "err", err)
		s.renderError(w, http.StatusInternalServerError, "サインインできませんでした。時間をおいてもう一度お試しください。")
		return
	}

	now := s.opts.Now()
	http.SetCookie(w, s.cookie(sessionName, s.sessions.Encode(session{
		UserID: u.ID, AuthTime: now, ExpiresAt: now.Add(sessionTTL),
		PasswordTag: s.sessions.passwordTag(u.PasswordHash),
	}), "/", int(sessionTTL.Seconds())))
	s.opts.Logger.Info("signed in", "sub", u.Subject())
	if form.Account {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	s.issueCode(w, r, form.Request, u.ID, now)
}

var errBadCredentials = errors.New("bad credentials")

func (s *Server) authenticate(ctx context.Context, email, password string) (user.User, error) {
	if email == "" || password == "" {
		return user.User{}, errBadCredentials
	}
	u, err := s.opts.Users.FindByEmail(ctx, email)
	hash := []byte(u.PasswordHash)
	switch {
	case errors.Is(err, user.ErrNotFound):
		hash = dummyHash
	case err != nil:
		return user.User{}, err
	}
	if bcrypt.CompareHashAndPassword(hash, []byte(password)) != nil || err != nil {
		return user.User{}, errBadCredentials
	}
	return u, nil
}

// signedInUser returns the session and its user. ok is false when the
// request has no valid session, the user no longer exists, or the password
// changed since sign-in; the session cookie is then cleared. err is set only
// when the lookup failed.
func (s *Server) signedInUser(w http.ResponseWriter, r *http.Request) (sess session, u user.User, ok bool, err error) {
	c, err := r.Cookie(sessionName)
	if err != nil {
		return session{}, user.User{}, false, nil
	}
	sess, ok = s.sessions.Decode(c.Value, s.opts.Now())
	if !ok {
		return session{}, user.User{}, false, nil
	}
	u, err = s.opts.Users.FindByID(r.Context(), sess.UserID)
	if err != nil && !errors.Is(err, user.ErrNotFound) {
		return session{}, user.User{}, false, err
	}
	if err != nil || !hmac.Equal([]byte(sess.PasswordTag), []byte(s.sessions.passwordTag(u.PasswordHash))) {
		http.SetCookie(w, s.cookie(sessionName, "", "/", -1))
		return session{}, user.User{}, false, nil
	}
	return sess, u, true, nil
}

func (s *Server) issueCode(w http.ResponseWriter, r *http.Request, a authRequest, userID int64, authTime time.Time) {
	code := s.codes.Issue(authCode{
		ClientID:      a.ClientID,
		RedirectURI:   a.RedirectURI,
		UserID:        userID,
		Nonce:         a.Nonce,
		CodeChallenge: a.CodeChallenge,
		Scope:         a.Scope,
		AuthTime:      authTime,
		ExpiresAt:     s.opts.Now().Add(codeTTL),
	})
	s.redirectToClient(w, r, a, url.Values{"code": {code}})
}

func (s *Server) redirectError(w http.ResponseWriter, r *http.Request, a authRequest, code, description string) {
	s.redirectToClient(w, r, a, url.Values{"error": {code}, "error_description": {description}})
}

// redirectToClient must only be called after the redirect_uri was matched
// against the registered list.
func (s *Server) redirectToClient(w http.ResponseWriter, r *http.Request, a authRequest, params url.Values) {
	target, err := url.Parse(a.RedirectURI)
	if err != nil {
		s.renderError(w, http.StatusBadRequest, "リダイレクト先が正しくありません。")
		return
	}
	q := target.Query()
	for k, vs := range params {
		q[k] = vs
	}
	if a.State != "" {
		q.Set("state", a.State)
	}
	q.Set("iss", s.opts.Issuer)
	target.RawQuery = q.Encode()
	// 303 turns the login POST into a GET on the client.
	http.Redirect(w, r, target.String(), http.StatusSeeOther)
}

// ---- token ----

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	client, ok := s.authenticateClient(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
		tokenError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		tokenError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code is supported")
		return
	}

	now := s.opts.Now()
	c, ok := s.codes.Redeem(r.PostForm.Get("code"), now)
	// A code is only redeemable by the client it was issued to.
	if !ok || c.ClientID != client.ID || c.RedirectURI != r.PostForm.Get("redirect_uri") ||
		!verifyPKCE(r.PostForm.Get("code_verifier"), c.CodeChallenge) {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "the code is invalid, expired, or does not match")
		return
	}
	u, err := s.opts.Users.FindByID(r.Context(), c.UserID)
	if errors.Is(err, user.ErrNotFound) {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "the user no longer exists")
		return
	}
	if err != nil {
		s.opts.Logger.Error("token user lookup failed", "err", err)
		tokenError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	exp := now.Add(tokenTTL)
	idClaims := s.userClaims(r.Context(), u, c.Scope)
	idClaims["iss"] = s.opts.Issuer
	idClaims["aud"] = c.ClientID
	idClaims["iat"] = now.Unix()
	idClaims["exp"] = exp.Unix()
	idClaims["auth_time"] = c.AuthTime.Unix()
	if c.Nonce != "" {
		idClaims["nonce"] = c.Nonce
	}
	idToken, err := s.opts.Signer.Sign(idClaims, "JWT")
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	accessToken, err := s.opts.Signer.Sign(map[string]any{
		"iss":       s.opts.Issuer,
		"sub":       u.Subject(),
		"aud":       s.opts.Issuer + "/userinfo",
		"client_id": c.ClientID,
		"scope":     c.Scope,
		"iat":       now.Unix(),
		"exp":       exp.Unix(),
		"jti":       randomToken(),
	}, "at+jwt")
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(tokenTTL.Seconds()),
		"id_token":     idToken,
		"scope":        c.Scope,
	})
}

func (s *Server) authenticateClient(r *http.Request) (config.Client, bool) {
	id, secret, ok := r.BasicAuth()
	if ok {
		// RFC 6749 §2.3.1: Basic credentials are form-urlencoded first.
		var err1, err2 error
		id, err1 = url.QueryUnescape(id)
		secret, err2 = url.QueryUnescape(secret)
		if err1 != nil || err2 != nil {
			return config.Client{}, false
		}
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	client, ok := s.clients[id]
	if !ok {
		return config.Client{}, false
	}
	if subtle.ConstantTimeCompare([]byte(secret), []byte(client.Secret)) != 1 {
		return config.Client{}, false
	}
	return client, true
}

func verifyPKCE(verifier, challenge string) bool {
	// RFC 7636 §4.1: 43 to 128 characters.
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(b64.EncodeToString(sum[:])), []byte(challenge)) == 1
}

// userClaims returns the claims allowed by the granted scopes. role is
// always included because the store decides admin access from it.
func (s *Server) userClaims(ctx context.Context, u user.User, scope string) map[string]any {
	scopes := strings.Fields(scope)
	claims := map[string]any{"sub": u.Subject(), "role": u.Role}
	if slices.Contains(scopes, "email") {
		claims["email"] = u.Email
	}
	if slices.Contains(scopes, "profile") {
		claims["name"] = u.DisplayName()
		claims["given_name"] = u.FirstName
		claims["family_name"] = u.LastName
		if picture := s.pictureURL(ctx, u); picture != "" {
			claims["picture"] = picture
		}
	}
	return claims
}

// ---- userinfo ----

func (s *Server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	var claims map[string]any
	var err error
	if ok {
		claims, err = s.opts.Signer.Verify(token, "at+jwt", s.opts.Now())
	}
	if !ok || err != nil || claims["iss"] != s.opts.Issuer {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	sub, _ := claims["sub"].(string)
	scope, _ := claims["scope"].(string)
	id, err := strconv.ParseInt(sub, 10, 64)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	u, err := s.opts.Users.FindByID(r.Context(), id)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, s.userClaims(r.Context(), u, scope))
}

// ---- logout ----

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, s.cookie(sessionName, "", "/", -1))
	q := r.URL.Query()
	target := q.Get("post_logout_redirect_uri")
	if target != "" && s.allowedPostLogoutRedirect(q.Get("client_id"), target) {
		u, err := url.Parse(target)
		if err == nil {
			if state := q.Get("state"); state != "" {
				v := u.Query()
				v.Set("state", state)
				u.RawQuery = v.Encode()
			}
			http.Redirect(w, r, u.String(), http.StatusFound)
			return
		}
	}
	s.render(w, http.StatusOK, "message.html", map[string]any{
		"Title":   "サインアウトしました",
		"Message": "Candy Rain ID からサインアウトしました。",
	})
}

// allowedPostLogoutRedirect reports whether target is registered for the
// client named by clientID, or for any client when clientID is empty.
func (s *Server) allowedPostLogoutRedirect(clientID, target string) bool {
	if clientID != "" {
		c, ok := s.clients[clientID]
		return ok && slices.Contains(c.PostLogoutRedirectURIs, target)
	}
	for _, c := range s.clients {
		if slices.Contains(c.PostLogoutRedirectURIs, target) {
			return true
		}
	}
	return false
}

// ---- rendering helpers ----

func (s *Server) cookie(name, value, path string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name: name, Value: value, Path: path, MaxAge: maxAge,
		HttpOnly: true, Secure: s.secureCookies, SameSite: http.SameSiteLaxMode,
	}
}

func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, status int, form loginForm, email, errMsg string) {
	name, path := form.csrfCookie()
	csrf := randomToken()
	if c, err := r.Cookie(name); err == nil && len(c.Value) >= 32 {
		csrf = c.Value
	}
	http.SetCookie(w, s.cookie(name, csrf, path, 3600))
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, status, "login.html", map[string]any{
		"Request":   form.Request,
		"Account":   form.Account,
		"CSRF":      csrf,
		"Email":     email,
		"Error":     errMsg,
		"LoginHint": s.opts.LoginHint,
	})
}

func (s *Server) renderError(w http.ResponseWriter, status int, msg string) {
	s.render(w, status, "message.html", map[string]any{"Title": "エラー", "Message": msg})
}

func (s *Server) render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := pages.ExecuteTemplate(w, name, data); err != nil {
		s.opts.Logger.Error("render failed", "template", name, "err", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func tokenError(w http.ResponseWriter, status int, code, description string) {
	body := map[string]string{"error": code}
	if description != "" {
		body["error_description"] = description
	}
	writeJSON(w, status, body)
}
