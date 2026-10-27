package oidc

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"

	"github.com/Sparklingstadt/candy-rain-identity-server/internal/user"
)

const (
	// maxAvatarBytes caps the image itself.
	maxAvatarBytes = 1 << 20
	// maxAvatarBody caps the whole multipart request: the image plus room
	// for the boundaries, headers and the CSRF field.
	maxAvatarBody = maxAvatarBytes + 64<<10

	avatarCache          = "public, max-age=300"
	avatarCacheImmutable = "public, max-age=31536000, immutable"

	// The account page shows the avatar from this origin and only submits
	// forms back to it.
	accountCSP = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

	msgAvatarType     = "画像は PNG・JPEG・WebP のいずれかにしてください"
	msgAvatarSize     = "画像は 1MB 以下にしてください"
	msgAvatarMissing  = "画像を選択してください"
	msgAvatarOneFile  = "画像は 1 枚だけ選択してください"
	msgAccountExpired = "画面の有効期限が切れました。アカウント画面を開き直してください。"
)

// accountNotices maps the done parameter to a fixed message, so nothing from
// the URL is ever shown on the page.
var accountNotices = map[string]string{
	"updated": "プロフィール画像を更新しました",
	"deleted": "プロフィール画像を削除しました",
}

// ---- picture claim and /avatars ----

// pictureURL returns the picture claim, or "" when the user has no avatar.
// A lookup failure (for example before the migration is applied) only
// omits the claim, so it never breaks sign-in.
func (s *Server) pictureURL(ctx context.Context, u user.User) string {
	etag, err := s.opts.Avatars.ETag(ctx, u.ID)
	if err != nil {
		if !errors.Is(err, user.ErrNoAvatar) {
			s.opts.Logger.Warn("avatar lookup failed", "sub", u.Subject(), "err", err)
		}
		return ""
	}
	return avatarPath(u, etag, s.opts.Issuer)
}

// avatarPath is the versioned image URL under prefix (the issuer, or ""
// for a same-origin path).
func avatarPath(u user.User, etag, prefix string) string {
	return prefix + "/avatars/" + u.Subject() + "?v=" + url.QueryEscape(etag)
}

func (s *Server) handleAvatar(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("sub"), 10, 64)
	if err != nil || id <= 0 {
		avatarNotFound(w)
		return
	}
	a, err := s.opts.Avatars.Get(r.Context(), id)
	if errors.Is(err, user.ErrNoAvatar) {
		avatarNotFound(w)
		return
	}
	if err != nil {
		s.opts.Logger.Error("avatar read failed", "sub", id, "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", a.ContentType)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("ETag", `"`+a.ETag+`"`)
	// Client apps on other origins show the image with <img>.
	h.Set("Cross-Origin-Resource-Policy", "cross-origin")
	if r.URL.Query().Get("v") == a.ETag {
		// The picture claim's URL changes whenever the image does.
		h.Set("Cache-Control", avatarCacheImmutable)
	} else {
		h.Set("Cache-Control", avatarCache)
	}
	// ServeContent answers If-None-Match with 304 and handles HEAD.
	http.ServeContent(w, r, "", a.UpdatedAt, bytes.NewReader(a.Data))
}

func avatarNotFound(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-cache")
	http.Error(w, "not found", http.StatusNotFound)
}

// detectAvatarType judges the image by its magic bytes, never by the file
// name or the Content-Type the browser sent. It returns "" for anything else
// (SVG and HTML in particular, which could carry scripts).
func detectAvatarType(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")):
		return "image/png"
	case bytes.HasPrefix(b, []byte("\xff\xd8\xff")):
		return "image/jpeg"
	case len(b) >= 12 && string(b[:4]) == "RIFF" && string(b[8:12]) == "WEBP":
		return "image/webp"
	}
	return ""
}

// ---- account page ----

// accountCSRF is bound to the session cookie: an HMAC of its value under
// the session secret. A forged request cannot know it, and it changes with
// every sign-in.
func (s *Server) accountCSRF(r *http.Request) string {
	c, err := r.Cookie(sessionName)
	if err != nil {
		return ""
	}
	return s.sessions.mac("account-csrf\x00" + c.Value)
}

func (s *Server) validAccountCSRF(r *http.Request) bool {
	want := s.accountCSRF(r)
	got := r.PostForm.Get("csrf_token")
	return want != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// accountUser returns the signed-in user. ok is false when the request has
// no valid session or the user no longer exists; the caller then shows or
// redirects to the login form.
func (s *Server) accountUser(w http.ResponseWriter, r *http.Request) (u user.User, ok bool, err error) {
	sess, ok := s.currentSession(r)
	if !ok {
		return user.User{}, false, nil
	}
	u, err = s.opts.Users.FindByID(r.Context(), sess.UserID)
	if errors.Is(err, user.ErrNotFound) {
		http.SetCookie(w, s.cookie(sessionName, "", "/", -1))
		return user.User{}, false, nil
	}
	if err != nil {
		return user.User{}, false, err
	}
	return u, true, nil
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	u, ok, err := s.accountUser(w, r)
	if err != nil {
		s.opts.Logger.Error("account user lookup failed", "err", err)
		s.renderError(w, http.StatusInternalServerError, "アカウント情報を読み込めませんでした。時間をおいてもう一度お試しください。")
		return
	}
	if !ok {
		// Signed out: the regular login form, continuing to /account.
		s.renderLogin(w, r, http.StatusOK, loginForm{Account: true}, "", "")
		return
	}
	s.renderAccount(w, r, http.StatusOK, u, accountNotices[r.URL.Query().Get("done")], "")
}

func (s *Server) renderAccount(w http.ResponseWriter, r *http.Request, status int, u user.User, notice, errMsg string) {
	etag, err := s.opts.Avatars.ETag(r.Context(), u.ID)
	if err != nil && !errors.Is(err, user.ErrNoAvatar) {
		s.opts.Logger.Error("avatar lookup failed", "sub", u.Subject(), "err", err)
		s.renderError(w, http.StatusInternalServerError, "アカウント情報を読み込めませんでした。時間をおいてもう一度お試しください。")
		return
	}
	avatar := ""
	if err == nil {
		avatar = avatarPath(u, etag, "")
	}
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", accountCSP)
	s.render(w, status, "account.html", map[string]any{
		"Name":    u.DisplayName(),
		"Email":   u.Email,
		"Avatar":  avatar,
		"CSRF":    s.accountCSRF(r),
		"Notice":  notice,
		"Error":   errMsg,
		"MaxSize": maxAvatarBytes,
	})
}

func (s *Server) handleAvatarUpload(w http.ResponseWriter, r *http.Request) {
	u, ok, err := s.accountUser(w, r)
	if err != nil {
		s.opts.Logger.Error("account user lookup failed", "err", err)
		s.renderError(w, http.StatusInternalServerError, "プロフィール画像を保存できませんでした。時間をおいてもう一度お試しください。")
		return
	}
	if !ok {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxAvatarBody)
	// Everything fits in memory, so no temporary files are written.
	err = r.ParseMultipartForm(maxAvatarBody)
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge) || errors.Is(err, multipart.ErrMessageTooLarge):
		// Nothing changes, so the CSRF token is not needed to say so.
		s.renderAccount(w, r, http.StatusRequestEntityTooLarge, u, "", msgAvatarSize)
		return
	case err != nil:
		s.renderError(w, http.StatusBadRequest, "送信内容を読み取れませんでした。")
		return
	}
	if !s.validAccountCSRF(r) {
		s.renderError(w, http.StatusForbidden, msgAccountExpired)
		return
	}

	data, status, msg := readAvatar(r.MultipartForm.File["avatar"])
	if msg != "" {
		s.renderAccount(w, r, status, u, "", msg)
		return
	}
	contentType := detectAvatarType(data)
	if contentType == "" {
		s.renderAccount(w, r, http.StatusBadRequest, u, "", msgAvatarType)
		return
	}
	if _, err := s.opts.Avatars.Put(r.Context(), u.ID, contentType, data); err != nil {
		s.opts.Logger.Error("avatar write failed", "sub", u.Subject(), "err", err)
		s.renderError(w, http.StatusInternalServerError, "プロフィール画像を保存できませんでした。時間をおいてもう一度お試しください。")
		return
	}
	s.opts.Logger.Info("avatar updated", "sub", u.Subject(), "type", contentType, "bytes", len(data))
	http.Redirect(w, r, "/account?done=updated", http.StatusSeeOther)
}

// readAvatar reads the single uploaded file. On failure it returns the
// status and the message to show.
func readAvatar(files []*multipart.FileHeader) ([]byte, int, string) {
	switch {
	case len(files) == 0:
		return nil, http.StatusBadRequest, msgAvatarMissing
	case len(files) > 1:
		return nil, http.StatusBadRequest, msgAvatarOneFile
	case files[0].Size > maxAvatarBytes:
		return nil, http.StatusRequestEntityTooLarge, msgAvatarSize
	}
	f, err := files[0].Open()
	if err != nil {
		return nil, http.StatusBadRequest, msgAvatarMissing
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxAvatarBytes+1))
	switch {
	case err != nil || len(data) == 0:
		return nil, http.StatusBadRequest, msgAvatarMissing
	case len(data) > maxAvatarBytes:
		return nil, http.StatusRequestEntityTooLarge, msgAvatarSize
	}
	return data, http.StatusOK, ""
}

func (s *Server) handleAvatarDelete(w http.ResponseWriter, r *http.Request) {
	u, ok, err := s.accountUser(w, r)
	if err != nil {
		s.opts.Logger.Error("account user lookup failed", "err", err)
		s.renderError(w, http.StatusInternalServerError, "プロフィール画像を削除できませんでした。時間をおいてもう一度お試しください。")
		return
	}
	if !ok {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		s.renderError(w, http.StatusBadRequest, "送信内容を読み取れませんでした。")
		return
	}
	if !s.validAccountCSRF(r) {
		s.renderError(w, http.StatusForbidden, msgAccountExpired)
		return
	}
	if err := s.opts.Avatars.Delete(r.Context(), u.ID); err != nil {
		s.opts.Logger.Error("avatar delete failed", "sub", u.Subject(), "err", err)
		s.renderError(w, http.StatusInternalServerError, "プロフィール画像を削除できませんでした。時間をおいてもう一度お試しください。")
		return
	}
	s.opts.Logger.Info("avatar deleted", "sub", u.Subject())
	http.Redirect(w, r, "/account?done=deleted", http.StatusSeeOther)
}
