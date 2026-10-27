package oidc

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"mime/multipart"
	"net/http"

	"github.com/Sparklingstadt/candy-rain-identity-server/internal/user"
)

const (
	// maxAvatarBytes caps the uploaded file.
	maxAvatarBytes = 1 << 20
	// maxAvatarBody caps the whole multipart request: the image plus room
	// for the boundaries, headers and the CSRF field.
	maxAvatarBody = maxAvatarBytes + 64<<10
	// maxAvatarDrain is how much of a too-large upload is read and thrown
	// away so the browser can show the error page.
	maxAvatarDrain = 16 << 20

	// The avatar id changes whenever the image does, so a URL never needs
	// revalidating.
	avatarCache = "public, max-age=31536000, immutable"
	// Even if a browser were tricked into rendering an avatar as a document,
	// it could not run anything.
	avatarCSP = "default-src 'none'; sandbox"

	// The account page shows the avatar from this origin and only submits
	// forms back to it.
	accountCSP = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

	// accountCSRFName is the double-submit cookie of the standalone
	// (/account) login form. It is separate from crs_csrf so that opening
	// /account never replaces the token of a client's login form that is
	// open in another tab. Path=/ lets GET /account read and reuse it.
	accountCSRFName = "crs_account_csrf"

	msgAccountExpired = "画面の有効期限が切れました。アカウント画面を開き直してください。"
)

// accountNotices maps the done parameter to a fixed message, so nothing from
// the URL is ever shown on the page. Errors use avatarErrorMessages.
var accountNotices = map[string]string{
	"updated": "プロフィール画像を更新しました",
	"deleted": "プロフィール画像を削除しました",
}

// ---- picture claim and /avatars ----

// userAvatar returns the user's avatar when it still belongs to them: the
// email saved at upload must match the current one. ok is false when there
// is none; err is set only when the lookup failed.
func (s *Server) userAvatar(ctx context.Context, u user.User) (a user.Avatar, ok bool, err error) {
	a, err = s.opts.Avatars.ForUser(ctx, u.ID)
	if errors.Is(err, user.ErrNoAvatar) {
		return user.Avatar{}, false, nil
	}
	if err != nil {
		return user.Avatar{}, false, err
	}
	if !a.BelongsTo(u) {
		s.dropStaleAvatar(ctx, a)
		return user.Avatar{}, false, nil
	}
	return a, true, nil
}

// dropStaleAvatar deletes a row left behind by a deleted user or an old
// email, so its image and email do not stay at rest. It deletes by avatar
// id, so it never removes an image uploaded since. Failures are only logged.
func (s *Server) dropStaleAvatar(ctx context.Context, a user.Avatar) {
	if err := s.opts.Avatars.DeleteByID(ctx, a.ID); err != nil {
		s.opts.Logger.Warn("stale avatar cleanup failed", "err", err)
		return
	}
	s.opts.Logger.Info("stale avatar removed", "user_id", a.UserID)
}

// pictureURL returns the picture claim, or "" when the user has no avatar.
// A lookup failure (for example before the migration is applied) only
// omits the claim, so it never breaks sign-in.
func (s *Server) pictureURL(ctx context.Context, u user.User) string {
	a, ok, err := s.userAvatar(ctx, u)
	if err != nil {
		s.opts.Logger.Error("avatar lookup failed; picture claim omitted", "sub", u.Subject(), "err", err)
		return ""
	}
	if !ok {
		return ""
	}
	return s.opts.Issuer + "/avatars/" + a.ID
}

func (s *Server) handleAvatar(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !user.ValidAvatarID(id) {
		avatarNotFound(w)
		return
	}
	a, err := s.opts.Avatars.ByID(r.Context(), id)
	if errors.Is(err, user.ErrNoAvatar) {
		avatarNotFound(w)
		return
	}
	if err != nil {
		s.opts.Logger.Error("avatar read failed", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	// Serve only while the row still belongs to the current user with that
	// id (there is no foreign key to "User").
	u, err := s.opts.Users.FindByID(r.Context(), a.UserID)
	if errors.Is(err, user.ErrNotFound) || (err == nil && !a.BelongsTo(u)) {
		s.dropStaleAvatar(r.Context(), a)
		avatarNotFound(w)
		return
	}
	if err != nil {
		s.opts.Logger.Error("avatar owner lookup failed", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", a.ContentType)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", avatarCSP)
	h.Set("Content-Disposition", "inline")
	h.Set("ETag", `"`+a.ID+`"`)
	h.Set("Cache-Control", avatarCache)
	// Client apps on other origins show the image with <img>.
	h.Set("Cross-Origin-Resource-Policy", "cross-origin")
	// ServeContent answers If-None-Match with 304 and handles HEAD.
	http.ServeContent(w, r, "", a.UpdatedAt, bytes.NewReader(a.Data))
}

func avatarNotFound(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-cache")
	http.Error(w, "not found", http.StatusNotFound)
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
// no valid session, the user no longer exists or the password changed; the
// caller then shows or redirects to the login form.
func (s *Server) accountUser(w http.ResponseWriter, r *http.Request) (u user.User, ok bool, err error) {
	_, u, ok, err = s.signedInUser(w, r)
	return u, ok, err
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
	a, hasAvatar, err := s.userAvatar(r.Context(), u)
	if err != nil {
		s.opts.Logger.Error("avatar lookup failed", "sub", u.Subject(), "err", err)
		s.renderError(w, http.StatusInternalServerError, "アカウント情報を読み込めませんでした。時間をおいてもう一度お試しください。")
		return
	}
	avatar := ""
	if hasAvatar {
		avatar = "/avatars/" + a.ID
	}
	q := r.URL.Query()
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", accountCSP)
	s.render(w, http.StatusOK, "account.html", map[string]any{
		"Name":   u.DisplayName(),
		"Email":  u.Email,
		"Avatar": avatar,
		"CSRF":   s.accountCSRF(r),
		"Notice": accountNotices[q.Get("done")],
		"Error":  avatarErrorMessages[q.Get("error")],
	})
}

// Every outcome of the account forms is a 303 back to /account (with a
// fixed code), so no response to a POST ever renders the page or its token.
func redirectAccountError(w http.ResponseWriter, r *http.Request, code avatarError) {
	http.Redirect(w, r, "/account?error="+string(code), http.StatusSeeOther)
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

	body := r.Body
	r.Body = http.MaxBytesReader(w, body, maxAvatarBody)
	// Everything fits in memory, so no temporary files are written.
	err = r.ParseMultipartForm(maxAvatarBody)
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge) || errors.Is(err, multipart.ErrMessageTooLarge):
		// The CSRF field may be unread, but nothing changes and nothing but
		// a fixed code is returned. Reading on (up to a cap) lets the browser
		// finish sending, so it shows the message instead of a connection
		// reset; the connection is closed afterwards either way.
		io.CopyN(io.Discard, body, maxAvatarDrain)
		redirectAccountError(w, r, errAvatarSize)
		return
	case err != nil:
		s.renderError(w, http.StatusBadRequest, "送信内容を読み取れませんでした。")
		return
	}
	if !s.validAccountCSRF(r) {
		s.renderError(w, http.StatusForbidden, msgAccountExpired)
		return
	}

	data, code := readAvatar(r.MultipartForm.File["avatar"])
	if code != "" {
		redirectAccountError(w, r, code)
		return
	}
	// Decoding can take tens of MB, so only a few run at once; the rest
	// wait briefly and are then turned away instead of piling up.
	if !s.decodes.acquire(r.Context()) {
		s.opts.Logger.Warn("avatar upload turned away: decoder busy", "sub", u.Subject())
		redirectAccountError(w, r, errAvatarBusy)
		return
	}
	out, contentType, code := processAvatar(data)
	s.decodes.release()
	if code != "" {
		redirectAccountError(w, r, code)
		return
	}
	if _, err := s.opts.Avatars.Put(r.Context(), u.ID, u.Email, contentType, out); err != nil {
		s.opts.Logger.Error("avatar write failed", "sub", u.Subject(), "err", err)
		s.renderError(w, http.StatusInternalServerError, "プロフィール画像を保存できませんでした。時間をおいてもう一度お試しください。")
		return
	}
	s.opts.Logger.Info("avatar updated", "sub", u.Subject(), "type", contentType, "bytes", len(out))
	http.Redirect(w, r, "/account?done=updated", http.StatusSeeOther)
}

// readAvatar reads the single uploaded file.
func readAvatar(files []*multipart.FileHeader) ([]byte, avatarError) {
	switch {
	case len(files) == 0:
		return nil, errAvatarMissing
	case len(files) > 1:
		return nil, errAvatarMultiple
	case files[0].Size > maxAvatarBytes:
		return nil, errAvatarSize
	}
	f, err := files[0].Open()
	if err != nil {
		return nil, errAvatarMissing
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxAvatarBytes+1))
	switch {
	case err != nil || len(data) == 0:
		return nil, errAvatarMissing
	case len(data) > maxAvatarBytes:
		return nil, errAvatarSize
	}
	return data, ""
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
