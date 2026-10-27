package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Sparklingstadt/candy-rain-identity-server/internal/user"
)

var (
	pngBytes  = append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0}, 32)...)
	jpegBytes = append([]byte("\xff\xd8\xff\xe0"), bytes.Repeat([]byte{0}, 32)...)
	webpBytes = append([]byte("RIFF\x24\x00\x00\x00WEBPVP8 "), bytes.Repeat([]byte{0}, 32)...)
)

const (
	msgBadType = "画像は PNG・JPEG・WebP のいずれかにしてください"
	msgTooBig  = "画像は 1MB 以下にしてください"
	msgUpdated = "プロフィール画像を更新しました"
	msgDeleted = "プロフィール画像を削除しました"
)

func (h *harness) get(path string) (*http.Response, string) {
	h.t.Helper()
	res, err := h.client.Get(h.issuer() + path)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res, string(body)
}

// tokensFor signs in through the store client with the given scope and
// returns the verified ID token claims and the userinfo response.
func (h *harness) tokensFor(scope string) (idClaims, info map[string]any) {
	h.t.Helper()
	verifier, challenge := pkcePair()
	q := authorizeQuery(challenge)
	q.Set("scope", scope)
	// A fresh jar each time so the login form is shown and the code issued.
	jar, _ := cookiejar.New(nil)
	h.client.Jar = jar
	code := codeFrom(h.t, h.login(q, "user1@mail.com", password))
	res, tokens := h.exchange(code, verifier)
	if res.StatusCode != http.StatusOK {
		h.t.Fatalf("token: %d %v", res.StatusCode, tokens)
	}
	idClaims, err := h.signer.Verify(tokens["id_token"].(string), "JWT", time.Now())
	if err != nil {
		h.t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, h.issuer()+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokens["access_token"].(string))
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	json.NewDecoder(res.Body).Decode(&info)
	return idClaims, info
}

func TestPictureClaim(t *testing.T) {
	h := newHarness(t)

	var doc struct {
		Claims []string `json:"claims_supported"`
	}
	res, err := http.Get(h.issuer() + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	json.NewDecoder(res.Body).Decode(&doc)
	res.Body.Close()
	if !slices.Contains(doc.Claims, "picture") {
		t.Errorf("claims_supported lacks picture: %v", doc.Claims)
	}

	// No avatar: the claim is omitted.
	idClaims, info := h.tokensFor("openid email profile")
	if _, ok := idClaims["picture"]; ok {
		t.Errorf("id_token has picture without an avatar: %v", idClaims["picture"])
	}
	if _, ok := info["picture"]; ok {
		t.Errorf("userinfo has picture without an avatar: %v", info["picture"])
	}

	a, _ := h.avatars.Put(context.Background(), 1, "image/png", pngBytes)
	want := h.issuer() + "/avatars/1?v=" + a.ETag
	idClaims, info = h.tokensFor("openid email profile")
	if idClaims["picture"] != want {
		t.Errorf("id_token picture = %v, want %s", idClaims["picture"], want)
	}
	if info["picture"] != want {
		t.Errorf("userinfo picture = %v, want %s", info["picture"], want)
	}

	// picture belongs to the profile scope.
	idClaims, info = h.tokensFor("openid email")
	if _, ok := idClaims["picture"]; ok {
		t.Error("id_token has picture without the profile scope")
	}
	if _, ok := info["picture"]; ok {
		t.Error("userinfo has picture without the profile scope")
	}
}

func TestAvatarEndpoint(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/avatars/1", "/avatars/2", "/avatars/abc", "/avatars/-1"} {
		if res, _ := h.get(path); res.StatusCode != http.StatusNotFound {
			t.Errorf("%s without an avatar: status %d", path, res.StatusCode)
		}
	}

	a, _ := h.avatars.Put(context.Background(), 1, "image/png", pngBytes)
	res, body := h.get("/avatars/1")
	if res.StatusCode != http.StatusOK || body != string(pngBytes) {
		t.Fatalf("status %d body %q", res.StatusCode, body)
	}
	for k, v := range map[string]string{
		"Content-Type":                 "image/png",
		"X-Content-Type-Options":       "nosniff",
		"ETag":                         `"` + a.ETag + `"`,
		"Cache-Control":                "public, max-age=300",
		"Cross-Origin-Resource-Policy": "cross-origin",
	} {
		if got := res.Header.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}

	// The versioned URL from the picture claim is immutable.
	res, _ = h.get("/avatars/1?v=" + a.ETag)
	if got := res.Header.Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Errorf("versioned Cache-Control = %q", got)
	}
	// A stale version is served, but not as immutable.
	res, _ = h.get("/avatars/1?v=old")
	if got := res.Header.Get("Cache-Control"); got != "public, max-age=300" {
		t.Errorf("stale version Cache-Control = %q", got)
	}

	req, _ := http.NewRequest(http.MethodGet, h.issuer()+"/avatars/1", nil)
	req.Header.Set("If-None-Match", `"`+a.ETag+`"`)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNotModified {
		t.Errorf("If-None-Match: status %d", res.StatusCode)
	}

	// Only the avatar route may be embedded from another origin.
	if res, _ := h.get("/healthz"); res.Header.Get("Cross-Origin-Resource-Policy") == "cross-origin" {
		t.Error("CORP cross-origin leaked to other routes")
	}
}

var (
	nextField   = regexp.MustCompile(`name="next" value="([^"]*)"`)
	clientField = regexp.MustCompile(`name="client_id"`)
)

// accountLogin signs in from the signed-out /account page and returns the
// CSRF token of the account page.
func (h *harness) accountLogin() string {
	h.t.Helper()
	res, body := h.get("/account")
	if res.StatusCode != http.StatusOK {
		h.t.Fatalf("GET /account signed out: %d", res.StatusCode)
	}
	m := csrfField.FindStringSubmatch(body)
	if m == nil {
		h.t.Fatal("login form has no csrf token")
	}
	res, err := h.client.PostForm(h.issuer()+"/authorize", url.Values{
		"csrf_token": {m[1]}, "next": {"account"}, "email": {"user1@mail.com"}, "password": {password},
	})
	if err != nil {
		h.t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/account" {
		h.t.Fatalf("account login: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	res, body = h.get("/account")
	if res.StatusCode != http.StatusOK {
		h.t.Fatalf("GET /account signed in: %d", res.StatusCode)
	}
	m = csrfField.FindStringSubmatch(body)
	if m == nil {
		h.t.Fatal("account page has no csrf token")
	}
	return m[1]
}

func TestAccountLoginRoundTrip(t *testing.T) {
	h := newHarness(t)
	res, body := h.get("/account")
	if res.StatusCode != http.StatusOK || !strings.Contains(body, `action="/authorize"`) {
		t.Fatalf("signed-out /account should show the login form: %d", res.StatusCode)
	}
	if m := nextField.FindStringSubmatch(body); m == nil || m[1] != "account" {
		t.Fatalf("login form should carry next=account, got %v", m)
	}
	if clientField.MatchString(body) {
		t.Error("standalone login form must not carry OIDC fields")
	}
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Error("login form must not be cached")
	}

	// A wrong password shows the account login form again.
	m := csrfField.FindStringSubmatch(body)
	res, err := h.client.PostForm(h.issuer()+"/authorize", url.Values{
		"csrf_token": {m[1]}, "next": {"account"}, "email": {"user1@mail.com"}, "password": {"wrong"},
	})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized || !nextField.Match(b) {
		t.Fatalf("wrong password: %d", res.StatusCode)
	}

	h.accountLogin()
	res, body = h.get("/account")
	for _, want := range []string{"雨宮 花子", "user1@mail.com", `enctype="multipart/form-data"`, `action="/account/avatar"`} {
		if !strings.Contains(body, want) {
			t.Errorf("account page lacks %q", want)
		}
	}
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Error("account page must not be cached")
	}
	if csp := res.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "img-src 'self'") || !strings.Contains(csp, "form-action 'self'") {
		t.Errorf("account page CSP = %q", csp)
	}

	// The IdP session is the shared SSO session: a client signs in without the form.
	_, challenge := pkcePair()
	res, err = h.client.Get(h.issuer() + "/authorize?" + authorizeQuery(challenge).Encode())
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	codeFrom(t, res)
}

func TestAccountLoginHasNoOpenRedirect(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra url.Values
		// wantLocation is "" when the login must not redirect at all.
		wantLocation string
	}{
		{"next=account ignores redirect_uri", url.Values{"next": {"account"}, "client_id": {clientID}, "redirect_uri": {"https://evil.test/cb"}}, "/account"},
		{"next=account ignores a registered redirect_uri", url.Values{"next": {"account"}, "client_id": {clientID}, "redirect_uri": {redirectURI}}, "/account"},
		{"absolute URL", url.Values{"next": {"https://evil.test/"}}, ""},
		{"scheme-relative URL", url.Values{"next": {"//evil.test/"}}, ""},
		{"backslash URL", url.Values{"next": {`/\evil.test`}}, ""},
		{"path", url.Values{"next": {"/account/../logout"}}, ""},
		{"no next and no client", url.Values{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			_, body := h.get("/account?next=https://evil.test/&redirect_uri=https://evil.test/")
			m := csrfField.FindStringSubmatch(body)
			if m == nil {
				t.Fatal("no csrf token")
			}
			form := url.Values{"csrf_token": {m[1]}, "email": {"user1@mail.com"}, "password": {password}}
			for k, v := range tc.extra {
				form[k] = v
			}
			res, err := h.client.PostForm(h.issuer()+"/authorize", form)
			if err != nil {
				t.Fatal(err)
			}
			res.Body.Close()
			loc := res.Header.Get("Location")
			if tc.wantLocation == "" {
				if loc != "" || res.StatusCode != http.StatusBadRequest {
					t.Fatalf("status %d location %q", res.StatusCode, loc)
				}
				return
			}
			if res.StatusCode != http.StatusSeeOther || loc != tc.wantLocation {
				t.Fatalf("status %d location %q", res.StatusCode, loc)
			}
		})
	}
}

func (h *harness) upload(csrf, filename string, data []byte) (*http.Response, string) {
	h.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if csrf != "" {
		mw.WriteField("csrf_token", csrf)
	}
	if data != nil {
		fw, _ := mw.CreateFormFile("avatar", filename)
		fw.Write(data)
	}
	mw.Close()
	res, err := h.client.Post(h.issuer()+"/account/avatar", mw.FormDataContentType(), &buf)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res, string(body)
}

func (h *harness) deleteAvatar(csrf string) *http.Response {
	h.t.Helper()
	form := url.Values{}
	if csrf != "" {
		form.Set("csrf_token", csrf)
	}
	res, err := h.client.PostForm(h.issuer()+"/account/avatar/delete", form)
	if err != nil {
		h.t.Fatal(err)
	}
	res.Body.Close()
	return res
}

func (h *harness) avatar() (user.Avatar, bool) {
	a, err := h.avatars.Get(context.Background(), 1)
	return a, err == nil
}

func TestAvatarUpload(t *testing.T) {
	for _, tc := range []struct {
		name, contentType string
		data              []byte
	}{
		{"png", "image/png", pngBytes},
		{"jpeg", "image/jpeg", jpegBytes},
		{"webp", "image/webp", webpBytes},
		{"exactly 1MB", "image/png", append(append([]byte{}, pngBytes...), make([]byte, 1<<20-len(pngBytes))...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			csrf := h.accountLogin()
			// The file name is ignored; the bytes decide the type.
			res, _ := h.upload(csrf, "photo.gif", tc.data)
			if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/account?done=updated" {
				t.Fatalf("status %d location %q", res.StatusCode, res.Header.Get("Location"))
			}
			a, ok := h.avatar()
			if !ok || a.ContentType != tc.contentType || !bytes.Equal(a.Data, tc.data) {
				t.Fatalf("stored %v %q", ok, a.ContentType)
			}
			_, body := h.get("/account?done=updated")
			if !strings.Contains(body, msgUpdated) || !strings.Contains(body, `src="/avatars/1?v=`+a.ETag+`"`) {
				t.Error("account page does not show the new avatar and message")
			}
		})
	}
}

func TestAvatarUploadValidation(t *testing.T) {
	big := append(append([]byte{}, pngBytes...), make([]byte, 1<<20)...)
	for _, tc := range []struct {
		name     string
		data     []byte
		status   int
		message  string
		filename string
	}{
		{"gif", []byte("GIF89a" + strings.Repeat("\x00", 32)), http.StatusBadRequest, msgBadType, "a.png"},
		{"svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`), http.StatusBadRequest, msgBadType, "a.png"},
		{"html", []byte("<!doctype html><script>alert(1)</script>"), http.StatusBadRequest, msgBadType, "a.webp"},
		{"riff but not webp", []byte("RIFF\x24\x00\x00\x00WAVEfmt " + strings.Repeat("\x00", 32)), http.StatusBadRequest, msgBadType, "a.webp"},
		{"empty", []byte{}, http.StatusBadRequest, "画像を選択してください", "a.png"},
		{"no file", nil, http.StatusBadRequest, "画像を選択してください", ""},
		{"over 1MB", big, http.StatusRequestEntityTooLarge, msgTooBig, "a.png"},
		{"far over 1MB", append(append([]byte{}, pngBytes...), make([]byte, 3<<20)...), http.StatusRequestEntityTooLarge, msgTooBig, "a.png"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			csrf := h.accountLogin()
			res, body := h.upload(csrf, tc.filename, tc.data)
			if res.StatusCode != tc.status || !strings.Contains(body, tc.message) {
				t.Fatalf("status %d, want %d with %q", res.StatusCode, tc.status, tc.message)
			}
			if _, ok := h.avatar(); ok {
				t.Fatal("rejected image was stored")
			}
		})
	}
}

func TestAvatarUploadNeedsCSRFAndSession(t *testing.T) {
	h := newHarness(t)
	csrf := h.accountLogin()
	for _, token := range []string{"", "forged", csrf + "x"} {
		if res, _ := h.upload(token, "a.png", pngBytes); res.StatusCode != http.StatusForbidden {
			t.Errorf("csrf %q: status %d", token, res.StatusCode)
		}
	}
	if _, ok := h.avatar(); ok {
		t.Fatal("stored without a valid CSRF token")
	}

	// The token of one session is useless without that session.
	jar, _ := cookiejar.New(nil)
	h.client.Jar = jar
	res, _ := h.upload(csrf, "a.png", pngBytes)
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/account" {
		t.Fatalf("no session: status %d location %q", res.StatusCode, res.Header.Get("Location"))
	}
	if res := h.deleteAvatar(csrf); res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/account" {
		t.Fatalf("delete without session: status %d location %q", res.StatusCode, res.Header.Get("Location"))
	}
	if _, ok := h.avatar(); ok {
		t.Fatal("stored without a session")
	}
}

func TestAvatarDelete(t *testing.T) {
	h := newHarness(t)
	csrf := h.accountLogin()
	if res, _ := h.upload(csrf, "a.png", pngBytes); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("upload: %d", res.StatusCode)
	}
	if _, body := h.get("/account"); !strings.Contains(body, `action="/account/avatar/delete"`) {
		t.Error("account page lacks the delete button")
	}

	if res := h.deleteAvatar(""); res.StatusCode != http.StatusForbidden {
		t.Fatalf("delete without csrf: %d", res.StatusCode)
	}
	if _, ok := h.avatar(); !ok {
		t.Fatal("deleted without a CSRF token")
	}

	res := h.deleteAvatar(csrf)
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/account?done=deleted" {
		t.Fatalf("delete: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	if _, ok := h.avatar(); ok {
		t.Fatal("avatar still stored")
	}
	if res, _ := h.get("/avatars/1"); res.StatusCode != http.StatusNotFound {
		t.Errorf("/avatars/1 after delete: %d", res.StatusCode)
	}
	_, body := h.get("/account?done=deleted")
	if !strings.Contains(body, msgDeleted) || strings.Contains(body, `src="/avatars/1`) || strings.Contains(body, `action="/account/avatar/delete"`) {
		t.Error("account page should show the deleted message and no image")
	}
	// Unknown done values show nothing.
	if _, body := h.get("/account?done=<script>"); strings.Contains(body, "<script>") {
		t.Error("done parameter is reflected")
	}
}
