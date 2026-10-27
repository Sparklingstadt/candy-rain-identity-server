package oidc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
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

const (
	msgBadType    = "画像は PNG・JPEG・WebP のいずれかにしてください"
	msgTooBig     = "画像は 1MB 以下にしてください"
	msgTooLarge   = "画像は 4096×4096 ピクセル以下にしてください"
	msgUnreadable = "画像を読み込めませんでした"
	msgMissing    = "画像を選択してください"
	msgUpdated    = "プロフィール画像を更新しました"
	msgDeleted    = "プロフィール画像を削除しました"
)

// A 1×1 lossless WebP.
var webpBytes, _ = base64.StdEncoding.DecodeString("UklGRhoAAABXRUJQVlA4TA0AAAAvAAAAEAcQERGIiP4HAA==")

func testImage(w, h int) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			img.Set(x, y, color.RGBA{uint8(x), uint8(y), 0x8f, 0xff})
		}
	}
	return img
}

func pngOf(w, h int) []byte {
	var buf bytes.Buffer
	png.Encode(&buf, testImage(w, h))
	return buf.Bytes()
}

func jpegOf(w, h int) []byte {
	var buf bytes.Buffer
	jpeg.Encode(&buf, testImage(w, h), nil)
	return buf.Bytes()
}

// exifSecret stands for the GPS position a phone writes into EXIF.
const exifSecret = "GPS-35.6812N-139.7671E"

// jpegWithEXIF inserts an APP1 (EXIF) segment right after SOI.
func jpegWithEXIF(w, h int) []byte {
	src := jpegOf(w, h)
	payload := append([]byte("Exif\x00\x00MM\x00\x2a\x00\x00\x00\x08"), exifSecret...)
	seg := []byte{0xff, 0xe1, 0, 0}
	binary.BigEndian.PutUint16(seg[2:], uint16(len(payload)+2))
	out := append([]byte{}, src[:2]...)
	out = append(out, seg...)
	out = append(out, payload...)
	return append(out, src[2:]...)
}

func decodeSize(t *testing.T, b []byte) (string, int, int) {
	t.Helper()
	cfg, format, err := image.DecodeConfig(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("stored image does not decode: %v", err)
	}
	return format, cfg.Width, cfg.Height
}

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
	if res.StatusCode != http.StatusOK {
		h.t.Fatalf("userinfo: %d", res.StatusCode)
	}
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

	a, _ := h.avatars.Put(context.Background(), 1, "user1@mail.com", "image/png", pngOf(4, 4))
	want := h.issuer() + "/avatars/" + a.ID
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

// An avatar left behind by a previous owner of the same user id (a deleted
// user, or a reset development database) is not attached to the new user.
func TestAvatarOfAnotherEmailIsIgnored(t *testing.T) {
	h := newHarness(t)
	a, _ := h.avatars.Put(context.Background(), 1, "previous-owner@mail.com", "image/png", pngOf(4, 4))

	idClaims, info := h.tokensFor("openid email profile")
	if _, ok := idClaims["picture"]; ok {
		t.Error("id_token has another user's picture")
	}
	if _, ok := info["picture"]; ok {
		t.Error("userinfo has another user's picture")
	}
	if res, _ := h.get("/avatars/" + a.ID); res.StatusCode != http.StatusNotFound {
		t.Errorf("/avatars of a stale row: %d", res.StatusCode)
	}
	h.client.Jar, _ = cookiejar.New(nil)
	h.accountLogin()
	if _, body := h.get("/account"); strings.Contains(body, "/avatars/") {
		t.Error("account page shows another user's avatar")
	}
}

type failingAvatars struct{}

var errAvatarDB = errors.New(`relation "idp.user_avatar" does not exist`)

func (failingAvatars) ForUser(context.Context, int64) (user.Avatar, error) {
	return user.Avatar{}, errAvatarDB
}
func (failingAvatars) ByID(context.Context, string) (user.Avatar, error) {
	return user.Avatar{}, errAvatarDB
}
func (failingAvatars) Put(context.Context, int64, string, string, []byte) (user.Avatar, error) {
	return user.Avatar{}, errAvatarDB
}
func (failingAvatars) Delete(context.Context, int64) error { return errAvatarDB }

// A broken avatar store (e.g. the migration is not applied yet) must not
// break sign-in: the picture claim is just omitted.
func TestFailingAvatarStoreOnlyOmitsPicture(t *testing.T) {
	h := newHarnessWith(t, failingAvatars{})
	idClaims, info := h.tokensFor("openid email profile")
	if _, ok := idClaims["picture"]; ok {
		t.Error("id_token has picture")
	}
	if _, ok := info["picture"]; ok {
		t.Error("userinfo has picture")
	}
	if idClaims["name"] != "雨宮 花子" || info["email"] != "user1@mail.com" {
		t.Errorf("other claims missing: %v %v", idClaims, info)
	}
	if res, _ := h.get("/avatars/" + user.NewAvatarID()); res.StatusCode != http.StatusInternalServerError {
		t.Errorf("/avatars: %d", res.StatusCode)
	}
	h.client.Jar, _ = cookiejar.New(nil)
	h.accountLogin()
	if res, _ := h.get("/account"); res.StatusCode != http.StatusInternalServerError {
		t.Errorf("/account: %d", res.StatusCode)
	}
}

func TestAvatarEndpoint(t *testing.T) {
	h := newHarness(t)
	a, _ := h.avatars.Put(context.Background(), 1, "user1@mail.com", "image/png", pngOf(4, 4))
	for _, path := range []string{
		"/avatars/1", "/avatars/2", "/avatars/abc",
		"/avatars/" + user.NewAvatarID(), // well-formed but unknown
		"/avatars/" + a.ID + "x",
	} {
		if res, _ := h.get(path); res.StatusCode != http.StatusNotFound {
			t.Errorf("%s: status %d", path, res.StatusCode)
		}
	}

	res, body := h.get("/avatars/" + a.ID)
	if res.StatusCode != http.StatusOK || !bytes.Equal([]byte(body), pngOf(4, 4)) {
		t.Fatalf("status %d", res.StatusCode)
	}
	for k, v := range map[string]string{
		"Content-Type":                 "image/png",
		"X-Content-Type-Options":       "nosniff",
		"ETag":                         `"` + a.ID + `"`,
		"Cache-Control":                "public, max-age=31536000, immutable",
		"Cross-Origin-Resource-Policy": "cross-origin",
		"Content-Security-Policy":      "default-src 'none'; sandbox",
		"Content-Disposition":          "inline",
	} {
		if got := res.Header.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}

	req, _ := http.NewRequest(http.MethodGet, h.issuer()+"/avatars/"+a.ID, nil)
	req.Header.Set("If-None-Match", `"`+a.ID+`"`)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNotModified {
		t.Errorf("If-None-Match: status %d", res.StatusCode)
	}

	// A new upload gets a new id; the old URL stops working.
	b, _ := h.avatars.Put(context.Background(), 1, "user1@mail.com", "image/png", pngOf(4, 4))
	if b.ID == a.ID {
		t.Fatal("the id did not change")
	}
	if res, _ := h.get("/avatars/" + a.ID); res.StatusCode != http.StatusNotFound {
		t.Errorf("old id after re-upload: %d", res.StatusCode)
	}
}

// The other routes keep the strict global headers.
func TestSecurityHeadersOutsideAvatars(t *testing.T) {
	h := newHarness(t)
	_, challenge := pkcePair()
	for _, path := range []string{"/healthz", "/account", "/authorize?" + authorizeQuery(challenge).Encode()} {
		res, _ := h.get(path)
		if got := res.Header.Get("Content-Security-Policy"); got != "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'" {
			t.Errorf("%s CSP = %q", path, got)
		}
		if res.Header.Get("X-Frame-Options") != "DENY" || res.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s lacks X-Frame-Options / nosniff", path)
		}
		if res.Header.Get("Cross-Origin-Resource-Policy") != "" {
			t.Errorf("%s has CORP", path)
		}
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
	return h.accountLoginAs("user1@mail.com")
}

func (h *harness) accountLoginAs(email string) string {
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
		"csrf_token": {m[1]}, "next": {"account"}, "email": {email}, "password": {password},
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
		return "" // the caller checks the status itself
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

// Opening /account signed out must not break a store login that is open in
// another tab (both forms use double-submit CSRF cookies).
func TestAccountLoginKeepsStoreLoginTabWorking(t *testing.T) {
	h := newHarness(t)
	_, challenge := pkcePair()
	q := authorizeQuery(challenge)
	_, storeForm := h.get("/authorize?" + q.Encode())
	storeToken := csrfField.FindStringSubmatch(storeForm)[1]

	_, accountForm := h.get("/account")
	accountToken := csrfField.FindStringSubmatch(accountForm)[1]
	// Opening /authorize again in a third tab does not break the account tab either.
	h.get("/authorize?" + q.Encode())

	form := url.Values{}
	for k, v := range q {
		form[k] = v
	}
	form.Set("csrf_token", storeToken)
	form.Set("email", "user1@mail.com")
	form.Set("password", password)
	res, err := h.client.PostForm(h.issuer()+"/authorize", form)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	codeFrom(t, res)

	h.client.Jar.SetCookies(mustURL(h.issuer()), []*http.Cookie{{Name: sessionName, Value: "", MaxAge: -1}})
	res, err = h.client.PostForm(h.issuer()+"/authorize", url.Values{
		"csrf_token": {accountToken}, "next": {"account"}, "email": {"user1@mail.com"}, "password": {password},
	})
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/account" {
		t.Fatalf("account tab: %d %q", res.StatusCode, res.Header.Get("Location"))
	}

	// One form's token does not pass for the other.
	res, err = h.client.PostForm(h.issuer()+"/authorize", url.Values{
		"csrf_token": {storeToken}, "next": {"account"}, "email": {"user1@mail.com"}, "password": {password},
	})
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("store token on the account form: %d", res.StatusCode)
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func TestAccountLoginHasNoOpenRedirect(t *testing.T) {
	_, challenge := pkcePair()
	full := authorizeQuery(challenge)
	withNext := func(extra url.Values) url.Values {
		v := url.Values{"next": {"account"}}
		for k, vs := range extra {
			v[k] = vs
		}
		return v
	}
	promptNone, promptLogin := url.Values{}, url.Values{}
	for k, v := range full {
		promptNone[k], promptLogin[k] = v, v
	}
	promptNone.Set("prompt", "none")
	promptLogin.Set("prompt", "login")
	for _, tc := range []struct {
		name  string
		extra url.Values
		// wantLocation is "" when the login must not redirect at all.
		wantLocation string
	}{
		{"next=account ignores redirect_uri", withNext(url.Values{"client_id": {clientID}, "redirect_uri": {"https://evil.test/cb"}}), "/account"},
		{"next=account ignores a full authorization request", withNext(full), "/account"},
		{"next=account with prompt=none", withNext(promptNone), "/account"},
		{"next=account with prompt=login", withNext(promptLogin), "/account"},
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

func (h *harness) upload(csrf, filename string, data []byte) *http.Response {
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
	res.Body.Close()
	return res
}

// uploadAndFollow uploads and follows the redirect back to /account.
func (h *harness) uploadAndFollow(csrf string, data []byte) (location, page string) {
	h.t.Helper()
	res := h.upload(csrf, "photo.gif", data)
	location = res.Header.Get("Location")
	if res.StatusCode != http.StatusSeeOther || !strings.HasPrefix(location, "/account?") {
		h.t.Fatalf("upload: status %d location %q", res.StatusCode, location)
	}
	_, page = h.get(location)
	return location, page
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
	a, err := h.avatars.ForUser(context.Background(), 1)
	if err != nil {
		return user.Avatar{}, false
	}
	a, err = h.avatars.ByID(context.Background(), a.ID)
	return a, err == nil
}

func TestAvatarUpload(t *testing.T) {
	big := pngOf(1024, 512)
	for _, tc := range []struct {
		name       string
		data       []byte
		wantFormat string
		wantW      int
		wantH      int
	}{
		{"png", pngOf(40, 30), "png", 40, 30},
		{"jpeg stays jpeg", jpegOf(40, 30), "jpeg", 40, 30},
		{"webp becomes png", webpBytes, "png", 1, 1},
		{"downscaled to fit 512", big, "png", 512, 256},
		{"tall jpeg downscaled", jpegOf(300, 1200), "jpeg", 128, 512},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			csrf := h.accountLogin()
			// The file name is ignored; the bytes decide the type.
			loc, page := h.uploadAndFollow(csrf, tc.data)
			if loc != "/account?done=updated" {
				t.Fatalf("location %q", loc)
			}
			a, ok := h.avatar()
			if !ok {
				t.Fatal("not stored")
			}
			format, w, hh := decodeSize(t, a.Data)
			if format != tc.wantFormat || a.ContentType != "image/"+tc.wantFormat || w != tc.wantW || hh != tc.wantH {
				t.Fatalf("stored %s %s %dx%d", format, a.ContentType, w, hh)
			}
			if a.Email != "user1@mail.com" || !user.ValidAvatarID(a.ID) {
				t.Errorf("stored email %q id %q", a.Email, a.ID)
			}
			if !strings.Contains(page, msgUpdated) || !strings.Contains(page, `src="/avatars/`+a.ID+`"`) {
				t.Error("account page does not show the new avatar and message")
			}
		})
	}
}

func TestAvatarUploadStripsEXIF(t *testing.T) {
	h := newHarness(t)
	csrf := h.accountLogin()
	src := jpegWithEXIF(64, 48)
	if !bytes.Contains(src, []byte(exifSecret)) {
		t.Fatal("fixture has no EXIF")
	}
	if loc, _ := h.uploadAndFollow(csrf, src); loc != "/account?done=updated" {
		t.Fatalf("location %q", loc)
	}
	a, _ := h.avatar()
	_, served := h.get("/avatars/" + a.ID)
	for _, b := range [][]byte{a.Data, []byte(served)} {
		if bytes.Contains(b, []byte(exifSecret)) || bytes.Contains(b, []byte("Exif\x00")) {
			t.Fatal("EXIF survived the upload")
		}
	}
	if format, w, hh := decodeSize(t, a.Data); format != "jpeg" || w != 64 || hh != 48 {
		t.Fatalf("stored %s %dx%d", format, w, hh)
	}
}

func TestAvatarUploadValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		data    []byte
		code    string
		message string
	}{
		{"gif", []byte("GIF89a" + strings.Repeat("\x00", 32)), "type", msgBadType},
		{"svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`), "type", msgBadType},
		{"html", []byte("<!doctype html><script>alert(1)</script>"), "type", msgBadType},
		{"riff but not webp", []byte("RIFF\x24\x00\x00\x00WAVEfmt " + strings.Repeat("\x00", 32)), "type", msgBadType},
		{"png magic then junk", append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte("junk"), 64)...), "decode", msgUnreadable},
		{"jpeg magic then junk", append([]byte("\xff\xd8\xff\xe0"), bytes.Repeat([]byte("junk"), 64)...), "decode", msgUnreadable},
		{"webp magic then junk", append([]byte("RIFF\x24\x00\x00\x00WEBPVP8 "), bytes.Repeat([]byte("junk"), 64)...), "decode", msgUnreadable},
		{"truncated png", pngOf(64, 64)[:100], "decode", msgUnreadable},
		{"too wide", pngOf(4097, 1), "dimensions", msgTooLarge},
		{"too tall", pngOf(1, 4097), "dimensions", msgTooLarge},
		{"empty", []byte{}, "missing", msgMissing},
		{"no file", nil, "missing", msgMissing},
		{"over 1MB", append(pngOf(8, 8), make([]byte, 1<<20)...), "size", msgTooBig},
		{"far over 1MB", append(pngOf(8, 8), make([]byte, 3<<20)...), "size", msgTooBig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			csrf := h.accountLogin()
			loc, page := h.uploadAndFollow(csrf, tc.data)
			if loc != "/account?error="+tc.code || !strings.Contains(page, tc.message) {
				t.Fatalf("location %q, want error=%s with %q", loc, tc.code, tc.message)
			}
			if _, ok := h.avatar(); ok {
				t.Fatal("rejected image was stored")
			}
		})
	}

	// A decompression bomb: a small file that declares a huge canvas.
	t.Run("declared size bomb", func(t *testing.T) {
		h := newHarness(t)
		csrf := h.accountLogin()
		bomb := pngOf(1, 1)
		// Rewrite IHDR to 50000×50000 (the CRC no longer matches, which
		// DecodeConfig does not check; the dimension check must reject it).
		binary.BigEndian.PutUint32(bomb[16:], 50000)
		binary.BigEndian.PutUint32(bomb[20:], 50000)
		loc, _ := h.uploadAndFollow(csrf, bomb)
		if loc != "/account?error=dimensions" && loc != "/account?error=decode" {
			t.Fatalf("location %q", loc)
		}
		if _, ok := h.avatar(); ok {
			t.Fatal("stored")
		}
	})

	// Unknown codes show nothing and are not reflected.
	h := newHarness(t)
	h.accountLogin()
	if _, body := h.get("/account?error=<script>&done=<b>"); strings.Contains(body, "<script>") || strings.Contains(body, "<b>") || strings.Contains(body, `class="error"`) {
		t.Error("query parameters are reflected")
	}
}

func TestAvatarUploadNeedsCSRFAndSession(t *testing.T) {
	h := newHarness(t)
	csrf := h.accountLogin()
	for _, token := range []string{"", "forged", csrf + "x"} {
		if res := h.upload(token, "a.png", pngOf(4, 4)); res.StatusCode != http.StatusForbidden {
			t.Errorf("csrf %q: status %d", token, res.StatusCode)
		}
	}
	if _, ok := h.avatar(); ok {
		t.Fatal("stored without a valid CSRF token")
	}

	// The token of session A does not work in session B.
	h.client.Jar, _ = cookiejar.New(nil)
	h.accountLoginAs("user2@mail.com")
	if res := h.upload(csrf, "a.png", pngOf(4, 4)); res.StatusCode != http.StatusForbidden {
		t.Errorf("other session's token on upload: %d", res.StatusCode)
	}
	if res := h.deleteAvatar(csrf); res.StatusCode != http.StatusForbidden {
		t.Errorf("other session's token on delete: %d", res.StatusCode)
	}

	// No session at all.
	h.client.Jar, _ = cookiejar.New(nil)
	if res := h.upload(csrf, "a.png", pngOf(4, 4)); res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/account" {
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
	h.uploadAndFollow(csrf, pngOf(4, 4))
	a, ok := h.avatar()
	if !ok {
		t.Fatal("upload failed")
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
	if res, _ := h.get("/avatars/" + a.ID); res.StatusCode != http.StatusNotFound {
		t.Errorf("/avatars after delete: %d", res.StatusCode)
	}
	_, body := h.get("/account?done=deleted")
	if !strings.Contains(body, msgDeleted) || strings.Contains(body, `src="/avatars/`) || strings.Contains(body, `action="/account/avatar/delete"`) {
		t.Error("account page should show the deleted message and no image")
	}
}
