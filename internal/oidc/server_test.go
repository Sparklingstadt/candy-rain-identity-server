package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/Sparklingstadt/candy-rain-identity-server/internal/config"
	"github.com/Sparklingstadt/candy-rain-identity-server/internal/user"
)

const (
	clientID     = "candy-rain-store"
	clientSecret = "store-secret"
	redirectURI  = "http://store.test/api/auth/callback/candy-rain-id"
	logoutURI    = "http://store.test/signout"
	password     = "demo-password"

	// A second client, so tests can check that clients stay separate.
	storesClientID     = "candy-rain-stores"
	storesClientSecret = "stores-secret"
	storesRedirectURI  = "http://stores.test/api/auth/callback/candy-rain-id"
	storesLogoutURI    = "http://stores.test/"
)

type fakeStore struct{ users []user.User }

func (f fakeStore) FindByEmail(_ context.Context, email string) (user.User, error) {
	for _, u := range f.users {
		if u.Email == email {
			return u, nil
		}
	}
	return user.User{}, user.ErrNotFound
}

func (f fakeStore) FindByID(_ context.Context, id int64) (user.User, error) {
	for _, u := range f.users {
		if u.ID == id {
			return u, nil
		}
	}
	return user.User{}, user.ErrNotFound
}

type harness struct {
	t       *testing.T
	ts      *httptest.Server
	client  *http.Client
	signer  *Signer
	avatars *user.MemoryAvatarStore
	srv     *Server
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	avatars := user.NewMemoryAvatarStore()
	h := newHarnessWith(t, avatars)
	h.avatars = avatars
	return h
}

// newHarnessWith runs the server on any avatar store, e.g. a failing one.
func newHarnessWith(t *testing.T, avatars user.AvatarStore) *harness {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	store := fakeStore{users: []user.User{
		{ID: 1, Email: "user1@mail.com", PasswordHash: string(hash), FirstName: "花子", LastName: "雨宮", Role: "CUSTOMER"},
		{ID: 2, Email: "user2@mail.com", PasswordHash: string(hash), FirstName: "太郎", LastName: "晴山", Role: "CUSTOMER"},
	}}
	signer := NewSigner(key)
	h := &harness{t: t, signer: signer}
	h.ts = httptest.NewUnstartedServer(nil)
	issuer := "http://" + h.ts.Listener.Addr().String()
	h.srv = New(Options{
		Issuer: issuer,
		Clients: []config.Client{{
			ID: clientID, Secret: clientSecret,
			RedirectURIs: []string{redirectURI}, PostLogoutRedirectURIs: []string{logoutURI},
		}, {
			ID: storesClientID, Secret: storesClientSecret,
			RedirectURIs: []string{storesRedirectURI}, PostLogoutRedirectURIs: []string{storesLogoutURI},
		}},
		Users:         store,
		Avatars:       avatars,
		Signer:        signer,
		SessionSecret: []byte(strings.Repeat("s", 32)),
	})
	h.ts.Config.Handler = h.srv
	h.ts.Start()
	t.Cleanup(h.ts.Close)

	jar, _ := cookiejar.New(nil)
	h.client = &http.Client{
		Jar: jar,
		// Stop at the redirect to the store so the test can read the code.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return h
}

func (h *harness) issuer() string { return h.ts.URL }

func pkcePair() (verifier, challenge string) {
	verifier = strings.Repeat("v", 50)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, b64.EncodeToString(sum[:])
}

// storesAuthorizeQuery is authorizeQuery for the second client.
func storesAuthorizeQuery(challenge string) url.Values {
	q := authorizeQuery(challenge)
	q.Set("client_id", storesClientID)
	q.Set("redirect_uri", storesRedirectURI)
	return q
}

func authorizeQuery(challenge string) url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid email profile"},
		"state":                 {"state-123"},
		"nonce":                 {"nonce-456"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
}

var csrfField = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

// login renders the form and submits it, returning the final response.
func (h *harness) login(q url.Values, email, pass string) *http.Response {
	h.t.Helper()
	res, err := h.client.Get(h.issuer() + "/authorize?" + q.Encode())
	if err != nil {
		h.t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		h.t.Fatalf("GET /authorize: status %d", res.StatusCode)
	}
	m := csrfField.FindSubmatch(body)
	if m == nil {
		h.t.Fatal("login form has no csrf token")
	}
	form := url.Values{}
	for k, v := range q {
		form[k] = v
	}
	form.Set("csrf_token", string(m[1]))
	form.Set("email", email)
	form.Set("password", pass)
	res, err = h.client.PostForm(h.issuer()+"/authorize", form)
	if err != nil {
		h.t.Fatal(err)
	}
	return res
}

func codeFrom(t *testing.T, res *http.Response) string {
	t.Helper()
	return codeAt(t, res, redirectURI)
}

// codeAt reads the code from a redirect that must go to redirectTo.
func codeAt(t *testing.T, res *http.Response, redirectTo string) string {
	t.Helper()
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected redirect to the store, got %d", res.StatusCode)
	}
	loc, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := loc.Scheme + "://" + loc.Host + loc.Path; got != redirectTo {
		t.Fatalf("redirected to %s", got)
	}
	if loc.Query().Get("state") != "state-123" {
		t.Fatalf("state not echoed: %v", loc.Query())
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %s", loc)
	}
	return code
}

func (h *harness) exchange(code, verifier string) (*http.Response, map[string]any) {
	h.t.Helper()
	return h.exchangeAs(clientID, clientSecret, redirectURI, code, verifier)
}

func (h *harness) exchangeAs(id, secret, redirectTo, code, verifier string) (*http.Response, map[string]any) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.issuer()+"/token", strings.NewReader(url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectTo},
		"code_verifier": {verifier},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(id, secret)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	var body map[string]any
	json.NewDecoder(res.Body).Decode(&body)
	return res, body
}

func TestDiscoveryAndJWKS(t *testing.T) {
	h := newHarness(t)
	res, err := http.Get(h.issuer() + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	json.NewDecoder(res.Body).Decode(&doc)
	res.Body.Close()
	if doc["issuer"] != h.issuer() || doc["jwks_uri"] != h.issuer()+"/jwks" {
		t.Fatalf("unexpected discovery document: %v", doc)
	}

	res, err = http.Get(h.issuer() + "/jwks")
	if err != nil {
		t.Fatal(err)
	}
	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	json.NewDecoder(res.Body).Decode(&jwks)
	res.Body.Close()
	if len(jwks.Keys) != 1 || jwks.Keys[0]["kid"] != h.signer.kid || jwks.Keys[0]["alg"] != "RS256" {
		t.Fatalf("unexpected jwks: %v", jwks)
	}
}

func TestAuthorizationCodeFlow(t *testing.T) {
	h := newHarness(t)
	verifier, challenge := pkcePair()
	code := codeFrom(t, h.login(authorizeQuery(challenge), "user1@mail.com", password))

	res, tokens := h.exchange(code, verifier)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("token: status %d %v", res.StatusCode, tokens)
	}
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Error("token response must not be cached")
	}

	idToken, _ := tokens["id_token"].(string)
	claims, err := h.signer.Verify(idToken, "JWT", time.Now())
	if err != nil {
		t.Fatalf("id_token does not verify: %v", err)
	}
	want := map[string]any{
		"iss": h.issuer(), "aud": clientID, "sub": "1", "nonce": "nonce-456",
		"email": "user1@mail.com", "name": "雨宮 花子", "role": "CUSTOMER",
	}
	for k, v := range want {
		if claims[k] != v {
			t.Errorf("id_token %s = %v, want %v", k, claims[k], v)
		}
	}

	req, _ := http.NewRequest(http.MethodGet, h.issuer()+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokens["access_token"].(string))
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var info map[string]any
	json.NewDecoder(res.Body).Decode(&info)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || info["sub"] != "1" || info["email"] != "user1@mail.com" {
		t.Fatalf("userinfo: %d %v", res.StatusCode, info)
	}

	// The same code cannot be redeemed twice.
	if res, body := h.exchange(code, verifier); res.StatusCode != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("code reuse: %d %v", res.StatusCode, body)
	}
}

func TestWrongPasswordShowsFormAgain(t *testing.T) {
	h := newHarness(t)
	_, challenge := pkcePair()
	for _, tc := range []struct{ email, pass string }{
		{"user1@mail.com", "wrong"},
		{"nobody@mail.com", password},
	} {
		res := h.login(authorizeQuery(challenge), tc.email, tc.pass)
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized || !strings.Contains(string(body), "メールアドレスまたはパスワードが違います") {
			t.Fatalf("%s: status %d", tc.email, res.StatusCode)
		}
	}
}

func TestTokenRejectsWrongVerifierAndClient(t *testing.T) {
	h := newHarness(t)
	_, challenge := pkcePair()
	code := codeFrom(t, h.login(authorizeQuery(challenge), "user1@mail.com", password))
	if res, body := h.exchange(code, strings.Repeat("x", 50)); res.StatusCode != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("wrong verifier: %d %v", res.StatusCode, body)
	}

	req, _ := http.NewRequest(http.MethodPost, h.issuer()+"/token", strings.NewReader("grant_type=authorization_code"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, "wrong-secret")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong client secret: %d", res.StatusCode)
	}
}

func TestUntrustedRedirectURIIsNotFollowed(t *testing.T) {
	h := newHarness(t)
	_, challenge := pkcePair()
	q := authorizeQuery(challenge)
	q.Set("redirect_uri", "https://evil.test/callback")
	res, err := h.client.Get(h.issuer() + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest || res.Header.Get("Location") != "" {
		t.Fatalf("status %d location %q", res.StatusCode, res.Header.Get("Location"))
	}
}

func TestPKCEIsRequired(t *testing.T) {
	h := newHarness(t)
	q := authorizeQuery("")
	q.Del("code_challenge")
	res, err := h.client.Get(h.issuer() + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	loc, _ := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != http.StatusSeeOther || loc.Query().Get("error") != "invalid_request" {
		t.Fatalf("status %d location %v", res.StatusCode, loc)
	}
}

func TestLoginWithoutCSRFTokenIsRejected(t *testing.T) {
	h := newHarness(t)
	_, challenge := pkcePair()
	form := authorizeQuery(challenge)
	form.Set("email", "user1@mail.com")
	form.Set("password", password)
	res, err := h.client.PostForm(h.issuer()+"/authorize", form)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", res.StatusCode)
	}
}

func TestSessionSkipsFormUntilLogout(t *testing.T) {
	h := newHarness(t)
	_, challenge := pkcePair()
	codeFrom(t, h.login(authorizeQuery(challenge), "user1@mail.com", password))

	// Signed in already: the identity server answers with a code right away.
	res, err := h.client.Get(h.issuer() + "/authorize?" + authorizeQuery(challenge).Encode())
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	codeFrom(t, res)

	res, err = h.client.Get(h.issuer() + "/logout?" + url.Values{
		"post_logout_redirect_uri": {logoutURI}, "state": {"bye"},
	}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusFound || res.Header.Get("Location") != logoutURI+"?state=bye" {
		t.Fatalf("logout: %d %q", res.StatusCode, res.Header.Get("Location"))
	}

	res, err = h.client.Get(h.issuer() + "/authorize?" + authorizeQuery(challenge).Encode())
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("after logout the form should show again, got %d", res.StatusCode)
	}
}

func TestSecondClientSignsInWithSharedSession(t *testing.T) {
	h := newHarness(t)
	verifier, challenge := pkcePair()
	code := codeAt(t, h.login(storesAuthorizeQuery(challenge), "user1@mail.com", password), storesRedirectURI)

	res, tokens := h.exchangeAs(storesClientID, storesClientSecret, storesRedirectURI, code, verifier)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("token: status %d %v", res.StatusCode, tokens)
	}
	claims, err := h.signer.Verify(tokens["id_token"].(string), "JWT", time.Now())
	if err != nil {
		t.Fatalf("id_token does not verify: %v", err)
	}
	if claims["aud"] != storesClientID || claims["sub"] != "1" {
		t.Fatalf("id_token aud %v sub %v", claims["aud"], claims["sub"])
	}

	// Signed in through one client, the other gets a code without the form.
	res, err = h.client.Get(h.issuer() + "/authorize?" + authorizeQuery(challenge).Encode())
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	codeFrom(t, res)
}

func TestClientsCannotUseEachOthersCodesOrRedirects(t *testing.T) {
	h := newHarness(t)
	verifier, challenge := pkcePair()

	// A code issued to candy-rain-store cannot be redeemed by candy-rain-stores.
	code := codeFrom(t, h.login(authorizeQuery(challenge), "user1@mail.com", password))
	for _, redirectTo := range []string{redirectURI, storesRedirectURI} {
		res, body := h.exchangeAs(storesClientID, storesClientSecret, redirectTo, code, verifier)
		if res.StatusCode != http.StatusBadRequest || body["error"] != "invalid_grant" {
			t.Fatalf("other client's code via %s: %d %v", redirectTo, res.StatusCode, body)
		}
	}

	// One client's secret does not authenticate the other.
	if res, body := h.exchangeAs(storesClientID, clientSecret, storesRedirectURI, code, verifier); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("other client's secret: %d %v", res.StatusCode, body)
	}

	// A redirect URI registered for one client is not accepted for the other.
	q := authorizeQuery(challenge)
	q.Set("redirect_uri", storesRedirectURI)
	res, err := h.client.Get(h.issuer() + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest || res.Header.Get("Location") != "" {
		t.Fatalf("other client's redirect_uri: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
}

func TestLogoutRedirectIsCheckedAgainstTheNamedClient(t *testing.T) {
	h := newHarness(t)
	for _, tc := range []struct {
		clientID, target string
		follow           bool
	}{
		{storesClientID, storesLogoutURI, true},
		{"", storesLogoutURI, true},
		{clientID, storesLogoutURI, false},
		{"unknown", logoutURI, false},
	} {
		q := url.Values{"post_logout_redirect_uri": {tc.target}}
		if tc.clientID != "" {
			q.Set("client_id", tc.clientID)
		}
		res, err := h.client.Get(h.issuer() + "/logout?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		followed := res.StatusCode == http.StatusFound && res.Header.Get("Location") == tc.target
		if followed != tc.follow {
			t.Errorf("client_id=%q target=%s: status %d location %q", tc.clientID, tc.target, res.StatusCode, res.Header.Get("Location"))
		}
	}
}
