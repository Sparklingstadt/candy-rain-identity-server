package oidc

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Sparklingstadt/candy-rain-identity-server/internal/user"
)

// failLogin signs in with a wrong password and returns the status.
func (h *harness) failLogin(email string) int {
	h.t.Helper()
	_, challenge := pkcePair()
	res := h.login(authorizeQuery(challenge), email, "wrong-password")
	res.Body.Close()
	return res.StatusCode
}

func TestTooManyFailuresBlockTheAccount(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < maxEmailFailures; i++ {
		if got := h.failLogin("user1@mail.com"); got != http.StatusUnauthorized {
			t.Fatalf("failure %d: status %d", i+1, got)
		}
	}
	// Even the right password is refused now, and no code is issued.
	_, challenge := pkcePair()
	res := h.login(authorizeQuery(challenge), "User1@Mail.com", password)
	res.Body.Close()
	if res.StatusCode != http.StatusTooManyRequests || res.Header.Get("Location") != "" {
		t.Fatalf("blocked sign-in: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	// Another account from the same address is not affected.
	codeFrom(t, h.login(authorizeQuery(challenge), "user2@mail.com", password))
}

// newLimitHarness lowers the limits, so that tests which go through the
// cost-12 dummy hash stay fast.
func newLimitHarness(t *testing.T, email, ip int) *harness {
	t.Helper()
	avatars := user.NewMemoryAvatarStore()
	h := newHarnessWith(t, avatars, func(o *Options) {
		o.MaxEmailFailures, o.MaxIPFailures = email, ip
	})
	h.avatars = avatars
	return h
}

func TestDefaultLimits(t *testing.T) {
	h := newHarness(t)
	if h.srv.opts.MaxEmailFailures != maxEmailFailures || h.srv.opts.MaxIPFailures != maxIPFailures {
		t.Fatalf("limits %d / %d", h.srv.opts.MaxEmailFailures, h.srv.opts.MaxIPFailures)
	}
}

func TestUnknownEmailsAreLimitedLikeKnownOnes(t *testing.T) {
	h := newLimitHarness(t, 2, maxIPFailures)
	for i := 0; i < 2; i++ {
		h.failLogin("nobody@mail.com")
	}
	if got := h.failLogin("nobody@mail.com"); got != http.StatusTooManyRequests {
		t.Fatalf("an unknown email must be blocked the same way, got %d", got)
	}
}

func TestSuccessfulSignInResetsTheAccountCount(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < maxEmailFailures-1; i++ {
		h.failLogin("user1@mail.com")
	}
	_, challenge := pkcePair()
	codeFrom(t, h.login(authorizeQuery(challenge), "user1@mail.com", password))
	h.client.Jar.SetCookies(mustURL(h.issuer()), []*http.Cookie{{Name: sessionName, Value: "", MaxAge: -1}})
	for i := 0; i < maxEmailFailures-1; i++ {
		if got := h.failLogin("user1@mail.com"); got != http.StatusUnauthorized {
			t.Fatalf("failure %d after a success: status %d", i+1, got)
		}
	}
}

func TestTooManyFailuresBlockTheAddress(t *testing.T) {
	h := newLimitHarness(t, maxEmailFailures, 4)
	// Credential stuffing: guesses spread over several accounts.
	for i := 0; i < 4; i++ {
		h.failLogin([]string{"user1@mail.com", "user2@mail.com"}[i%2])
	}
	_, challenge := pkcePair()
	res := h.login(authorizeQuery(challenge), "user1@mail.com", password)
	res.Body.Close()
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("the address should be blocked, got %d", res.StatusCode)
	}
}

func TestLimitStoreFailureDoesNotStopSignIn(t *testing.T) {
	h := newHarness(t)
	h.failures.Err = errors.New("relation idp.login_failure does not exist")
	_, challenge := pkcePair()
	codeFrom(t, h.login(authorizeQuery(challenge), "user1@mail.com", password))
}

func TestClientIP(t *testing.T) {
	cases := []struct {
		header, value, remote, want string
	}{
		{"", "", "203.0.113.7:51234", "203.0.113.7"},
		{"", "", "[2001:db8::1]:443", "2001:db8::1"},
		// Without a configured header, a client-sent one is ignored.
		{"", "198.51.100.1", "203.0.113.7:51234", "203.0.113.7"},
		{"X-Real-IP", "198.51.100.1", "10.0.0.1:1", "198.51.100.1"},
		{"X-Forwarded-For", "198.51.100.1, 10.0.0.2", "10.0.0.1:1", "198.51.100.1"},
		// Anything that is not an IP gives no address key at all.
		{"X-Real-IP", "not-an-ip", "10.0.0.1:1", ""},
		{"X-Real-IP", "", "10.0.0.1:1", ""},
	}
	for _, c := range cases {
		s := &Server{opts: Options{ClientIPHeader: c.header}}
		r := httptest.NewRequest(http.MethodPost, "/authorize", nil)
		r.RemoteAddr = c.remote
		if c.value != "" {
			r.Header.Set("X-Real-IP", c.value)
			r.Header.Set("X-Forwarded-For", c.value)
		}
		if got := s.clientIP(r); got != c.want {
			t.Errorf("header %q value %q remote %q: got %q, want %q", c.header, c.value, c.remote, got, c.want)
		}
	}
}
