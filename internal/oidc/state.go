package oidc

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"strconv"
	"strings"
	"sync"
	"time"
)

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return b64.EncodeToString(b)
}

// authCode is what the token endpoint needs to finish the flow.
type authCode struct {
	ClientID      string
	RedirectURI   string
	UserID        int64
	Nonce         string
	CodeChallenge string
	Scope         string
	AuthTime      time.Time
	ExpiresAt     time.Time
}

// codeStore keeps authorization codes in memory. Codes live for a minute and
// can be redeemed once, so running a single instance is enough for this demo;
// several instances would need a shared store such as Redis or PostgreSQL.
type codeStore struct {
	mu    sync.Mutex
	codes map[string]authCode
}

func newCodeStore() *codeStore {
	return &codeStore{codes: map[string]authCode{}}
}

func (s *codeStore) Issue(c authCode) string {
	code := randomToken()
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.codes {
		if now.After(v.ExpiresAt) {
			delete(s.codes, k)
		}
	}
	s.codes[code] = c
	return code
}

// Redeem returns the code's data and deletes it, so a code works only once.
func (s *codeStore) Redeem(code string, now time.Time) (authCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[code]
	delete(s.codes, code)
	if !ok || now.After(c.ExpiresAt) {
		return authCode{}, false
	}
	return c, true
}

// sessionCodec signs the identity server's own sign-in cookie, which lets a
// user who already signed in skip the password form (single sign-on).
type sessionCodec struct {
	secret []byte
}

type session struct {
	UserID    int64
	AuthTime  time.Time
	ExpiresAt time.Time
}

func (c sessionCodec) mac(payload string) string {
	h := hmac.New(sha256.New, c.secret)
	h.Write([]byte(payload))
	return b64.EncodeToString(h.Sum(nil))
}

func (c sessionCodec) Encode(s session) string {
	payload := strings.Join([]string{
		strconv.FormatInt(s.UserID, 10),
		strconv.FormatInt(s.AuthTime.Unix(), 10),
		strconv.FormatInt(s.ExpiresAt.Unix(), 10),
	}, ".")
	return payload + "." + c.mac(payload)
}

func (c sessionCodec) Decode(value string, now time.Time) (session, bool) {
	i := strings.LastIndexByte(value, '.')
	if i < 0 {
		return session{}, false
	}
	payload, sig := value[:i], value[i+1:]
	if !hmac.Equal([]byte(sig), []byte(c.mac(payload))) {
		return session{}, false
	}
	parts := strings.Split(payload, ".")
	if len(parts) != 3 {
		return session{}, false
	}
	var nums [3]int64
	for i, p := range parts {
		n, err := strconv.ParseInt(p, 10, 64)
		if err != nil {
			return session{}, false
		}
		nums[i] = n
	}
	s := session{UserID: nums[0], AuthTime: time.Unix(nums[1], 0), ExpiresAt: time.Unix(nums[2], 0)}
	if !now.Before(s.ExpiresAt) {
		return session{}, false
	}
	return s, true
}
