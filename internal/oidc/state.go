package oidc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
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

// codeStore seals authorization codes with AES-GCM instead of storing them,
// so any instance can redeem a code issued by another (Vercel Functions run
// several instances and scale to zero). Codes live for a minute; redeemed
// codes are remembered per instance on a best-effort basis, and replaying one
// on another instance would still need the client secret and PKCE verifier.
type codeStore struct {
	aead     cipher.AEAD
	mu       sync.Mutex
	redeemed map[string]time.Time
}

func newCodeStore(secret []byte) *codeStore {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte("candy-rain-id authorization code"))
	block, err := aes.NewCipher(h.Sum(nil))
	if err != nil {
		panic(err) // a 32-byte key is always valid
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return &codeStore{aead: aead, redeemed: map[string]time.Time{}}
}

func (s *codeStore) Issue(c authCode) string {
	plaintext, err := json.Marshal(c)
	if err != nil {
		panic(err) // authCode always marshals
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return b64.EncodeToString(s.aead.Seal(nonce, nonce, plaintext, nil))
}

// Redeem opens the code and rejects it when expired or already redeemed here.
func (s *codeStore) Redeem(code string, now time.Time) (authCode, bool) {
	raw, err := b64.DecodeString(code)
	if err != nil || len(raw) < s.aead.NonceSize() {
		return authCode{}, false
	}
	plaintext, err := s.aead.Open(nil, raw[:s.aead.NonceSize()], raw[s.aead.NonceSize():], nil)
	if err != nil {
		return authCode{}, false
	}
	var c authCode
	if json.Unmarshal(plaintext, &c) != nil || now.After(c.ExpiresAt) {
		return authCode{}, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for k, exp := range s.redeemed {
		if now.After(exp) {
			delete(s.redeemed, k)
		}
	}
	if _, used := s.redeemed[code]; used {
		return authCode{}, false
	}
	s.redeemed[code] = c.ExpiresAt
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
	// PasswordTag is passwordTag of the password hash at sign-in. When the
	// password changes in candy-rain-store, the tag no longer matches and
	// every session of that user ends, including stolen cookies.
	PasswordTag string
}

func (c sessionCodec) mac(payload string) string {
	h := hmac.New(sha256.New, c.secret)
	h.Write([]byte(payload))
	return b64.EncodeToString(h.Sum(nil))
}

// passwordTag binds a session to a password hash without putting the hash
// in the cookie. It is base64url, so it never contains the "." separator.
func (c sessionCodec) passwordTag(passwordHash string) string {
	return c.mac("session-password\x00" + passwordHash)
}

func (c sessionCodec) Encode(s session) string {
	payload := strings.Join([]string{
		strconv.FormatInt(s.UserID, 10),
		strconv.FormatInt(s.AuthTime.Unix(), 10),
		strconv.FormatInt(s.ExpiresAt.Unix(), 10),
		s.PasswordTag,
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
	// Cookies from before PasswordTag existed have three parts and are
	// rejected, so those users sign in once more.
	parts := strings.Split(payload, ".")
	if len(parts) != 4 || parts[3] == "" {
		return session{}, false
	}
	var nums [3]int64
	for i, p := range parts[:3] {
		n, err := strconv.ParseInt(p, 10, 64)
		if err != nil {
			return session{}, false
		}
		nums[i] = n
	}
	s := session{
		UserID: nums[0], AuthTime: time.Unix(nums[1], 0), ExpiresAt: time.Unix(nums[2], 0),
		PasswordTag: parts[3],
	}
	if !now.Before(s.ExpiresAt) {
		return session{}, false
	}
	return s, true
}
