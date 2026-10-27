package oidc

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCodeRedeemsOnAnotherInstanceOnce(t *testing.T) {
	secret := []byte(strings.Repeat("s", 32))
	now := time.Now()
	code := newCodeStore(secret).Issue(authCode{ClientID: "c", UserID: 7, ExpiresAt: now.Add(codeTTL)})

	other := newCodeStore(secret)
	c, ok := other.Redeem(code, now)
	if !ok || c.UserID != 7 || c.ClientID != "c" {
		t.Fatalf("redeem on another instance: %v %v", ok, c)
	}
	if _, ok := other.Redeem(code, now); ok {
		t.Fatal("a code must not be redeemed twice on the same instance")
	}
}

func TestCodeRejectsTamperingExpiryAndOtherSecrets(t *testing.T) {
	secret := []byte(strings.Repeat("s", 32))
	now := time.Now()
	store := newCodeStore(secret)
	code := store.Issue(authCode{UserID: 7, ExpiresAt: now.Add(codeTTL)})

	if _, ok := newCodeStore([]byte(strings.Repeat("x", 32))).Redeem(code, now); ok {
		t.Error("a code sealed with another secret must be rejected")
	}
	tampered := code[:len(code)-2] + "AA"
	if tampered == code {
		tampered = code[:len(code)-2] + "BB"
	}
	if _, ok := store.Redeem(tampered, now); ok {
		t.Error("a tampered code must be rejected")
	}
	if _, ok := store.Redeem(code, now.Add(2*codeTTL)); ok {
		t.Error("an expired code must be rejected")
	}
	if _, ok := store.Redeem("not-a-code", now); ok {
		t.Error("garbage must be rejected")
	}
}

func TestSessionKeepsPasswordTagAndRejectsOldCookies(t *testing.T) {
	c := sessionCodec{secret: []byte(strings.Repeat("s", 32))}
	now := time.Now()
	tag := c.passwordTag("$2a$12$hash")
	s, ok := c.Decode(c.Encode(session{UserID: 7, AuthTime: now, ExpiresAt: now.Add(time.Hour), PasswordTag: tag}), now)
	if !ok || s.UserID != 7 || s.PasswordTag != tag {
		t.Fatalf("round trip: %v %v", ok, s)
	}
	if c.passwordTag("$2a$12$other") == tag {
		t.Fatal("different hashes must give different tags")
	}

	// A correctly signed cookie in the format without PasswordTag.
	payload := "7." + strconv.FormatInt(now.Unix(), 10) + "." + strconv.FormatInt(now.Add(time.Hour).Unix(), 10)
	if _, ok := c.Decode(payload+"."+c.mac(payload), now); ok {
		t.Fatal("a cookie without a password tag must be rejected")
	}
}
