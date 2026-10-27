package oidc

import (
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
