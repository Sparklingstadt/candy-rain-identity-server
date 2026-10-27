package oidc

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	// loginWindow is how long failures are counted from the first one.
	loginWindow = 15 * time.Minute
	// maxEmailFailures stops guessing the password of one account. Unknown
	// emails are counted too, so the limit does not reveal which exist.
	maxEmailFailures = 10
	// maxIPFailures stops one address from trying many accounts (credential
	// stuffing). It is higher because people share addresses (NAT).
	maxIPFailures = 50
)

// loginKey is one counter of failed sign-ins and its limit.
type loginKey struct {
	key   string
	limit int
}

// loginKeys returns the counters a sign-in attempt is checked against: the
// submitted email and the client's address.
func (s *Server) loginKeys(r *http.Request, email string) []loginKey {
	var keys []loginKey
	if email != "" {
		keys = append(keys, loginKey{"email:" + strings.ToLower(email), s.opts.MaxEmailFailures})
	}
	if ip := s.clientIP(r); ip != "" {
		keys = append(keys, loginKey{"ip:" + ip, s.opts.MaxIPFailures})
	}
	return keys
}

// clientIP returns the client's address from ClientIPHeader when set (the
// proxy in front, such as Vercel, overwrites it), or the TCP peer otherwise.
// Only a parseable IP is returned, so a header cannot fill the table with
// arbitrary keys.
func (s *Server) clientIP(r *http.Request) string {
	raw := r.RemoteAddr
	if s.opts.ClientIPHeader != "" {
		raw, _, _ = strings.Cut(r.Header.Get(s.opts.ClientIPHeader), ",")
	} else if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return ""
	}
	return ip.String()
}

// loginBlocked reports whether any counter reached its limit. A failing
// store is logged and lets the attempt through: before the migration is
// applied, or while the table is unavailable, sign-in keeps working.
func (s *Server) loginBlocked(ctx context.Context, keys []loginKey) bool {
	now := s.opts.Now()
	for _, k := range keys {
		n, err := s.opts.LoginFailures.Failures(ctx, k.key, now)
		if err != nil {
			s.opts.Logger.Error("login limit check failed; attempt allowed", "err", err)
			return false
		}
		if n >= k.limit {
			kind, _, _ := strings.Cut(k.key, ":")
			s.opts.Logger.Warn("sign-in blocked: too many failures", "by", kind)
			return true
		}
	}
	return false
}

func (s *Server) recordLoginFailure(ctx context.Context, keys []loginKey) {
	now := s.opts.Now()
	for _, k := range keys {
		if err := s.opts.LoginFailures.Fail(ctx, k.key, now, loginWindow); err != nil {
			s.opts.Logger.Error("login failure not recorded", "err", err)
		}
	}
}

// resetLoginFailures forgets the email's failures after a successful
// sign-in. The address keeps its count, so an attacker cannot clear it by
// signing in to an account of their own between guesses.
func (s *Server) resetLoginFailures(ctx context.Context, keys []loginKey) {
	for _, k := range keys {
		if !strings.HasPrefix(k.key, "email:") {
			continue
		}
		if err := s.opts.LoginFailures.Reset(ctx, k.key); err != nil {
			s.opts.Logger.Error("login failures not reset", "err", err)
		}
	}
}
