// Package config loads the identity server settings from environment variables.
package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
)

type Client struct {
	ID                     string
	Secret                 string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
}

type Config struct {
	Addr          string
	Issuer        string
	DatabaseURL   string
	SigningKey    *rsa.PrivateKey
	SessionSecret []byte
	Client        Client
	// LoginHint is shown under the login form, e.g. the demo account.
	LoginHint string
}

// Load reads the environment. Missing secrets are generated for local
// development and logged as warnings; set them explicitly in production
// so that tokens and sessions survive restarts.
func Load(logger *slog.Logger) (Config, error) {
	cfg := Config{
		Addr:        envOr("ADDR", ":"+envOr("PORT", "8080")),
		Issuer:      strings.TrimRight(os.Getenv("ISSUER"), "/"),
		DatabaseURL: os.Getenv("DATABASE_URL"),
		LoginHint:   os.Getenv("LOGIN_HINT"),
		Client: Client{
			ID:                     os.Getenv("OIDC_CLIENT_ID"),
			Secret:                 os.Getenv("OIDC_CLIENT_SECRET"),
			RedirectURIs:           splitList(os.Getenv("OIDC_REDIRECT_URIS")),
			PostLogoutRedirectURIs: splitList(os.Getenv("OIDC_POST_LOGOUT_REDIRECT_URIS")),
		},
	}

	var errs []error
	if cfg.Issuer == "" {
		errs = append(errs, errors.New("ISSUER is required"))
	} else if u, err := url.Parse(cfg.Issuer); err != nil || u.Scheme == "" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		errs = append(errs, errors.New("ISSUER must be an absolute URL without query or fragment"))
	}
	if cfg.DatabaseURL == "" {
		errs = append(errs, errors.New("DATABASE_URL is required"))
	}
	if cfg.Client.ID == "" || cfg.Client.Secret == "" {
		errs = append(errs, errors.New("OIDC_CLIENT_ID and OIDC_CLIENT_SECRET are required"))
	}
	if len(cfg.Client.RedirectURIs) == 0 {
		errs = append(errs, errors.New("OIDC_REDIRECT_URIS is required"))
	}

	// On Vercel every instance would generate its own key and secret, so
	// tokens, codes and sessions issued by one would fail on another.
	if os.Getenv("VERCEL") != "" && (os.Getenv("SIGNING_KEY_PEM") == "" || os.Getenv("SESSION_SECRET") == "") {
		errs = append(errs, errors.New("SIGNING_KEY_PEM and SESSION_SECRET are required on Vercel"))
	}

	if pemText := os.Getenv("SIGNING_KEY_PEM"); pemText != "" {
		key, err := ParseRSAPrivateKey([]byte(pemText))
		if err != nil {
			errs = append(errs, fmt.Errorf("SIGNING_KEY_PEM: %w", err))
		}
		cfg.SigningKey = key
	} else {
		logger.Warn("SIGNING_KEY_PEM is not set; using a temporary key, so issued tokens become invalid on restart")
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return Config{}, err
		}
		cfg.SigningKey = key
	}

	if secret := os.Getenv("SESSION_SECRET"); secret != "" {
		if len(secret) < 32 {
			errs = append(errs, errors.New("SESSION_SECRET must be at least 32 characters"))
		}
		cfg.SessionSecret = []byte(secret)
	} else {
		logger.Warn("SESSION_SECRET is not set; using a temporary secret, so sign-in sessions end on restart")
		cfg.SessionSecret = make([]byte, 32)
		if _, err := rand.Read(cfg.SessionSecret); err != nil {
			return Config{}, err
		}
	}

	return cfg, errors.Join(errs...)
}

// ParseRSAPrivateKey accepts PKCS#1 ("RSA PRIVATE KEY") and PKCS#8 ("PRIVATE KEY") PEM.
func ParseRSAPrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("key is not RSA")
	}
	return key, nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
