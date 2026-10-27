// Package config loads the identity server settings from environment variables.
package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
)

type Client struct {
	ID                     string   `json:"id"`
	Secret                 string   `json:"secret"`
	RedirectURIs           []string `json:"redirect_uris"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
}

type Config struct {
	Addr          string
	Issuer        string
	DatabaseURL   string
	SigningKey    *rsa.PrivateKey
	SessionSecret []byte
	Clients       []Client
	// LoginHint is shown under the login form, e.g. the demo account.
	LoginHint string
	// ClientIPHeader is the header with the client's IP, set by the proxy
	// in front. Vercel overwrites X-Real-IP, so it is the default there.
	// Elsewhere it is empty (the TCP peer) unless CLIENT_IP_HEADER is set.
	ClientIPHeader string
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
	clients, err := loadClients()
	if err != nil {
		errs = append(errs, err)
	}
	cfg.Clients = clients

	cfg.ClientIPHeader = clientIPHeader()

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

// loadClients reads the clients from OIDC_CLIENTS (a JSON array) and from
// the single-client OIDC_CLIENT_ID / OIDC_CLIENT_SECRET / OIDC_REDIRECT_URIS /
// OIDC_POST_LOGOUT_REDIRECT_URIS variables. Both may be set; the single
// client is registered alongside the ones in OIDC_CLIENTS.
func loadClients() ([]Client, error) {
	var clients []Client
	if raw := strings.TrimSpace(os.Getenv("OIDC_CLIENTS")); raw != "" {
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&clients); err != nil {
			return nil, fmt.Errorf("OIDC_CLIENTS must be a JSON array of clients: %w", err)
		}
	}
	single := Client{
		ID:                     os.Getenv("OIDC_CLIENT_ID"),
		Secret:                 os.Getenv("OIDC_CLIENT_SECRET"),
		RedirectURIs:           splitList(os.Getenv("OIDC_REDIRECT_URIS")),
		PostLogoutRedirectURIs: splitList(os.Getenv("OIDC_POST_LOGOUT_REDIRECT_URIS")),
	}
	if single.ID != "" || single.Secret != "" || len(single.RedirectURIs) > 0 {
		clients = append(clients, single)
	}
	return clients, ValidateClients(clients)
}

// ValidateClients checks that every client can complete the flow and that
// client IDs are unique.
func ValidateClients(clients []Client) error {
	if len(clients) == 0 {
		return errors.New("register at least one client with OIDC_CLIENTS or OIDC_CLIENT_ID")
	}
	var errs []error
	seen := map[string]bool{}
	for i, c := range clients {
		name := c.ID
		if name == "" {
			name = fmt.Sprintf("#%d", i+1)
		}
		if c.ID == "" || c.Secret == "" {
			errs = append(errs, fmt.Errorf("client %s: id and secret are required", name))
		}
		if len(c.RedirectURIs) == 0 {
			errs = append(errs, fmt.Errorf("client %s: at least one redirect URI is required", name))
		}
		if c.ID != "" && seen[c.ID] {
			errs = append(errs, fmt.Errorf("client %s is registered more than once", c.ID))
		}
		seen[c.ID] = true
	}
	return errors.Join(errs...)
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

// clientIPHeader returns CLIENT_IP_HEADER, or X-Real-IP on Vercel, which
// overwrites that header with the client's address so it cannot be spoofed.
func clientIPHeader() string {
	if h := os.Getenv("CLIENT_IP_HEADER"); h != "" {
		return h
	}
	if os.Getenv("VERCEL") != "" {
		return "X-Real-IP"
	}
	return ""
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
