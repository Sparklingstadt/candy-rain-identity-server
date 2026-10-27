package oidc

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"time"
)

var b64 = base64.RawURLEncoding

// Signer issues RS256 JWTs and publishes the matching JWKS.
type Signer struct {
	key *rsa.PrivateKey
	kid string
}

func NewSigner(key *rsa.PrivateKey) *Signer {
	return &Signer{key: key, kid: thumbprint(&key.PublicKey)}
}

type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func publicJWK(pub *rsa.PublicKey) jwk {
	return jwk{
		Kty: "RSA",
		N:   b64.EncodeToString(pub.N.Bytes()),
		E:   b64.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// thumbprint is the RFC 7638 JWK thumbprint, used as the key ID.
func thumbprint(pub *rsa.PublicKey) string {
	k := publicJWK(pub)
	// Members in lexicographic order, no whitespace, as RFC 7638 requires.
	canonical := `{"e":"` + k.E + `","kty":"RSA","n":"` + k.N + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return b64.EncodeToString(sum[:])
}

func (s *Signer) JWKS() map[string]any {
	k := publicJWK(&s.key.PublicKey)
	k.Use, k.Alg, k.Kid = "sig", "RS256", s.kid
	return map[string]any{"keys": []jwk{k}}
}

func (s *Signer) Sign(claims map[string]any, typ string) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": s.kid, "typ": typ})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64.EncodeToString(header) + "." + b64.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(nil, s.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64.EncodeToString(sig), nil
}

var errInvalidToken = errors.New("invalid token")

// Verify checks the signature, type and expiry of a token issued by this signer
// and returns its claims.
func (s *Signer) Verify(token, typ string, now time.Time) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errInvalidToken
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := decodeSegment(parts[0], &header); err != nil {
		return nil, errInvalidToken
	}
	if header.Alg != "RS256" || header.Kid != s.kid || header.Typ != typ {
		return nil, errInvalidToken
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, errInvalidToken
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(&s.key.PublicKey, crypto.SHA256, digest[:], sig) != nil {
		return nil, errInvalidToken
	}
	var claims map[string]any
	if err := decodeSegment(parts[1], &claims); err != nil {
		return nil, errInvalidToken
	}
	exp, ok := claims["exp"].(float64)
	if !ok || now.Unix() >= int64(exp) {
		return nil, errInvalidToken
	}
	return claims, nil
}

func decodeSegment(seg string, v any) error {
	raw, err := b64.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}
