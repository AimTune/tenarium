package oktadir

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// assertionSource obtains access tokens with the client credentials grant,
// authenticating with a signed JWT (private_key_jwt), as Okta requires for
// API service apps.
type assertionSource struct {
	tokenURL string
	clientID string
	keyID    string
	key      crypto.Signer
	alg      string
	scopes   string
	client   *http.Client
	now      func() time.Time
}

func (s *assertionSource) Token() (*oauth2.Token, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.client.Timeout)
	defer cancel()
	assertion, err := s.assertion()
	if err != nil {
		return nil, err
	}
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"scope":                 {s.scopes},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("okta: token: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, apiError("token", resp.StatusCode, body)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
		return nil, errors.New("okta: token: response has no access_token")
	}
	if !strings.EqualFold(tr.TokenType, "Bearer") {
		return nil, fmt.Errorf("okta: token: unsupported token type %q (disable DPoP for the service app)", tr.TokenType)
	}
	ttl := time.Duration(tr.ExpiresIn) * time.Second
	ttl -= min(30*time.Second, ttl/2)
	return &oauth2.Token{AccessToken: tr.AccessToken, TokenType: "Bearer", Expiry: s.now().Add(ttl)}, nil
}

// assertion returns a fresh client assertion JWT.
func (s *assertionSource) assertion() (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	now := s.now()
	header := map[string]string{"alg": s.alg, "typ": "JWT"}
	if s.keyID != "" {
		header["kid"] = s.keyID
	}
	claims := map[string]any{
		"iss": s.clientID, "sub": s.clientID, "aud": s.tokenURL,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "jti": hex.EncodeToString(jti),
	}
	return signJWT(s.key, s.alg, header, claims)
}

func signJWT(key crypto.Signer, alg string, header map[string]string, claims map[string]any) (string, error) {
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(h) + "." + enc.EncodeToString(c)
	var hashed []byte
	var hash crypto.Hash
	switch alg {
	case "RS256", "ES256":
		sum := sha256.Sum256([]byte(input))
		hashed, hash = sum[:], crypto.SHA256
	case "ES384":
		sum := sha512.Sum384([]byte(input))
		hashed, hash = sum[:], crypto.SHA384
	case "ES512":
		sum := sha512.Sum512([]byte(input))
		hashed, hash = sum[:], crypto.SHA512
	default:
		return "", fmt.Errorf("unsupported algorithm %s", alg)
	}
	var sig []byte
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if sig, err = rsa.SignPKCS1v15(rand.Reader, k, hash, hashed); err != nil {
			return "", err
		}
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, k, hashed)
		if err != nil {
			return "", err
		}
		size := (k.Curve.Params().BitSize + 7) / 8
		sig = append(fixed(r, size), fixed(s, size)...)
	default:
		return "", fmt.Errorf("unsupported key type %T", key)
	}
	return input + "." + enc.EncodeToString(sig), nil
}

func fixed(n *big.Int, size int) []byte {
	b := make([]byte, size)
	return n.FillBytes(b)
}

// parsePrivateKey parses a PEM RSA (PKCS#1 or PKCS#8) or EC (SEC 1 or
// PKCS#8) private key and returns it with its JWS algorithm.
func parsePrivateKey(data []byte) (crypto.Signer, string, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, "", errors.New("no PEM block found")
	}
	var key any
	var err error
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, "", fmt.Errorf("unsupported PEM block %q", block.Type)
	}
	if err != nil {
		return nil, "", err
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if k.N.BitLen() < 2048 {
			return nil, "", errors.New("RSA keys must have at least 2048 bits")
		}
		return k, "RS256", nil
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			return k, "ES256", nil
		case elliptic.P384():
			return k, "ES384", nil
		case elliptic.P521():
			return k, "ES512", nil
		}
		return nil, "", errors.New("unsupported EC curve")
	}
	return nil, "", fmt.Errorf("unsupported key type %T", key)
}
