package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
)

// Claims are the claims of a Tenarium access token.
type Claims struct {
	jwt.Claims
	Email    string   `json:"email,omitempty"`
	Name     string   `json:"name,omitempty"`
	TenantID string   `json:"tid,omitempty"`
	Roles    []string `json:"roles,omitempty"`
	// Region is the tenant's region, for routing at the edge without a
	// lookup (tenant tokens only).
	Region string `json:"region,omitempty"`
	// Act names the impersonating caller (RFC 8693 "act" claim).
	Act *Actor `json:"act,omitempty"`
}

// Issuer signs and verifies Tenarium access tokens (ES256). Signing keys
// are kept in the store so every replica signs and verifies with the same
// keys; the newest key signs, all keys verify.
type Issuer struct {
	store    store.Store
	issuer   string
	audience string
	ttl      time.Duration
	now      func() time.Time
	provider bool

	mu       sync.RWMutex
	keys     []*jose.JSONWebKey // newest last
	created  []time.Time        // CreatedAt of keys[i]
	loadedAt time.Time
}

func NewIssuer(s store.Store, issuer, audience string, accessTTL time.Duration) *Issuer {
	return &Issuer{store: s, issuer: strings.TrimRight(issuer, "/"), audience: audience, ttl: accessTTL, now: time.Now}
}

func (i *Issuer) Issuer() string           { return i.issuer }
func (i *Issuer) AccessTTL() time.Duration { return i.ttl }

// Init loads the signing keys, creating the first one if there is none.
// Concurrent replicas may race to create it; the loser reloads.
func (i *Issuer) Init(ctx context.Context) error {
	if err := i.load(ctx); err != nil {
		return err
	}
	i.mu.RLock()
	n := len(i.keys)
	i.mu.RUnlock()
	if n > 0 {
		return nil
	}
	if err := i.Rotate(ctx); err != nil && !errors.Is(err, store.ErrAlreadyExists) {
		return err
	}
	return i.load(ctx)
}

// Rotate adds a new signing key. Existing keys keep verifying tokens.
func (i *Issuer) Rotate(ctx context.Context) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	k := store.SigningKey{
		ID:         uuid.Must(uuid.NewV7()).String(),
		Algorithm:  string(jose.ES256),
		PrivatePEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		CreatedAt:  i.now().UTC(),
	}
	if err := i.store.AddSigningKey(ctx, k); err != nil {
		return err
	}
	return i.load(ctx)
}

func (i *Issuer) load(ctx context.Context) error {
	stored, err := i.store.ListSigningKeys(ctx)
	if err != nil {
		return err
	}
	keys := make([]*jose.JSONWebKey, 0, len(stored))
	created := make([]time.Time, 0, len(stored))
	for _, k := range stored {
		block, _ := pem.Decode(k.PrivatePEM)
		if block == nil {
			return fmt.Errorf("signing key %s: invalid PEM", k.ID)
		}
		priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("signing key %s: %w", k.ID, err)
		}
		keys = append(keys, &jose.JSONWebKey{Key: priv, KeyID: k.ID, Algorithm: k.Algorithm, Use: "sig"})
		created = append(created, k.CreatedAt)
	}
	i.mu.Lock()
	i.keys, i.created, i.loadedAt = keys, created, i.now()
	i.mu.Unlock()
	return nil
}

// Sign issues an access token for subject.
func (i *Issuer) Sign(subject, email, name, tenantID string, roles []string) (string, time.Time, error) {
	return i.sign(Claims{Email: email, Name: name, TenantID: tenantID, Roles: roles}, subject, i.ttl)
}

// SignAccess issues an access token with the given claims (registered
// claims are set by the issuer); ttl 0 uses the configured access TTL.
func (i *Issuer) SignAccess(subject string, c Claims, ttl time.Duration) (string, time.Time, error) {
	if ttl <= 0 {
		ttl = i.ttl
	}
	return i.sign(c, subject, ttl)
}

func (i *Issuer) sign(c Claims, subject string, ttl time.Duration) (string, time.Time, error) {
	i.mu.RLock()
	if len(i.keys) == 0 {
		i.mu.RUnlock()
		return "", time.Time{}, errors.New("no signing key")
	}
	key := i.keys[len(i.keys)-1]
	i.mu.RUnlock()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("at+jwt").WithHeader(jose.HeaderKey("kid"), key.KeyID))
	if err != nil {
		return "", time.Time{}, err
	}
	now := i.now().UTC()
	exp := now.Add(ttl)
	c.Claims = jwt.Claims{
		Issuer: i.issuer, Subject: subject, Audience: jwt.Audience{i.audience},
		IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(exp),
		ID: uuid.NewString(),
	}
	tok, err := jwt.Signed(signer).Claims(c).Serialize()
	return tok, exp, err
}

// ErrForeignToken means the token was not issued by this Tenarium, so
// another authenticator may handle it.
var ErrForeignToken = errors.New("not a tenarium token")

// Verify checks a token's signature, issuer, audience and lifetime.
func (i *Issuer) Verify(raw string) (Claims, error) {
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return Claims{}, ErrForeignToken
	}
	var unverified Claims
	if err := tok.UnsafeClaimsWithoutVerification(&unverified); err != nil || unverified.Issuer != i.issuer {
		return Claims{}, ErrForeignToken
	}
	if len(tok.Headers) != 1 {
		return Claims{}, errors.New("unexpected token headers")
	}
	kid := tok.Headers[0].KeyID
	pub := i.publicKey(kid)
	if pub == nil && i.reloadAllowed() {
		// Another replica may have rotated since we loaded.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = i.load(ctx)
		cancel()
		pub = i.publicKey(kid)
	}
	if pub == nil {
		return Claims{}, fmt.Errorf("unknown signing key %q", kid)
	}
	var c Claims
	if err := tok.Claims(pub, &c); err != nil {
		return Claims{}, fmt.Errorf("invalid token signature: %w", err)
	}
	if err := c.ValidateWithLeeway(jwt.Expected{Issuer: i.issuer, AnyAudience: jwt.Audience{i.audience}, Time: i.now()}, 30*time.Second); err != nil {
		return Claims{}, fmt.Errorf("invalid token: %w", err)
	}
	return c, nil
}

// JWKS returns the public keys as a JSON Web Key Set.
func (i *Issuer) JWKS() []byte {
	i.mu.RLock()
	defer i.mu.RUnlock()
	set := jose.JSONWebKeySet{}
	for _, k := range i.keys {
		set.Keys = append(set.Keys, k.Public())
	}
	b, _ := json.Marshal(set)
	return b
}

// Discovery returns a minimal OpenID Provider configuration so standard
// libraries can verify Tenarium tokens.
func (i *Issuer) Discovery() []byte {
	d := map[string]any{
		"issuer":                                i.issuer,
		"jwks_uri":                              i.issuer + "/.well-known/jwks.json",
		"token_endpoint":                        i.issuer + "/v1/auth/token",
		"grant_types_supported":                 []string{"password", "refresh_token"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"subject_types_supported":               []string{"public"},
		"response_types_supported":              []string{"token"},
	}
	if i.provider {
		// Tenarium is a full OpenID provider (internal/oidcprovider).
		d["authorization_endpoint"] = i.issuer + "/oauth/authorize"
		d["token_endpoint"] = i.issuer + "/oauth/token"
		d["userinfo_endpoint"] = i.issuer + "/oauth/userinfo"
		d["end_session_endpoint"] = i.issuer + "/oauth/logout"
		d["grant_types_supported"] = []string{"authorization_code", "refresh_token"}
		d["response_types_supported"] = []string{"code"}
		d["response_modes_supported"] = []string{"query"}
		d["scopes_supported"] = []string{"openid", "profile", "email", "offline_access"}
		d["code_challenge_methods_supported"] = []string{"S256"}
		d["token_endpoint_auth_methods_supported"] = []string{"client_secret_basic", "client_secret_post", "none"}
		d["claims_supported"] = []string{"sub", "email", "email_verified", "name", "tid", "auth_time", "nonce"}
		d["authorization_response_iss_parameter_supported"] = true
	}
	b, _ := json.Marshal(d)
	return b
}

// EnableProvider advertises the OpenID provider endpoints in discovery.
func (i *Issuer) EnableProvider() { i.provider = true }

func (i *Issuer) publicKey(kid string) any {
	i.mu.RLock()
	defer i.mu.RUnlock()
	idx := slices.IndexFunc(i.keys, func(k *jose.JSONWebKey) bool { return k.KeyID == kid })
	if idx < 0 {
		return nil
	}
	return i.keys[idx].Public().Key
}

// reloadAllowed rate-limits reloads triggered by unknown key IDs, so forged
// tokens cannot hammer the store.
func (i *Issuer) reloadAllowed() bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.now().Sub(i.loadedAt) > 10*time.Second
}

// KeyInfo describes a signing key without its private part.
type KeyInfo struct {
	ID        string    `json:"kid"`
	Algorithm string    `json:"alg"`
	CreatedAt time.Time `json:"created_at"`
	// Active marks the key new tokens are signed with.
	Active bool `json:"active"`
}

// Keys lists the signing keys, oldest first.
func (i *Issuer) Keys(ctx context.Context) ([]KeyInfo, error) {
	if err := i.load(ctx); err != nil {
		return nil, err
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := make([]KeyInfo, len(i.keys))
	for n, k := range i.keys {
		out[n] = KeyInfo{ID: k.KeyID, Algorithm: k.Algorithm, CreatedAt: i.created[n].UTC(), Active: n == len(i.keys)-1}
	}
	return out, nil
}

// ErrActiveKey is returned when retiring the key that signs new tokens.
var ErrActiveKey = errors.New("cannot retire the active signing key; rotate first")

// Retire deletes a signing key; tokens it signed stop verifying at once
// (on other replicas after their next reload). Use it after a key leaked.
func (i *Issuer) Retire(ctx context.Context, kid string) error {
	keys, err := i.Keys(ctx)
	if err != nil {
		return err
	}
	idx := slices.IndexFunc(keys, func(k KeyInfo) bool { return k.ID == kid })
	switch {
	case idx < 0:
		return store.ErrNotFound
	case keys[idx].Active:
		return ErrActiveKey
	}
	if err := i.store.DeleteSigningKey(ctx, kid); err != nil {
		return err
	}
	return i.load(ctx)
}

// retireMargin is how long after its successor appeared a key is kept
// beyond the access token lifetime: covers clock skew and replicas that
// have not reloaded yet.
const retireMargin = 5 * time.Minute

// Maintain reloads the keys (picking up rotations by other replicas),
// rotates when the active key is older than rotateEvery (0: never), and
// retires keys that can no longer have valid tokens. Run it periodically,
// well under retireMargin apart.
func (i *Issuer) Maintain(ctx context.Context, rotateEvery time.Duration) error {
	keys, err := i.Keys(ctx)
	if err != nil {
		return err
	}
	now := i.now()
	if n := len(keys); n > 0 && rotateEvery > 0 && now.Sub(keys[n-1].CreatedAt) >= rotateEvery {
		if err := i.Rotate(ctx); err != nil {
			return err
		}
		return nil // retire on the next run, after replicas switched keys
	}
	for n := 0; n+1 < len(keys); n++ {
		// Tokens of key n were signed before its successor existed, plus
		// what lagging replicas signed until they reloaded.
		if now.Sub(keys[n+1].CreatedAt) > i.ttl+retireMargin {
			if err := i.store.DeleteSigningKey(ctx, keys[n].ID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
	}
	return i.load(ctx)
}

// SignClaims signs extra claims for internal use (e.g. SSO state) under a
// dedicated audience, so they can never pass as access tokens.
func (i *Issuer) SignClaims(audience string, ttl time.Duration, extra any) (string, error) {
	i.mu.RLock()
	if len(i.keys) == 0 {
		i.mu.RUnlock()
		return "", errors.New("no signing key")
	}
	key := i.keys[len(i.keys)-1]
	i.mu.RUnlock()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), key.KeyID))
	if err != nil {
		return "", err
	}
	now := i.now().UTC()
	std := jwt.Claims{Issuer: i.issuer, Audience: jwt.Audience{audience}, IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(ttl))}
	return jwt.Signed(signer).Claims(std).Claims(extra).Serialize()
}

// VerifyClaims checks a token from SignClaims and decodes its extra
// claims into out.
func (i *Issuer) VerifyClaims(raw, audience string, out any) error {
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil || len(tok.Headers) != 1 {
		return errors.New("malformed token")
	}
	pub := i.publicKey(tok.Headers[0].KeyID)
	if pub == nil {
		return errors.New("unknown signing key")
	}
	var std jwt.Claims
	if err := tok.Claims(pub, &std, out); err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}
	return std.ValidateWithLeeway(jwt.Expected{Issuer: i.issuer, AnyAudience: jwt.Audience{audience}, Time: i.now()}, 30*time.Second)
}

// Actor is the party acting on behalf of the token's subject.
type Actor struct {
	Subject string `json:"sub"`
}
