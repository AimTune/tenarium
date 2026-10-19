package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	dekSize   = 32 // AES-256
	nonceSize = 12 // GCM standard nonce
	tagSize   = 16

	// DefaultDEKTTL is how long one data key is used for new encryptions.
	DefaultDEKTTL = time.Hour
	// DefaultDEKMaxUses caps encryptions per data key. Random 96-bit GCM
	// nonces stay far below the 2^-32 collision bound recommended by NIST
	// SP 800-38D (2^32 messages per key) at this limit.
	DefaultDEKMaxUses = 1 << 24
	// DefaultDecryptCacheSize bounds the number of unwrapped data keys kept
	// in memory for decryption.
	DefaultDecryptCacheSize = 1024
)

// EnvelopeOptions tune an Envelope keyring. Zero values select defaults.
type EnvelopeOptions struct {
	DEKTTL           time.Duration
	DEKMaxUses       uint64
	DecryptCacheSize int
	// RejectPlaintext makes Decrypt fail with ErrPlaintextRejected for
	// values that are not encrypted, instead of passing them through.
	RejectPlaintext bool
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Envelope is a Keyring using envelope encryption: values are sealed with
// AES-256-GCM under a random 256-bit data key (DEK), and the DEK is wrapped
// by a KeyProvider. New values are written with the primary provider; any of
// the configured providers can decrypt (for migrations between providers).
//
// DEK lifecycle: one DEK is generated and wrapped once, then reused for new
// encryptions until DEKTTL or DEKMaxUses is reached. This keeps KMS traffic
// to roughly one Wrap call per hour per process rather than one per write.
// Unwrapped DEKs are cached (bounded) keyed by their wrapped form, so
// decryption costs one Unwrap per distinct DEK rather than per read.
type Envelope struct {
	primary   KeyProvider
	providers map[string]KeyProvider
	opts      EnvelopeOptions

	mu  sync.Mutex
	cur *activeDEK

	cacheMu sync.Mutex
	cache   map[string]cipher.AEAD // cacheKey(provider, keyID, wrapped) -> AEAD for that DEK
}

type activeDEK struct {
	keyID      string
	wrappedB64 string
	aead       cipher.AEAD
	created    time.Time
	uses       uint64
}

var _ Keyring = (*Envelope)(nil)
var _ Rewrapper = (*Envelope)(nil)

// NewEnvelope returns an Envelope keyring that encrypts with primary and can
// decrypt with primary or any of decryptOnly.
func NewEnvelope(primary KeyProvider, decryptOnly []KeyProvider, opts EnvelopeOptions) (*Envelope, error) {
	if primary == nil {
		return nil, errors.New("secrets: primary provider is required")
	}
	if opts.DEKTTL <= 0 {
		opts.DEKTTL = DefaultDEKTTL
	}
	if opts.DEKMaxUses == 0 {
		opts.DEKMaxUses = DefaultDEKMaxUses
	}
	if opts.DecryptCacheSize == 0 {
		opts.DecryptCacheSize = DefaultDecryptCacheSize
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	e := &Envelope{
		primary:   primary,
		providers: map[string]KeyProvider{},
		opts:      opts,
		cache:     map[string]cipher.AEAD{},
	}
	for _, p := range append([]KeyProvider{primary}, decryptOnly...) {
		if !validProviderName(p.Name()) {
			return nil, fmt.Errorf("secrets: invalid provider name %q", p.Name())
		}
		if _, dup := e.providers[p.Name()]; dup {
			return nil, fmt.Errorf("secrets: provider %q configured twice", p.Name())
		}
		e.providers[p.Name()] = p
	}
	return e, nil
}

// Encrypt seals plaintext bound to aad.
func (e *Envelope) Encrypt(ctx context.Context, plaintext []byte, aad string) (string, error) {
	d, err := e.activeDEK(ctx)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, nonceSize, nonceSize+len(plaintext)+tagSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	hdr := header(e.primary.Name(), d.keyID, d.wrappedB64)
	sealed := d.aead.Seal(nonce, nonce, plaintext, dataAAD(hdr, aad))
	return hdr + ":" + b64.EncodeToString(sealed), nil
}

// Decrypt opens a value produced by Encrypt with the same aad. Values that
// are not encrypted are returned as-is unless RejectPlaintext is set.
func (e *Envelope) Decrypt(ctx context.Context, stored string, aad string) ([]byte, error) {
	if !IsEncrypted(stored) {
		if e.opts.RejectPlaintext {
			return nil, ErrPlaintextRejected
		}
		return []byte(stored), nil
	}
	env, err := parseEnvelope(stored)
	if err != nil {
		return nil, err
	}
	p, ok := e.providers[env.provider]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownProvider, env.provider)
	}
	aead, err := e.unwrap(ctx, p, env)
	if err != nil {
		return nil, err
	}
	hdr := header(env.provider, env.keyID, b64.EncodeToString(env.wrapped))
	nonce, ct := env.sealed[:nonceSize], env.sealed[nonceSize:]
	pt, err := aead.Open(nil, nonce, ct, dataAAD(hdr, aad))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// NeedsRewrap reports whether stored is plaintext or was encrypted under a
// provider or key other than the current primary key.
func (e *Envelope) NeedsRewrap(ctx context.Context, stored string) (bool, error) {
	if !IsEncrypted(stored) {
		return true, nil
	}
	env, err := parseEnvelope(stored)
	if err != nil {
		return false, err
	}
	if env.provider != e.primary.Name() {
		return true, nil
	}
	d, err := e.activeDEK(ctx)
	if err != nil {
		return false, err
	}
	return env.keyID != d.keyID, nil
}

// RotateDEK discards the active data key so the next Encrypt generates and
// wraps a fresh one (e.g. right after the primary KEK was rotated).
func (e *Envelope) RotateDEK() {
	e.mu.Lock()
	e.cur = nil
	e.mu.Unlock()
}

// PurgeCache drops all cached unwrapped data keys.
func (e *Envelope) PurgeCache() {
	e.cacheMu.Lock()
	clear(e.cache)
	e.cacheMu.Unlock()
}

func (e *Envelope) activeDEK(ctx context.Context) (*activeDEK, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.opts.Now()
	if d := e.cur; d != nil && d.uses < e.opts.DEKMaxUses && now.Sub(d.created) < e.opts.DEKTTL {
		d.uses++
		return d, nil
	}
	// Holding the lock across the KMS call means concurrent writers wait for
	// one Wrap instead of all issuing their own; it happens once per TTL.
	dek := make([]byte, dekSize)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	keyID, wrapped, err := e.primary.Wrap(ctx, dek)
	if err != nil {
		wipe(dek)
		return nil, fmt.Errorf("secrets: wrapping data key with %s: %w", e.primary.Name(), err)
	}
	if keyID == "" || len(wrapped) == 0 {
		wipe(dek)
		return nil, fmt.Errorf("secrets: %s returned an empty key id or wrapped key", e.primary.Name())
	}
	aead, err := newGCM(dek)
	wipe(dek)
	if err != nil {
		return nil, err
	}
	e.putCache(cacheKey(e.primary.Name(), keyID, wrapped), aead)
	e.cur = &activeDEK{keyID: keyID, wrappedB64: b64.EncodeToString(wrapped), aead: aead, created: now, uses: 1}
	return e.cur, nil
}

func (e *Envelope) unwrap(ctx context.Context, p KeyProvider, env envelope) (cipher.AEAD, error) {
	ck := cacheKey(env.provider, env.keyID, env.wrapped)
	if e.opts.DecryptCacheSize > 0 {
		e.cacheMu.Lock()
		aead, ok := e.cache[ck]
		e.cacheMu.Unlock()
		if ok {
			return aead, nil
		}
	}
	dek, err := p.Unwrap(ctx, env.keyID, env.wrapped)
	if err != nil {
		if errors.Is(err, ErrDecrypt) {
			return nil, err
		}
		return nil, fmt.Errorf("secrets: unwrapping data key with %s: %w", env.provider, err)
	}
	defer wipe(dek)
	if len(dek) != dekSize {
		return nil, fmt.Errorf("%w: data key has wrong length", ErrDecrypt)
	}
	aead, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	e.putCache(ck, aead)
	return aead, nil
}

func (e *Envelope) putCache(k string, aead cipher.AEAD) {
	if e.opts.DecryptCacheSize <= 0 {
		return
	}
	e.cacheMu.Lock()
	defer e.cacheMu.Unlock()
	if len(e.cache) >= e.opts.DecryptCacheSize {
		// Random eviction (Go map order) is good enough: in steady state the
		// number of live DEKs is tiny, so the cache rarely fills.
		for old := range e.cache {
			delete(e.cache, old)
			break
		}
	}
	e.cache[k] = aead
}

func cacheKey(provider, keyID string, wrapped []byte) string {
	return provider + "\x00" + keyID + "\x00" + string(wrapped)
}

// dataAAD binds the sealed data to the full ciphertext header and the
// caller's context string.
func dataAAD(hdr, aad string) []byte {
	return []byte("tenarium/secrets/data/v1\x00" + hdr + "\x00" + aad)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
