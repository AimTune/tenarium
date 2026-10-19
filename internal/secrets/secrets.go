package secrets

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Keyring encrypts and decrypts small secret values (signing keys, webhook
// secrets, client secrets) for storage at rest.
//
// aad ("additional authenticated data") binds a ciphertext to the context it
// is stored in, e.g. "signing_key:<id>" or "webhook_secret:<id>". Decrypting
// with a different aad fails, so an attacker with write access to the
// database cannot move a ciphertext from one row to another.
//
// Decrypt passes values that are not in the encrypted format (see
// IsEncrypted) through unchanged, so databases written before encryption was
// enabled keep working. Use Rotate to migrate them.
type Keyring interface {
	Encrypt(ctx context.Context, plaintext []byte, aad string) (string, error)
	Decrypt(ctx context.Context, ciphertext string, aad string) ([]byte, error)
}

// Rewrapper is implemented by keyrings that can tell whether a stored value
// is already encrypted under the current provider and key. Rotate uses it to
// skip values that do not need work.
type Rewrapper interface {
	NeedsRewrap(ctx context.Context, stored string) (bool, error)
}

// Errors returned by this package. Wrapped errors carry details; use
// errors.Is to test.
var (
	// ErrMalformed means a value looks encrypted (has the "enc:" prefix) but
	// cannot be parsed.
	ErrMalformed = errors.New("secrets: malformed ciphertext")
	// ErrUnsupportedVersion means the ciphertext uses a format version this
	// build does not understand.
	ErrUnsupportedVersion = errors.New("secrets: unsupported ciphertext version")
	// ErrUnknownProvider means the ciphertext names a key provider that is
	// not configured.
	ErrUnknownProvider = errors.New("secrets: ciphertext provider not configured")
	// ErrDecrypt means authentication failed: wrong key, wrong aad, or the
	// value was tampered with. It deliberately does not say which.
	ErrDecrypt = errors.New("secrets: decryption failed")
	// ErrPlaintextRejected is returned by Decrypt when RejectPlaintext is
	// set and the stored value is not encrypted.
	ErrPlaintextRejected = errors.New("secrets: refusing unencrypted value")
)

const (
	formatPrefix = "enc:"
	formatV1     = "v1"
	fieldCount   = 6 // enc, v1, provider, key id, wrapped dek, nonce+ct
)

var b64 = base64.RawURLEncoding

// IsEncrypted reports whether s is in this package's ciphertext format
// ("enc:v<N>:..."). It does not validate the rest of the value.
func IsEncrypted(s string) bool {
	if !strings.HasPrefix(s, formatPrefix+"v") {
		return false
	}
	rest := s[len(formatPrefix)+1:]
	i := strings.IndexByte(rest, ':')
	if i <= 0 {
		return false
	}
	for _, c := range rest[:i] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// envelope is a parsed v1 ciphertext:
//
//	enc:v1:<provider>:<key id>:<wrapped dek>:<nonce||ciphertext>
//
// key id is query-escaped (KMS key ids such as ARNs and URLs contain ':');
// the two binary fields are unpadded base64url.
type envelope struct {
	provider string
	keyID    string
	wrapped  []byte
	sealed   []byte // nonce || ciphertext || tag
}

// header returns the canonical text that precedes the sealed data. It is
// authenticated as part of the data AEAD's additional data.
func header(provider, keyID, wrappedB64 string) string {
	return formatPrefix + formatV1 + ":" + provider + ":" + url.QueryEscape(keyID) + ":" + wrappedB64
}

func (e envelope) String() string {
	return header(e.provider, e.keyID, b64.EncodeToString(e.wrapped)) + ":" + b64.EncodeToString(e.sealed)
}

func parseEnvelope(s string) (envelope, error) {
	if !IsEncrypted(s) {
		return envelope{}, ErrMalformed
	}
	parts := strings.Split(s, ":")
	if parts[1] != formatV1 {
		return envelope{}, fmt.Errorf("%w: %q", ErrUnsupportedVersion, parts[1])
	}
	if len(parts) != fieldCount {
		return envelope{}, fmt.Errorf("%w: expected %d fields, got %d", ErrMalformed, fieldCount, len(parts))
	}
	if !validProviderName(parts[2]) {
		return envelope{}, fmt.Errorf("%w: bad provider name", ErrMalformed)
	}
	keyID, err := url.QueryUnescape(parts[3])
	if err != nil || keyID == "" {
		return envelope{}, fmt.Errorf("%w: bad key id", ErrMalformed)
	}
	wrapped, err := b64.DecodeString(parts[4])
	if err != nil || len(wrapped) == 0 {
		return envelope{}, fmt.Errorf("%w: bad wrapped key", ErrMalformed)
	}
	sealed, err := b64.DecodeString(parts[5])
	if err != nil || len(sealed) < nonceSize+tagSize {
		return envelope{}, fmt.Errorf("%w: bad payload", ErrMalformed)
	}
	return envelope{provider: parts[2], keyID: keyID, wrapped: wrapped, sealed: sealed}, nil
}

func validProviderName(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// Rotate re-encrypts stored with kr's current provider and key. Legacy
// plaintext values are encrypted. If kr implements Rewrapper and reports the
// value is already current, stored is returned unchanged with changed=false.
//
// Typical use is a background job that walks every secret column:
//
//	newVal, changed, err := secrets.Rotate(ctx, kr, row.Secret, "webhook_secret:"+row.ID)
//	if err == nil && changed { update row }
func Rotate(ctx context.Context, kr Keyring, stored, aad string) (newValue string, changed bool, err error) {
	if !IsEncrypted(stored) {
		// Legacy plaintext: encrypt directly (Decrypt may be configured to
		// reject plaintext, which is exactly when a migration is needed).
		out, err := kr.Encrypt(ctx, []byte(stored), aad)
		if err != nil {
			return "", false, err
		}
		return out, true, nil
	}
	if rw, ok := kr.(Rewrapper); ok {
		need, err := rw.NeedsRewrap(ctx, stored)
		if err != nil {
			return "", false, err
		}
		if !need {
			return stored, false, nil
		}
	}
	pt, err := kr.Decrypt(ctx, stored, aad)
	if err != nil {
		return "", false, err
	}
	defer wipe(pt)
	out, err := kr.Encrypt(ctx, pt, aad)
	if err != nil {
		return "", false, err
	}
	return out, out != stored, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
