// Package identity holds the credential primitives for Tenarium's internal
// user directory: password hashing and verification, password policy, and
// opaque tokens.
package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters (RFC 9106 "second recommended option", 64 MiB).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
	saltLen      = 16
)

// ErrMismatch is returned when a password does not match its hash.
var ErrMismatch = errors.New("password does not match")

// HashPassword returns a self-describing argon2id hash
// ("$argon2id$v=19$m=65536,t=3,p=2$<salt>$<key>").
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

// VerifyPassword checks password against an encoded hash in constant time.
// Parameters are read from the hash, so hashes made with older parameters
// keep working.
func VerifyPassword(encoded, password string) error {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return errors.New("unsupported password hash")
	}
	var (
		version      int
		memory, time uint32
		threads      uint8
	)
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return errors.New("unsupported argon2 version")
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return errors.New("malformed password hash")
	}
	enc := base64.RawStdEncoding
	salt, err := enc.DecodeString(parts[4])
	if err != nil {
		return errors.New("malformed password hash")
	}
	want, err := enc.DecodeString(parts[5])
	if err != nil {
		return errors.New("malformed password hash")
	}
	got := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(want))) //nolint:gosec // length of a decoded 32-byte key
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrMismatch
	}
	return nil
}

// dummyHash is verified against when a user does not exist, so that "no
// such user" and "wrong password" take the same time.
var dummyHash, _ = HashPassword("tenarium-timing-equaliser")

// BurnTime spends the same effort as a password verification.
func BurnTime(password string) { _ = VerifyPassword(dummyHash, password) }

// Policy is the password policy for the internal directory.
type Policy struct {
	MinLength int
}

// commonPasswords rejects the most obvious choices; a breached-password
// check belongs in a hook or plugin.
var commonPasswords = map[string]bool{
	"password": true, "password1": true, "password123": true, "12345678": true, "123456789": true,
	"1234567890": true, "qwertyuiop": true, "iloveyou": true, "letmein123": true, "administrator": true,
	"changeme": true, "changeme123": true, "welcome123": true, "passw0rd": true, "p@ssw0rd": true,
}

// Check validates a new password. email is rejected as a password.
func (p Policy) Check(password, email string) error {
	n := utf8.RuneCountInString(password)
	minLen := max(p.MinLength, 8)
	switch {
	case n < minLen:
		return fmt.Errorf("must be at least %d characters", minLen)
	case len(password) > 1024:
		return errors.New("must be at most 1024 bytes")
	case commonPasswords[strings.ToLower(password)]:
		return errors.New("is too common")
	case email != "" && strings.EqualFold(password, email):
		return errors.New("must not be your email address")
	}
	return nil
}

// NewToken returns a random URL-safe token and its storage hash. Only the
// hash is stored; the token is handed to the user once.
func NewToken() (token, hash string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, HashToken(token)
}

// HashToken hashes an opaque token for storage and lookup.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
