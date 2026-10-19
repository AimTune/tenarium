// Package secrets encrypts secret values at rest (token signing keys,
// webhook signing secrets, upstream client secrets) using envelope
// encryption with a pluggable key provider (KMS).
//
// # Model
//
// Each value is sealed with AES-256-GCM under a random 256-bit data key
// (DEK). The DEK is wrapped by a KeyProvider: a local AES-256-GCM key from
// config, AWS KMS, GCP Cloud KMS, HashiCorp Vault Transit or Azure Key Vault.
// The result is a self-describing, versioned string:
//
//	enc:v1:<provider>:<key id>:<wrapped dek>:<nonce || ciphertext || tag>
//
// key id is query-escaped; the binary fields are unpadded base64url. The
// data AEAD's additional data covers the whole header plus a caller-supplied
// context string (aad) such as "signing_key:<id>", so a ciphertext cannot be
// moved to another row or have its header edited without failing to decrypt.
//
// # Threat model
//
// Protects: database dumps, backups, replicas, snapshots, read-only SQL
// injection and anyone who can read the secrets table but not the KEK.
// With a cloud KMS the KEK never leaves the KMS, and access is audited and
// revocable there.
//
// Does not protect: a compromised running server (it holds unwrapped DEKs in
// memory and can ask the KMS to unwrap more), an attacker holding both the
// database and the local KEK config, or an attacker who can write to the
// database and observe the application's behaviour with chosen values
// (integrity is per value; deleting rows or restoring an older, valid
// ciphertext for the same aad is not detected).
//
// # Performance
//
// A DEK is generated and wrapped once, then reused for new values until
// EnvelopeOptions.DEKTTL (default 1h) or DEKMaxUses (default 2^24) is hit,
// so writes cost one KMS call per hour per process instead of one per value.
// Reuse is safe: GCM nonces are random 96-bit values and the use cap keeps
// collision probability negligible. Unwrapped DEKs are cached (as ready
// AEADs) keyed by their wrapped form, so reads cost one KMS call per
// distinct DEK per process. The trade-off versus a DEK per value is that a
// leaked DEK exposes every value written in that window, which matters only
// in the "compromised running server" case already out of scope.
//
// # Rotation
//
// KEK rotation (local provider): add a new key, make it primary, keep the old
// one. New values use the new key; old ones still decrypt. Run Rotate over
// every stored value (it skips values already under the current key), then
// remove the old key.
//
// KMS-side rotation (AWS automatic rotation, GCP primary version, Vault
// transit/keys/<k>/rotate, Azure new key version): nothing to do for
// decryption; run Rotate to re-wrap under the new version if policy requires.
//
// Provider migration (e.g. local -> vault): set provider to the new one and
// list the old one in decrypt_providers, run Rotate, then remove it.
//
// Legacy plaintext: Decrypt returns values without the "enc:" prefix as-is,
// so enabling encryption on an existing database is safe. Rotate encrypts
// them. Once migrated, set reject_plaintext so a plaintext value written into
// the database by an attacker is refused.
package secrets
