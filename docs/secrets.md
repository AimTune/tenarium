# Secrets at rest

Tenarium stores a few secrets it must be able to read back: token signing keys, TOTP secrets,
tenant webhook signing secrets, SSO client secrets, and the ACME certificates and account key of
[managed certificates](tls.md) (`kv` table). With a `secrets` provider configured they
are encrypted in the database with **envelope encryption**: each value is sealed with AES-256-GCM
under a data key (DEK), and the DEK is wrapped by a key-encryption key (KEK) held in a KMS or in
the configuration.

Values that are only verified, never read back, are stored as hashes anyway and need no
encryption: passwords, API keys, refresh tokens, OAuth client secrets, one-time tokens.

## Configuration

```yaml
secrets:
  provider: awskms         # none (default) | local | awskms | gcpkms | vault | azurekv
  decrypt_providers: []    # old providers kept for reading during a migration
  dek_ttl: 1h              # how long one data key is reused for new values
  dek_max_uses: 16777216   # encryptions per data key (at most 2^32)
  decrypt_cache_size: 1024 # unwrapped data keys kept in memory (negative: no cache)
  reject_plaintext: false  # refuse unencrypted values (after migrating, see below)
  timeout: 30s             # per KMS request

  local:                   # KEKs in the config: head -c32 /dev/urandom | base64
    primary: k2
    keys:
      k1: ${TENARIUM_KEK_1}  # retired, kept to decrypt
      k2: ${TENARIUM_KEK_2}

  aws_kms:                 # IAM: kms:Encrypt and kms:Decrypt on the key
    key_id: alias/tenarium # key ID, key ARN, alias name or alias ARN
    region: eu-west-1      # else the SDK chain (AWS_REGION, shared config) or the key ARN
    # endpoint, profile, access_key_id, secret_access_key, session_token: optional;
    # by default the AWS credential chain (env, IRSA / web identity, ECS, instance role)

  gcp_kms:                 # IAM: roles/cloudkms.cryptoKeyEncrypterDecrypter
    key_name: projects/p/locations/global/keyRings/r/cryptoKeys/tenarium
    # credentials_file or credentials_json, else Application Default Credentials; endpoint

  vault:                   # Transit; policy: update on transit/encrypt/tenarium and transit/decrypt/tenarium
    address: https://vault:8200
    token_file: /vault/secrets/token   # or token, or VAULT_TOKEN
    mount_path: transit
    key_name: tenarium
    # namespace: admin/team

  azure_key_vault:         # RSA key with wrapKey / unwrapKey
    vault_url: https://my-vault.vault.azure.net
    key_name: tenarium
    tenant_id: ...
    client_id: ...
    client_secret: ${AZURE_CLIENT_SECRET}
    # key_version, algorithm (RSA-OAEP-256 | RSA-OAEP), authority_host, scope, api_version
```

Only the section of the configured provider (and of each `decrypt_providers` entry) is used.
The configuration is validated at startup without calling the KMS; cloud credentials are
resolved then, and the first KMS call happens on the first encryption or decryption.

| Provider | KEK lives in | Use for |
|---|---|---|
| `local` | the configuration (env vars, mounted secret) | development, self-hosted installs; keep the keys out of the database and its backups |
| `awskms` | AWS KMS (symmetric key) | AWS |
| `gcpkms` | Google Cloud KMS | GCP |
| `vault` | HashiCorp Vault Transit | Vault users, on-premises |
| `azurekv` | Azure Key Vault or Managed HSM (RSA key) | Azure |

## How it works

- A stored value looks like
  `enc:v1:<provider>:<key id>:<wrapped DEK>:<nonce|ciphertext|tag>`. It names the provider and
  key that wrapped its DEK, so old values keep decrypting after a key rotation.
- Each value is bound to its row (`signing_key:<id>`, `mfa:<user>`, `kv:<key>` for every value
  of the `kv` table, ...) as additional
  authenticated data: a ciphertext copied to another row, or with an edited header, fails to
  decrypt.
- A DEK is reused for new values for `dek_ttl` or `dek_max_uses` encryptions, so writes cost one
  KMS call per hour per replica rather than one per value. Unwrapped DEKs are cached, so reads
  cost one KMS call per distinct DEK per replica.
- Values written before encryption was enabled have no `enc:` prefix and are read as they are,
  so turning encryption on for an existing database is safe.
- With `provider: none`, Tenarium refuses to read encrypted values instead of returning
  garbage, so an accidental configuration rollback fails loudly.

**What it protects against:** database dumps, backups, replicas and snapshots, read-only SQL
injection, and anyone who can read the tables but not the KEK. With a cloud KMS the KEK never
leaves the KMS, and its use is audited and revocable there.

**What it does not protect against:** a compromised running server (it holds unwrapped DEKs and
can ask the KMS for more), an attacker holding both the database and the `local` keys, or one
who can write to the database and restore an older valid ciphertext for the same row.

## Rotation and migration

- **Local KEK rotation:** add a new key, make it `primary`, keep the old one, restart. New values
  use the new key; old ones still decrypt.
- **KMS-side rotation** (AWS automatic rotation, a new GCP primary version, Vault
  `transit/keys/<key>/rotate`, a new Azure key version): nothing to do; the KMS still decrypts
  values wrapped by older versions.
- **Changing provider** (for example `local` to `vault`): set `provider` to the new one and list
  the old one in `decrypt_providers` with its section kept.

Values written afterwards use the new key or provider; existing rows keep their old encryption
until you re-encrypt them:

```sh
tenarium -config tenarium.yaml -reencrypt
# {"rewritten": {"kv": 3, "mfa": 12, "signing_keys": 2, "webhooks": 5},
#  "current":   {"sso": 4}}
```

It rewrites every encrypted value (signing keys, MFA secrets, webhook and SSO secrets and the
key-value table) under the current key, encrypts values stored before encryption was enabled,
skips values that are already current, and prints a report. It is safe to run repeatedly, and
while servers are running: signing keys and key-value entries are only replaced if unchanged
since they were read (a conflict is counted under `skipped`; run it again). MFA, webhook and SSO
secrets are rewritten in place, so prefer a quiet moment: a user enrolling two-factor at the same
instant could lose the new enrollment. Only after a run that reports nothing `skipped`, remove the
old local key or decrypt provider, or set `reject_plaintext`; otherwise reads of those values
fail.

## Not covered

- SAML metadata is public and stored as is.
- Plugin configuration secrets are not stored by Tenarium; pass them as `${VAR}` from the
  environment.
