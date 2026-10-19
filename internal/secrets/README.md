# internal/secrets

Envelope encryption for secrets stored in the database (signing keys,
webhook secrets, client secrets). The package overview, threat model and
rotation procedure are in [doc.go](doc.go); this file covers configuration
and wiring.

## API

```go
kr, err := secrets.New(ctx, cfg.Secrets)                    // validates, builds providers
ct, err := kr.Encrypt(ctx, pem, "signing_key:"+id)           // "enc:v1:..."
pt, err := kr.Decrypt(ctx, row.PrivateKey, "signing_key:"+id) // plaintext passes through
out, changed, err := secrets.Rotate(ctx, kr, row.PrivateKey, "signing_key:"+id)
secrets.IsEncrypted(s)
```

Use a stable, row-specific `aad` (`<kind>:<primary key>`). Decrypting with a
different `aad` fails with `ErrDecrypt`.

## Ciphertext format

```
enc:v1:<provider>:<url-query-escaped key id>:<b64url wrapped DEK>:<b64url nonce|ct|tag>
```

The data AAD is `"tenarium/secrets/data/v1" NUL header NUL aad`, where header is
everything before the last field.

## Configuration

```yaml
secrets:
  provider: local          # none | local | awskms | gcpkms | vault | azurekv
  decrypt_providers: []    # old providers kept for reading during a migration
  dek_ttl: 1h              # how long one data key is reused for writes
  dek_max_uses: 16777216
  decrypt_cache_size: 1024 # negative disables the unwrapped-DEK cache
  reject_plaintext: false  # enable after every row has been rotated
  timeout: 30s

  local:                   # generate keys: head -c32 /dev/urandom | base64
    primary: k2
    keys:
      k1: "base64-32-bytes"   # retired, kept to decrypt
      k2: "base64-32-bytes"

  aws_kms:                 # IAM: kms:Encrypt, kms:Decrypt on the key
    key_id: alias/tenarium
    region: eu-west-1
    # endpoint: http://localhost:4566   (LocalStack)
    # access_key_id / secret_access_key / session_token / profile: optional,
    # otherwise the default AWS credential chain (env, IRSA, instance role)

  gcp_kms:                 # IAM: roles/cloudkms.cryptoKeyEncrypterDecrypter
    key_name: projects/p/locations/global/keyRings/r/cryptoKeys/tenarium
    # credentials_file / credentials_json, else Application Default Credentials

  vault:                   # policy: update on transit/encrypt/tenarium, transit/decrypt/tenarium
    address: https://vault:8200
    token_file: /vault/secrets/token   # or token, or VAULT_TOKEN
    mount_path: transit
    key_name: tenarium
    # namespace: admin/team

  azure_key_vault:         # key permissions: wrapKey, unwrapKey (RSA key)
    vault_url: https://my-vault.vault.azure.net
    key_name: tenarium
    tenant_id: ...
    client_id: ...
    client_secret: ...
    # key_version, algorithm (RSA-OAEP-256), authority_host, scope, api_version
```

`provider: none` (the default) stores values unchanged; it refuses to read
values that are encrypted, so an accidental config rollback fails loudly.

## Rotation

1. Add a new local key and make it `primary` (or rotate the key in your KMS,
   or switch `provider` and list the old one under `decrypt_providers`).
2. Restart. New writes use the new key; old values keep decrypting.
3. Run `secrets.Rotate` over every stored value. It skips values that are
   already current, and encrypts legacy plaintext.
4. Remove the old key / decrypt provider. Optionally set `reject_plaintext`.

## Tests

`go test ./internal/secrets/` uses in-process fakes for every KMS (the AWS
fake re-computes and checks the SigV4 signature). Real-service tests run
when these are set:

| Variable | Service |
| --- | --- |
| `TENARIUM_TEST_VAULT_ADDR`, `TENARIUM_TEST_VAULT_TOKEN` | Vault dev server (`hashicorp/vault`, `VAULT_DEV_ROOT_TOKEN_ID=root`) |
| `TENARIUM_TEST_AWS_ENDPOINT` | LocalStack (`localstack/localstack`, `SERVICES=kms`) |
