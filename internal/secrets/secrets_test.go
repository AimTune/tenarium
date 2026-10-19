package secrets

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func mustKey(t *testing.T) string {
	t.Helper()
	k, err := GenerateLocalKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func localKeyring(t *testing.T, primary string, keys map[string]string, opts ...func(*Config)) Keyring {
	t.Helper()
	c := Config{Provider: ProviderLocal, Local: LocalConfig{Primary: primary, Keys: keys}}
	for _, o := range opts {
		o(&c)
	}
	kr, err := New(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func TestLocalRoundTrip(t *testing.T) {
	ctx := context.Background()
	kr := localKeyring(t, "k1", map[string]string{"k1": mustKey(t)})
	for _, pt := range [][]byte{[]byte("whsec_abc123"), {}, bytes.Repeat([]byte{0, 1, 2, 255}, 4096)} {
		ct, err := kr.Encrypt(ctx, pt, "webhook_secret:42")
		if err != nil {
			t.Fatal(err)
		}
		if !IsEncrypted(ct) || !strings.HasPrefix(ct, "enc:v1:local:k1:") {
			t.Fatalf("unexpected format %q", ct)
		}
		if len(pt) > 4 && strings.Contains(ct, string(pt)) {
			t.Fatal("plaintext visible in ciphertext")
		}
		got, err := kr.Decrypt(ctx, ct, "webhook_secret:42")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("round trip mismatch")
		}
	}
	// Same plaintext encrypts differently each time (random nonce).
	a, _ := kr.Encrypt(ctx, []byte("x"), "a")
	b, _ := kr.Encrypt(ctx, []byte("x"), "a")
	if a == b {
		t.Fatal("ciphertexts should differ")
	}
}

func TestAADMismatchFails(t *testing.T) {
	ctx := context.Background()
	kr := localKeyring(t, "k1", map[string]string{"k1": mustKey(t)})
	ct, err := kr.Encrypt(ctx, []byte("secret"), "signing_key:1")
	if err != nil {
		t.Fatal(err)
	}
	for _, aad := range []string{"signing_key:2", "webhook_secret:1", "", "signing_key:1 "} {
		if _, err := kr.Decrypt(ctx, ct, aad); !errors.Is(err, ErrDecrypt) {
			t.Errorf("aad %q: want ErrDecrypt, got %v", aad, err)
		}
	}
}

func TestTamperingFails(t *testing.T) {
	ctx := context.Background()
	keys := map[string]string{"k1": mustKey(t), "k2": mustKey(t)}
	kr := localKeyring(t, "k1", keys)
	ct, err := kr.Encrypt(ctx, []byte("secret value"), "aad")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(ct, ":")

	flip := func(field int) string {
		p := append([]string(nil), parts...)
		raw, err := b64.DecodeString(p[field])
		if err != nil {
			t.Fatal(err)
		}
		raw[len(raw)/2] ^= 0x01
		p[field] = b64.EncodeToString(raw)
		return strings.Join(p, ":")
	}
	cases := map[string]string{
		"payload bit flip":     flip(5),
		"wrapped dek bit flip": flip(4),
		"truncated payload":    ct[:len(ct)-4],
		"key id swapped":       strings.Replace(ct, ":k1:", ":k2:", 1),
	}
	// Splice a wrapped DEK from another ciphertext encrypted under a fresh DEK.
	kr2 := localKeyring(t, "k1", keys)
	other, _ := kr2.Encrypt(ctx, []byte("other"), "aad")
	op := strings.Split(other, ":")
	p := append([]string(nil), parts...)
	p[4] = op[4]
	cases["foreign dek"] = strings.Join(p, ":")

	for name, bad := range cases {
		if _, err := kr.Decrypt(ctx, bad, "aad"); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	// Ciphertext moved between rows in the same keyring: covered by AAD test.
}

func TestMalformed(t *testing.T) {
	ctx := context.Background()
	kr := localKeyring(t, "k1", map[string]string{"k1": mustKey(t)})
	for _, s := range []string{"enc:v1:", "enc:v1:local:k1:AAAA", "enc:v1:local:k1:!!:AAAA", "enc:v1:LOCAL:k1:AAAA:AAAA", "enc:v1:local::AAAA:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
		if _, err := kr.Decrypt(ctx, s, ""); !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: want ErrMalformed, got %v", s, err)
		}
	}
	if _, err := kr.Decrypt(ctx, "enc:v9:x", ""); !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("want ErrUnsupportedVersion, got %v", err)
	}
	// A provider that is not configured.
	ct, _ := kr.Encrypt(ctx, []byte("x"), "")
	moved := strings.Replace(ct, ":local:", ":vault:", 1)
	if _, err := kr.Decrypt(ctx, moved, ""); !errors.Is(err, ErrUnknownProvider) {
		t.Errorf("want ErrUnknownProvider, got %v", err)
	}
}

func TestIsEncrypted(t *testing.T) {
	yes := []string{"enc:v1:local:k:a:b", "enc:v12:x"}
	no := []string{"", "enc:", "enc:v:", "enc:vx:", "-----BEGIN PRIVATE KEY-----", "whsec_123", "ENC:v1:x", "enc:v1"}
	for _, s := range yes {
		if !IsEncrypted(s) {
			t.Errorf("%q should be encrypted", s)
		}
	}
	for _, s := range no {
		if IsEncrypted(s) {
			t.Errorf("%q should not be encrypted", s)
		}
	}
}

func TestLegacyPlaintextPassthrough(t *testing.T) {
	ctx := context.Background()
	kr := localKeyring(t, "k1", map[string]string{"k1": mustKey(t)})
	legacy := "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n"
	got, err := kr.Decrypt(ctx, legacy, "signing_key:1")
	if err != nil || string(got) != legacy {
		t.Fatalf("passthrough failed: %q %v", got, err)
	}

	strict := localKeyring(t, "k1", map[string]string{"k1": mustKey(t)}, func(c *Config) { c.RejectPlaintext = true })
	if _, err := strict.Decrypt(ctx, legacy, "signing_key:1"); !errors.Is(err, ErrPlaintextRejected) {
		t.Fatalf("want ErrPlaintextRejected, got %v", err)
	}
	// Rotate still migrates plaintext under RejectPlaintext.
	out, changed, err := Rotate(ctx, strict, legacy, "signing_key:1")
	if err != nil || !changed || !IsEncrypted(out) {
		t.Fatalf("rotate plaintext: %q %v %v", out, changed, err)
	}
	got, err = strict.Decrypt(ctx, out, "signing_key:1")
	if err != nil || string(got) != legacy {
		t.Fatalf("decrypt migrated: %v", err)
	}
}

func TestKeyRotation(t *testing.T) {
	ctx := context.Background()
	k1, k2 := mustKey(t), mustKey(t)
	old := localKeyring(t, "k1", map[string]string{"k1": k1})
	ct1, err := old.Encrypt(ctx, []byte("s3cret"), "webhook_secret:9")
	if err != nil {
		t.Fatal(err)
	}

	// Operator adds k2 and makes it primary, keeping k1 for decryption.
	kr := localKeyring(t, "k2", map[string]string{"k1": k1, "k2": k2})
	got, err := kr.Decrypt(ctx, ct1, "webhook_secret:9")
	if err != nil || string(got) != "s3cret" {
		t.Fatalf("old key should decrypt: %v", err)
	}
	ct2, err := kr.Encrypt(ctx, []byte("new"), "x")
	if err != nil || !strings.HasPrefix(ct2, "enc:v1:local:k2:") {
		t.Fatalf("new values should use k2: %q %v", ct2, err)
	}

	rw := kr.(Rewrapper)
	if need, err := rw.NeedsRewrap(ctx, ct1); err != nil || !need {
		t.Fatalf("k1 value should need rewrap: %v %v", need, err)
	}
	if need, err := rw.NeedsRewrap(ctx, ct2); err != nil || need {
		t.Fatalf("k2 value should not need rewrap: %v %v", need, err)
	}

	rotated, changed, err := Rotate(ctx, kr, ct1, "webhook_secret:9")
	if err != nil || !changed || !strings.HasPrefix(rotated, "enc:v1:local:k2:") {
		t.Fatalf("rotate: %q %v %v", rotated, changed, err)
	}
	same, changed, err := Rotate(ctx, kr, rotated, "webhook_secret:9")
	if err != nil || changed || same != rotated {
		t.Fatalf("second rotate should be a no-op: %v %v", changed, err)
	}
	if _, _, err := Rotate(ctx, kr, ct1, "wrong"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("rotate with wrong aad: %v", err)
	}

	// After every row is rotated, k1 can be removed.
	onlyK2 := localKeyring(t, "k2", map[string]string{"k2": k2})
	if got, err := onlyK2.Decrypt(ctx, rotated, "webhook_secret:9"); err != nil || string(got) != "s3cret" {
		t.Fatalf("rotated value under k2 only: %v", err)
	}
	if _, err := onlyK2.Decrypt(ctx, ct1, "webhook_secret:9"); err == nil {
		t.Fatal("k1 value must not decrypt without k1")
	}
}

// countingProvider wraps a provider and counts calls.
type countingProvider struct {
	KeyProvider
	name          string
	wraps, unwrap atomic.Int64
}

func (c *countingProvider) Name() string {
	if c.name != "" {
		return c.name
	}
	return c.KeyProvider.Name()
}

func (c *countingProvider) Wrap(ctx context.Context, dek []byte) (string, []byte, error) {
	c.wraps.Add(1)
	return c.KeyProvider.Wrap(ctx, dek)
}

func (c *countingProvider) Unwrap(ctx context.Context, id string, w []byte) ([]byte, error) {
	c.unwrap.Add(1)
	return c.KeyProvider.Unwrap(ctx, id, w)
}

func newCounting(t *testing.T) *countingProvider {
	t.Helper()
	p, err := NewLocalProvider(LocalConfig{Primary: "k", Keys: map[string]string{"k": mustKey(t)}})
	if err != nil {
		t.Fatal(err)
	}
	return &countingProvider{KeyProvider: p}
}

func TestDEKCaching(t *testing.T) {
	ctx := context.Background()
	cp := newCounting(t)
	now := time.Unix(1_700_000_000, 0)
	var clockMu sync.Mutex
	e, err := NewEnvelope(cp, nil, EnvelopeOptions{DEKTTL: time.Hour, DEKMaxUses: 100, Now: func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}})
	if err != nil {
		t.Fatal(err)
	}
	var cts []string
	for i := 0; i < 50; i++ {
		ct, err := e.Encrypt(ctx, []byte("v"), "a")
		if err != nil {
			t.Fatal(err)
		}
		cts = append(cts, ct)
	}
	if n := cp.wraps.Load(); n != 1 {
		t.Fatalf("want 1 wrap for 50 encrypts, got %d", n)
	}
	for _, ct := range cts {
		if _, err := e.Decrypt(ctx, ct, "a"); err != nil {
			t.Fatal(err)
		}
	}
	if n := cp.unwrap.Load(); n != 0 {
		t.Fatalf("active DEK should be served from cache, got %d unwraps", n)
	}

	// Max uses rolls the DEK.
	for i := 0; i < 60; i++ {
		if _, err := e.Encrypt(ctx, []byte("v"), "a"); err != nil {
			t.Fatal(err)
		}
	}
	if n := cp.wraps.Load(); n != 2 {
		t.Fatalf("want rollover after max uses, wraps=%d", n)
	}
	// TTL rolls the DEK.
	clockMu.Lock()
	now = now.Add(2 * time.Hour)
	clockMu.Unlock()
	if _, err := e.Encrypt(ctx, []byte("v"), "a"); err != nil {
		t.Fatal(err)
	}
	if n := cp.wraps.Load(); n != 3 {
		t.Fatalf("want rollover after TTL, wraps=%d", n)
	}
	e.RotateDEK()
	if _, err := e.Encrypt(ctx, []byte("v"), "a"); err != nil {
		t.Fatal(err)
	}
	if n := cp.wraps.Load(); n != 4 {
		t.Fatalf("want rollover after RotateDEK, wraps=%d", n)
	}

	// A fresh process (empty cache) unwraps once per distinct DEK.
	e2, _ := NewEnvelope(cp, nil, EnvelopeOptions{})
	for _, ct := range cts {
		if _, err := e2.Decrypt(ctx, ct, "a"); err != nil {
			t.Fatal(err)
		}
	}
	if n := cp.unwrap.Load(); n != 1 {
		t.Fatalf("want 1 unwrap for 50 values sharing a DEK, got %d", n)
	}
	e2.PurgeCache()
	if _, err := e2.Decrypt(ctx, cts[0], "a"); err != nil {
		t.Fatal(err)
	}
	if n := cp.unwrap.Load(); n != 2 {
		t.Fatalf("want unwrap after purge, got %d", n)
	}

	// Cache disabled: every decrypt unwraps.
	e3, _ := NewEnvelope(cp, nil, EnvelopeOptions{DecryptCacheSize: -1})
	before := cp.unwrap.Load()
	for _, ct := range cts[:5] {
		if _, err := e3.Decrypt(ctx, ct, "a"); err != nil {
			t.Fatal(err)
		}
	}
	if n := cp.unwrap.Load() - before; n != 5 {
		t.Fatalf("cache disabled: want 5 unwraps, got %d", n)
	}
}

func TestConcurrentUse(t *testing.T) {
	ctx := context.Background()
	cp := newCounting(t)
	e, _ := NewEnvelope(cp, nil, EnvelopeOptions{DEKMaxUses: 7, DecryptCacheSize: 3})
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				aad := "row:" + string(rune('a'+g))
				ct, err := e.Encrypt(ctx, []byte(aad), aad)
				if err != nil {
					errs <- err
					return
				}
				pt, err := e.Decrypt(ctx, ct, aad)
				if err != nil || string(pt) != aad {
					errs <- errors.Join(err, errors.New("mismatch"))
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestProviderMigration(t *testing.T) {
	ctx := context.Background()
	key := mustKey(t)
	oldKR := localKeyring(t, "k1", map[string]string{"k1": key})
	ct, _ := oldKR.Encrypt(ctx, []byte("legacy-local"), "a")

	// New primary is a different provider; local kept for decryption.
	local, _ := NewLocalProvider(LocalConfig{Primary: "k1", Keys: map[string]string{"k1": key}})
	other := newCounting(t)
	other.name = "other"
	e, err := NewEnvelope(other, []KeyProvider{local}, EnvelopeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := e.Decrypt(ctx, ct, "a"); err != nil || string(got) != "legacy-local" {
		t.Fatalf("decrypt via secondary provider: %v", err)
	}
	out, changed, err := Rotate(ctx, e, ct, "a")
	if err != nil || !changed || !strings.HasPrefix(out, "enc:v1:other:") {
		t.Fatalf("migrate: %q %v %v", out, changed, err)
	}
	if _, err := NewEnvelope(local, []KeyProvider{local}, EnvelopeOptions{}); err == nil {
		t.Fatal("duplicate provider should be rejected")
	}
}

func TestNoneProvider(t *testing.T) {
	ctx := context.Background()
	kr, err := New(ctx, Config{})
	if err != nil {
		t.Fatal(err)
	}
	s, err := kr.Encrypt(ctx, []byte("plain"), "a")
	if err != nil || s != "plain" {
		t.Fatalf("none encrypt: %q %v", s, err)
	}
	if got, err := kr.Decrypt(ctx, "plain", "a"); err != nil || string(got) != "plain" {
		t.Fatal(err)
	}
	if _, err := kr.Decrypt(ctx, "enc:v1:local:k:AAAA:AAAA", "a"); err == nil {
		t.Fatal("none must refuse encrypted values")
	}
	if _, err := kr.Encrypt(ctx, []byte("enc:v1:x"), "a"); err == nil {
		t.Fatal("none must refuse ambiguous plaintext")
	}
}

func TestConfigValidation(t *testing.T) {
	key := mustKey(t)
	good := LocalConfig{Primary: "k1", Keys: map[string]string{"k1": key}}
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"unknown provider", Config{Provider: "rot13"}, "unknown provider"},
		{"local no keys", Config{Provider: "local"}, "local.keys"},
		{"local bad primary", Config{Provider: "local", Local: LocalConfig{Primary: "x", Keys: map[string]string{"k1": key}}}, "local.primary"},
		{"local short key", Config{Provider: "local", Local: LocalConfig{Primary: "k1", Keys: map[string]string{"k1": "c2hvcnQ="}}}, "32 bytes"},
		{"local not base64", Config{Provider: "local", Local: LocalConfig{Primary: "k1", Keys: map[string]string{"k1": "%%%"}}}, "base64"},
		{"aws no key", Config{Provider: "awskms"}, "aws_kms.key_id"},
		{"aws half creds", Config{Provider: "awskms", AWSKMS: AWSKMSConfig{KeyID: "alias/x", AccessKeyID: "A"}}, "together"},
		{"gcp bad name", Config{Provider: "gcpkms", GCPKMS: GCPKMSConfig{KeyName: "projects/p/keys/k"}}, "gcp_kms.key_name"},
		{"vault no key", Config{Provider: "vault", Vault: VaultTransitConfig{Address: "http://v:8200"}}, "vault.key_name"},
		{"vault bad mount", Config{Provider: "vault", Vault: VaultTransitConfig{Address: "http://v:8200", KeyName: "k", MountPath: "a/../b"}}, "mount_path"},
		{"azure no creds", Config{Provider: "azurekv", AzureKeyVault: AzureKeyVaultConfig{VaultURL: "https://v.vault.azure.net", KeyName: "k"}}, "client_secret"},
		{"azure bad alg", Config{Provider: "azurekv", AzureKeyVault: AzureKeyVaultConfig{VaultURL: "https://v.vault.azure.net", KeyName: "k", Algorithm: "RSA1_5", TenantID: "t", ClientID: "c", ClientSecret: "s"}}, "algorithm"},
		{"decrypt none", Config{Provider: "local", Local: good, DecryptProviders: []string{"none"}}, "cannot decrypt"},
		{"decrypt dup", Config{Provider: "local", Local: good, DecryptProviders: []string{"local"}}, "twice"},
		{"decrypt missing section", Config{Provider: "local", Local: good, DecryptProviders: []string{"vault"}}, "vault"},
		{"dek uses", Config{Provider: "local", Local: good, DEKMaxUses: 1 << 40}, "dek_max_uses"},
		{"dek ttl", Config{Provider: "local", Local: good, DEKTTL: time.Millisecond}, "dek_ttl"},
	}
	for _, tc := range cases {
		err := tc.cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want error containing %q, got %v", tc.name, tc.want, err)
		}
		if _, err := New(context.Background(), tc.cfg); err == nil {
			t.Errorf("%s: New should fail", tc.name)
		}
	}
	if err := (Config{Provider: "local", Local: good}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestConfigYAML(t *testing.T) {
	key := mustKey(t)
	src := `
provider: local
decrypt_providers: [vault]
dek_ttl: 30m
dek_max_uses: 1000
reject_plaintext: true
timeout: 5s
local:
  primary: k2
  keys:
    k1: ` + key + `
    k2: ` + key + `
vault:
  address: http://127.0.0.1:8200
  token: root
  key_name: tenarium
  mount_path: transit
aws_kms:
  key_id: alias/tenarium
  region: eu-west-1
gcp_kms:
  key_name: projects/p/locations/global/keyRings/r/cryptoKeys/k
azure_key_vault:
  vault_url: https://v.vault.azure.net
  key_name: k
`
	var c Config
	if err := yaml.Unmarshal([]byte(src), &c); err != nil {
		t.Fatal(err)
	}
	if c.DEKTTL != 30*time.Minute || c.Timeout != 5*time.Second || c.DEKMaxUses != 1000 || !c.RejectPlaintext {
		t.Fatalf("scalars: %+v", c)
	}
	if c.Local.Primary != "k2" || len(c.Local.Keys) != 2 || c.Vault.KeyName != "tenarium" ||
		c.AWSKMS.Region != "eu-west-1" || c.GCPKMS.KeyName == "" || c.AzureKeyVault.KeyName != "k" ||
		len(c.DecryptProviders) != 1 {
		t.Fatalf("sections: %+v", c)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}
