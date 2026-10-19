package encrypted

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/secrets"
	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/internal/store/memory"
	"github.com/AimTune/tenarium/internal/store/storetest"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/google/uuid"
)

func keyring(t *testing.T) secrets.Keyring {
	t.Helper()
	k, err := secrets.GenerateLocalKey()
	if err != nil {
		t.Fatal(err)
	}
	kr, err := secrets.New(context.Background(), secrets.Config{Provider: "local",
		Local: secrets.LocalConfig{Keys: map[string]string{"k1": k}, Primary: "k1"}})
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

// The wrapper must behave exactly like the store it wraps.
func TestConformance(t *testing.T) {
	kr := keyring(t)
	storetest.Run(t, func(t *testing.T) store.Store { return Wrap(memory.New(), kr) })
}

func TestSecretsEncryptedAtRest(t *testing.T) {
	ctx := context.Background()
	raw := memory.New()
	s := Wrap(raw, keyring(t))
	now := time.Now().UTC()

	tn := sdk.Tenant{ID: uuid.NewString(), Slug: "acme", Name: "Acme", Status: sdk.StatusActive, Version: 1, CreatedAt: now, UpdatedAt: now}
	w := store.Webhook{ID: uuid.NewString(), TenantID: tn.ID, URL: "https://x", Secret: "whsec_plain", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := s.InTx(ctx, func(tx store.Tx) error {
		if err := tx.CreateTenant(ctx, tn); err != nil {
			return err
		}
		return tx.CreateWebhook(ctx, w)
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddSigningKey(ctx, store.SigningKey{ID: "k", Algorithm: "ES256", PrivatePEM: []byte("-----PEM-----"), CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSSOConnection(ctx, store.SSOConnection{TenantID: tn.ID, Issuer: "https://idp", ClientSecret: "sso-secret", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}

	// What the database holds is ciphertext...
	rw, _ := raw.GetWebhook(ctx, w.ID)
	rk, _ := raw.ListSigningKeys(ctx)
	rs, _ := raw.GetSSOConnection(ctx, tn.ID)
	for _, v := range []string{rw.Secret, string(rk[0].PrivatePEM), rs.ClientSecret} {
		if !strings.HasPrefix(v, "enc:v1:") {
			t.Fatalf("stored in plaintext: %q", v)
		}
	}
	// ...and the application reads plaintext.
	if got, _ := s.GetWebhook(ctx, w.ID); got.Secret != "whsec_plain" {
		t.Fatalf("webhook secret: %q", got.Secret)
	}
	if ks, _ := s.ListSigningKeys(ctx); string(ks[0].PrivatePEM) != "-----PEM-----" {
		t.Fatal("signing key not decrypted")
	}
	if c, _ := s.GetSSOConnection(ctx, tn.ID); c.ClientSecret != "sso-secret" {
		t.Fatal("sso secret not decrypted")
	}
	// Ciphertext moved to another row does not decrypt (AAD binding).
	w2 := rw
	w2.ID = uuid.NewString()
	_ = raw.InTx(ctx, func(tx store.Tx) error { return tx.CreateWebhook(ctx, w2) })
	if _, err := s.GetWebhook(ctx, w2.ID); err == nil {
		t.Fatal("swapped ciphertext decrypted")
	}
	// Rows written before encryption was enabled still read.
	legacy := store.Webhook{ID: uuid.NewString(), TenantID: tn.ID, URL: "https://y", Secret: "old", CreatedAt: now, UpdatedAt: now}
	_ = raw.InTx(ctx, func(tx store.Tx) error { return tx.CreateWebhook(ctx, legacy) })
	if got, err := s.GetWebhook(ctx, legacy.ID); err != nil || got.Secret != "old" {
		t.Fatalf("legacy plaintext: %+v %v", got, err)
	}
}

func TestKVEncryptedAtRest(t *testing.T) {
	ctx := context.Background()
	raw := memory.New()
	s := Wrap(raw, keyring(t))
	if err := s.KVPut(ctx, "certs/acme_account+key", []byte("-----BEGIN EC PRIVATE KEY-----")); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.KVPutIfAbsent(ctx, "certs/lock", []byte(`{"owner":"a"}`)); !ok || err != nil {
		t.Fatalf("put if absent: %v %v", ok, err)
	}
	for _, k := range []string{"certs/acme_account+key", "certs/lock"} {
		stored, _ := raw.KVGet(ctx, k)
		if !strings.HasPrefix(string(stored), "enc:") {
			t.Fatalf("%s stored in plaintext: %q", k, stored)
		}
	}
	if v, err := s.KVGet(ctx, "certs/acme_account+key"); err != nil || string(v) != "-----BEGIN EC PRIVATE KEY-----" {
		t.Fatalf("read back: %q %v", v, err)
	}
	// Values written before encryption was configured still read.
	if err := raw.KVPut(ctx, "certs/old", []byte("plain")); err != nil {
		t.Fatal(err)
	}
	if v, err := s.KVGet(ctx, "certs/old"); err != nil || string(v) != "plain" {
		t.Fatalf("legacy value: %q %v", v, err)
	}
}

func TestReencrypt(t *testing.T) {
	ctx := context.Background()
	raw := memory.New()
	k1, _ := secrets.GenerateLocalKey()
	k2, _ := secrets.GenerateLocalKey()
	local := func(primary string) secrets.Keyring {
		kr, err := secrets.New(ctx, secrets.Config{Provider: "local",
			Local: secrets.LocalConfig{Keys: map[string]string{"k1": k1, "k2": k2}, Primary: primary}})
		if err != nil {
			t.Fatal(err)
		}
		return kr
	}
	s := Wrap(raw, local("k1"))
	// Values written before encryption, and values under the old key.
	if err := raw.KVPut(ctx, "certs/legacy", []byte("plain cert")); err != nil {
		t.Fatal(err)
	}
	if err := s.KVPut(ctx, "certs/a", []byte("cert a")); err != nil {
		t.Fatal(err)
	}
	if err := s.AddSigningKey(ctx, store.SigningKey{ID: "k1", Algorithm: "ES256", PrivatePEM: []byte("pem"), CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	u := sdk.User{ID: "u1", Email: "u@example.com", Status: sdk.UserActive, Version: 1}
	if err := raw.InTx(ctx, func(tx store.Tx) error { return tx.CreateUser(ctx, u) }); err != nil {
		t.Fatal(err)
	}
	if err := s.PutMFA(ctx, store.MFA{UserID: "u1", TOTPSecret: "JBSWY3DPEHPK3PXP"}); err != nil {
		t.Fatal(err)
	}

	// k2 becomes primary; k1 still decrypts the old values.
	s2 := Wrap(raw, local("k2")).(*Store)
	rep, err := s2.Reencrypt(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Rewritten["kv"] != 2 || rep.Rewritten["signing_keys"] != 1 || rep.Rewritten["mfa"] != 1 {
		t.Fatalf("first run: %+v", rep)
	}
	if rep, _ = s2.Reencrypt(ctx); len(rep.Rewritten) != 0 || rep.Current["kv"] != 2 {
		t.Fatalf("second run should find everything current: %+v", rep)
	}
	if v, err := s2.KVGet(ctx, "certs/legacy"); err != nil || string(v) != "plain cert" {
		t.Fatalf("legacy value: %q %v", v, err)
	}
	if m, err := s2.GetMFA(ctx, "u1"); err != nil || m.TOTPSecret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("mfa: %+v %v", m, err)
	}
}
