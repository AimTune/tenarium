// Package encrypted wraps a store.Store so that secrets are encrypted at
// rest with a secrets.Keyring (envelope encryption, KMS-backed): token
// signing keys, TOTP secrets, webhook secrets and SSO client secrets.
// Each value is bound to its row (additional authenticated data), and
// values written before encryption was enabled are still read as-is.
package encrypted

import (
	"context"

	"github.com/AimTune/tenarium/internal/secrets"
	"github.com/AimTune/tenarium/internal/store"
)

// Wrap returns s with secret fields encrypted by kr. The result keeps
// implementing store.Notifier when s does.
func Wrap(s store.Store, kr secrets.Keyring) store.Store {
	e := &Store{Store: s, kr: kr}
	if n, ok := s.(store.Notifier); ok {
		return &notifier{Store: e, Notifier: n}
	}
	return e
}

type notifier struct {
	*Store
	store.Notifier
}

type Store struct {
	store.Store
	kr secrets.Keyring
}

func (s *Store) seal(ctx context.Context, v, aad string) (string, error) {
	if v == "" {
		return "", nil
	}
	return s.kr.Encrypt(ctx, []byte(v), aad)
}

func (s *Store) open(ctx context.Context, v, aad string) (string, error) {
	if v == "" {
		return "", nil
	}
	b, err := s.kr.Decrypt(ctx, v, aad)
	return string(b), err
}

// --- signing keys ---------------------------------------------------------------

func (s *Store) AddSigningKey(ctx context.Context, k store.SigningKey) error {
	sealed, err := s.seal(ctx, string(k.PrivatePEM), "signing_key:"+k.ID)
	if err != nil {
		return err
	}
	k.PrivatePEM = []byte(sealed)
	return s.Store.AddSigningKey(ctx, k)
}

func (s *Store) ListSigningKeys(ctx context.Context) ([]store.SigningKey, error) {
	keys, err := s.Store.ListSigningKeys(ctx)
	if err != nil {
		return nil, err
	}
	for i, k := range keys {
		pem, err := s.open(ctx, string(k.PrivatePEM), "signing_key:"+k.ID)
		if err != nil {
			return nil, err
		}
		keys[i].PrivatePEM = []byte(pem)
	}
	return keys, nil
}

// --- MFA ------------------------------------------------------------------------

func (s *Store) PutMFA(ctx context.Context, m store.MFA) error {
	sealed, err := s.seal(ctx, m.TOTPSecret, "mfa:"+m.UserID)
	if err != nil {
		return err
	}
	m.TOTPSecret = sealed
	return s.Store.PutMFA(ctx, m)
}

func (s *Store) GetMFA(ctx context.Context, userID string) (store.MFA, error) {
	m, err := s.Store.GetMFA(ctx, userID)
	if err != nil {
		return m, err
	}
	m.TOTPSecret, err = s.open(ctx, m.TOTPSecret, "mfa:"+m.UserID)
	return m, err
}

// --- webhooks -------------------------------------------------------------------

func (s *Store) openWebhook(ctx context.Context, w store.Webhook) (store.Webhook, error) {
	var err error
	w.Secret, err = s.open(ctx, w.Secret, "webhook:"+w.ID)
	return w, err
}

func (s *Store) GetWebhook(ctx context.Context, id string) (store.Webhook, error) {
	w, err := s.Store.GetWebhook(ctx, id)
	if err != nil {
		return w, err
	}
	return s.openWebhook(ctx, w)
}

func (s *Store) ListWebhooks(ctx context.Context, tenantID string) ([]store.Webhook, error) {
	ws, err := s.Store.ListWebhooks(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for i := range ws {
		if ws[i], err = s.openWebhook(ctx, ws[i]); err != nil {
			return nil, err
		}
	}
	return ws, nil
}

// --- SSO ------------------------------------------------------------------------

func (s *Store) openSSO(ctx context.Context, c store.SSOConnection) (store.SSOConnection, error) {
	var err error
	c.ClientSecret, err = s.open(ctx, c.ClientSecret, "sso:"+c.TenantID)
	return c, err
}

func (s *Store) GetSSOConnection(ctx context.Context, tenantID string) (store.SSOConnection, error) {
	c, err := s.Store.GetSSOConnection(ctx, tenantID)
	if err != nil {
		return c, err
	}
	return s.openSSO(ctx, c)
}

func (s *Store) FindSSOConnection(ctx context.Context, domain string) (store.SSOConnection, error) {
	c, err := s.Store.FindSSOConnection(ctx, domain)
	if err != nil {
		return c, err
	}
	return s.openSSO(ctx, c)
}

func (s *Store) PutSSOConnection(ctx context.Context, c store.SSOConnection) error {
	sealed, err := s.seal(ctx, c.ClientSecret, "sso:"+c.TenantID)
	if err != nil {
		return err
	}
	c.ClientSecret = sealed
	return s.Store.PutSSOConnection(ctx, c)
}

// --- transactions -----------------------------------------------------------------

func (s *Store) InTx(ctx context.Context, fn func(tx store.Tx) error) error {
	return s.Store.InTx(ctx, func(tx store.Tx) error { return fn(&encTx{Tx: tx, s: s}) })
}

type encTx struct {
	store.Tx
	s *Store
}

func (t *encTx) CreateWebhook(ctx context.Context, w store.Webhook) error {
	sealed, err := t.s.seal(ctx, w.Secret, "webhook:"+w.ID)
	if err != nil {
		return err
	}
	w.Secret = sealed
	return t.Tx.CreateWebhook(ctx, w)
}

func (t *encTx) UpdateWebhook(ctx context.Context, w store.Webhook) error {
	sealed, err := t.s.seal(ctx, w.Secret, "webhook:"+w.ID)
	if err != nil {
		return err
	}
	w.Secret = sealed
	return t.Tx.UpdateWebhook(ctx, w)
}

// --- key-value entries (ACME account keys and certificates) ----------------------

func (s *Store) sealKV(ctx context.Context, key string, v []byte) ([]byte, error) {
	if len(v) == 0 {
		return v, nil
	}
	sealed, err := s.kr.Encrypt(ctx, v, "kv:"+key)
	return []byte(sealed), err
}

func (s *Store) KVGet(ctx context.Context, key string) ([]byte, error) {
	v, err := s.Store.KVGet(ctx, key)
	if err != nil || len(v) == 0 {
		return v, err
	}
	return s.kr.Decrypt(ctx, string(v), "kv:"+key)
}

func (s *Store) KVPut(ctx context.Context, key string, value []byte) error {
	sealed, err := s.sealKV(ctx, key, value)
	if err != nil {
		return err
	}
	return s.Store.KVPut(ctx, key, sealed)
}

func (s *Store) KVPutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	sealed, err := s.sealKV(ctx, key, value)
	if err != nil {
		return false, err
	}
	return s.Store.KVPutIfAbsent(ctx, key, sealed)
}
