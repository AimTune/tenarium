package encrypted

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/AimTune/tenarium/internal/secrets"
	"github.com/AimTune/tenarium/internal/store"
)

// ReplaceSigningKeyPEM takes plaintext PEMs, like the rest of the wrapper.
func (s *Store) ReplaceSigningKeyPEM(ctx context.Context, id string, old, next []byte) error {
	keys, err := s.Store.ListSigningKeys(ctx)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if k.ID != id {
			continue
		}
		cur, err := s.open(ctx, string(k.PrivatePEM), "signing_key:"+id)
		if err != nil {
			return err
		}
		if cur != string(old) {
			return store.ErrConflict
		}
		sealed, err := s.seal(ctx, string(next), "signing_key:"+id)
		if err != nil {
			return err
		}
		return s.Store.ReplaceSigningKeyPEM(ctx, id, k.PrivatePEM, []byte(sealed))
	}
	return store.ErrNotFound
}

// KVCompareAndSwap compares and writes plaintext values.
func (s *Store) KVCompareAndSwap(ctx context.Context, key string, old, next []byte) (bool, error) {
	raw, err := s.Store.KVGet(ctx, key)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	cur, err := s.kr.Decrypt(ctx, string(raw), "kv:"+key)
	if err != nil {
		return false, err
	}
	if !bytes.Equal(cur, old) {
		return false, nil
	}
	sealed, err := s.sealKV(ctx, key, next)
	if err != nil {
		return false, err
	}
	return s.Store.KVCompareAndSwap(ctx, key, raw, sealed)
}

// Report counts what Reencrypt did per kind of secret.
type Report struct {
	Rewritten map[string]int `json:"rewritten"`
	Current   map[string]int `json:"current"`
	// Skipped are values changed concurrently; run Reencrypt again.
	Skipped map[string]int `json:"skipped,omitempty"`
}

func (r *Report) count(kind string, changed bool) {
	if changed {
		r.Rewritten[kind]++
	} else {
		r.Current[kind]++
	}
}

// Reencrypt rewrites every stored secret under the keyring's current
// provider and key: after a key rotation (so the old key can be removed),
// a provider migration, or to encrypt values written before encryption
// was enabled. Values already current are left alone, so it can be run
// repeatedly. Signing keys and key-value entries are swapped only if
// unchanged since they were read; MFA, webhook and SSO secrets are
// rewritten in place, so run it when those are not being edited (a user
// enrolling two-factor at the same moment could lose the new secret).
func (s *Store) Reencrypt(ctx context.Context) (Report, error) {
	rep := Report{Rewritten: map[string]int{}, Current: map[string]int{}, Skipped: map[string]int{}}
	rotate := func(v, aad string) (string, bool, error) {
		if v == "" {
			return v, false, nil
		}
		return secrets.Rotate(ctx, s.kr, v, aad)
	}

	keys, err := s.Store.ListSigningKeys(ctx)
	if err != nil {
		return rep, err
	}
	for _, k := range keys {
		next, changed, err := rotate(string(k.PrivatePEM), "signing_key:"+k.ID)
		if err != nil {
			return rep, fmt.Errorf("signing key %s: %w", k.ID, err)
		}
		if changed {
			if err := s.Store.ReplaceSigningKeyPEM(ctx, k.ID, k.PrivatePEM, []byte(next)); errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) {
				rep.Skipped["signing_keys"]++
				continue
			} else if err != nil {
				return rep, err
			}
		}
		rep.count("signing_keys", changed)
	}

	kvKeys, err := s.Store.KVKeys(ctx, "")
	if err != nil {
		return rep, err
	}
	for _, key := range kvKeys {
		raw, err := s.Store.KVGet(ctx, key)
		if errors.Is(err, store.ErrNotFound) {
			continue
		} else if err != nil {
			return rep, err
		}
		next, changed, err := rotate(string(raw), "kv:"+key)
		if err != nil {
			return rep, fmt.Errorf("kv %s: %w", key, err)
		}
		if changed {
			if ok, err := s.Store.KVCompareAndSwap(ctx, key, raw, []byte(next)); err != nil {
				return rep, err
			} else if !ok {
				rep.Skipped["kv"]++
				continue
			}
		}
		rep.count("kv", changed)
	}

	// MFA secrets, per user.
	after := ""
	for {
		users, err := s.Store.ListUsers(ctx, store.ListUsersQuery{After: after, Limit: 500})
		if err != nil {
			return rep, err
		}
		for _, u := range users {
			m, err := s.Store.GetMFA(ctx, u.ID)
			if errors.Is(err, store.ErrNotFound) {
				continue
			} else if err != nil {
				return rep, err
			}
			next, changed, err := rotate(m.TOTPSecret, "mfa:"+m.UserID)
			if err != nil {
				return rep, fmt.Errorf("mfa of %s: %w", u.ID, err)
			}
			if changed {
				m.TOTPSecret = next
				if err := s.Store.PutMFA(ctx, m); err != nil {
					return rep, err
				}
			}
			rep.count("mfa", changed)
		}
		if len(users) < 500 {
			break
		}
		after = users[len(users)-1].ID
	}

	// Webhook and SSO secrets, per tenant (deleted ones too: their rows
	// stay until purged).
	after = ""
	for {
		ts, err := s.Store.ListTenants(ctx, store.ListTenantsQuery{After: after, Limit: 500, IncludeDeleted: true})
		if err != nil {
			return rep, err
		}
		for _, t := range ts {
			hooks, err := s.Store.ListWebhooks(ctx, t.ID)
			if err != nil {
				return rep, err
			}
			for _, w := range hooks {
				next, changed, err := rotate(w.Secret, "webhook:"+w.ID)
				if err != nil {
					return rep, fmt.Errorf("webhook %s: %w", w.ID, err)
				}
				if changed {
					w.Secret = next
					if err := s.Store.InTx(ctx, func(tx store.Tx) error { return tx.UpdateWebhook(ctx, w) }); err != nil {
						return rep, err
					}
				}
				rep.count("webhooks", changed)
			}
			c, err := s.Store.GetSSOConnection(ctx, t.ID)
			if errors.Is(err, store.ErrNotFound) {
				continue
			} else if err != nil {
				return rep, err
			}
			next, changed, err := rotate(c.ClientSecret, "sso:"+c.TenantID)
			if err != nil {
				return rep, fmt.Errorf("sso of %s: %w", t.ID, err)
			}
			if changed {
				c.ClientSecret = next
				if err := s.Store.PutSSOConnection(ctx, c); err != nil {
					return rep, err
				}
			}
			rep.count("sso", changed)
		}
		if len(ts) < 500 {
			break
		}
		after = ts[len(ts)-1].ID
	}
	if len(rep.Skipped) == 0 {
		rep.Skipped = nil
	}
	return rep, nil
}
