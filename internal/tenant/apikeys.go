package tenant

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/AimTune/tenarium/internal/identity"
	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/google/uuid"
)

// APIKeyPrefix starts every Tenarium API key, so leaked keys are easy to
// recognize by secret scanners.
const APIKeyPrefix = "tnr_"

// API key event types.
const (
	EventAPIKeyCreated = "apikey.created"
	EventAPIKeyRevoked = "apikey.revoked"
)

// APIKeyInput creates a key.
type APIKeyInput struct {
	Name  string   `json:"name"`
	Roles []string `json:"roles"`
	// ExpiresIn is a Go duration ("720h"); empty means no expiry.
	ExpiresIn string `json:"expires_in,omitempty"`
}

// CreatedAPIKey is returned once, with the secret.
type CreatedAPIKey struct {
	store.APIKey
	Key string `json:"key"`
}

// CreateAPIKey creates a key for a tenant (tenantRef != "") or a platform
// key. A tenant-scoped caller can only grant roles it holds itself.
func (s *Service) CreateAPIKey(ctx context.Context, tenantRef string, in APIKeyInput) (CreatedAPIKey, error) {
	tenantID := ""
	if tenantRef != "" {
		t, err := s.Get(ctx, tenantRef)
		if err != nil {
			return CreatedAPIKey{}, err
		}
		if !t.IsLive() {
			return CreatedAPIKey{}, transitionErr("create API keys for", t.Status)
		}
		tenantID = t.ID
	}
	name := strings.TrimSpace(in.Name)
	if name == "" || utf8.RuneCountInString(name) > maxNameLen {
		return CreatedAPIKey{}, invalid("name", "must be 1-%d characters", maxNameLen)
	}
	if len(in.Roles) == 0 {
		return CreatedAPIKey{}, invalid("roles", "at least one role is required")
	}
	for _, r := range in.Roles {
		if !keyRe.MatchString(r) {
			return CreatedAPIKey{}, invalid("roles", "invalid role %q", r)
		}
		if tenantID != "" {
			if err := s.checkRole(ctx, tenantID, "roles", r); err != nil {
				return CreatedAPIKey{}, err
			}
		}
	}
	if p, ok := sdk.PrincipalFrom(ctx); ok && p.TenantID != "" {
		for _, r := range in.Roles {
			// Custom roles are checked by action at the API (canGrant).
			if s.roleAllowed(r) && !slices.Contains(p.Roles, r) {
				return CreatedAPIKey{}, fmt.Errorf("%w: cannot grant role %q you do not hold", sdk.ErrForbidden, r)
			}
		}
	}
	now := s.now()
	var expires *time.Time
	if in.ExpiresIn != "" {
		d, err := time.ParseDuration(in.ExpiresIn)
		if err != nil || d <= 0 {
			return CreatedAPIKey{}, invalid("expires_in", "must be a positive duration such as 720h")
		}
		e := now.Add(d)
		expires = &e
	}
	b := make([]byte, 30)
	_, _ = rand.Read(b)
	secret := APIKeyPrefix + base64.RawURLEncoding.EncodeToString(b)
	k := store.APIKey{
		ID: uuid.Must(uuid.NewV7()).String(), TenantID: tenantID, Name: name, Prefix: secret[:12],
		Hash: identity.HashToken(secret), Roles: slices.Clone(in.Roles), CreatedBy: actor(ctx),
		CreatedAt: now, ExpiresAt: expires,
	}
	err := s.store.InTx(ctx, func(tx store.Tx) error {
		if err := tx.CreateAPIKey(ctx, k); err != nil {
			return err
		}
		return s.appendEvent(ctx, tx, EventAPIKeyCreated, tenantID, "api-keys/"+k.ID, k)
	})
	if err != nil {
		return CreatedAPIKey{}, err
	}
	s.notify()
	return CreatedAPIKey{APIKey: k, Key: secret}, nil
}

// ListAPIKeys lists a tenant's keys, or platform keys for tenantRef "".
func (s *Service) ListAPIKeys(ctx context.Context, tenantRef string) ([]store.APIKey, error) {
	tenantID := ""
	if tenantRef != "" {
		t, err := s.Get(ctx, tenantRef)
		if err != nil {
			return nil, err
		}
		tenantID = t.ID
	}
	return s.store.ListAPIKeys(ctx, tenantID)
}

// RevokeAPIKey revokes a key immediately.
func (s *Service) RevokeAPIKey(ctx context.Context, tenantRef, id string) error {
	tenantID := ""
	if tenantRef != "" {
		t, err := s.Get(ctx, tenantRef)
		if err != nil {
			return err
		}
		tenantID = t.ID
	}
	err := s.store.InTx(ctx, func(tx store.Tx) error {
		k, err := tx.RevokeAPIKey(ctx, tenantID, id, s.now())
		if err != nil {
			return err
		}
		return s.appendEvent(ctx, tx, EventAPIKeyRevoked, tenantID, "api-keys/"+k.ID, k)
	})
	if err != nil {
		return err
	}
	s.notify()
	return nil
}

// ErrInvalidAPIKey is returned for unknown, revoked or expired keys.
var ErrInvalidAPIKey = errors.New("invalid API key")

// apiKeyTouches throttles last-used writes to one per key per minute.
var apiKeyTouches sync.Map

// APIKeyPrincipal authenticates a key. Keys of tenants that are no longer
// active stop working.
func (s *Service) APIKeyPrincipal(ctx context.Context, secret string) (*sdk.Principal, error) {
	k, err := s.store.GetAPIKeyByHash(ctx, identity.HashToken(secret))
	if err != nil {
		return nil, ErrInvalidAPIKey
	}
	now := s.now()
	if k.RevokedAt != nil || (k.ExpiresAt != nil && !now.Before(*k.ExpiresAt)) {
		return nil, ErrInvalidAPIKey
	}
	if k.TenantID != "" {
		t, err := s.store.GetTenant(ctx, k.TenantID)
		if err != nil || t.Status != sdk.StatusActive {
			return nil, ErrInvalidAPIKey
		}
	}
	if last, ok := apiKeyTouches.Load(k.ID); !ok || now.Sub(last.(time.Time)) > time.Minute {
		apiKeyTouches.Store(k.ID, now)
		_ = s.store.TouchAPIKey(context.WithoutCancel(ctx), k.ID, now)
	}
	return &sdk.Principal{
		Subject: k.ID, Kind: "service", TenantID: k.TenantID, Roles: slices.Clone(k.Roles),
		Claims: map[string]any{"name": k.Name, "prefix": k.Prefix},
	}, nil
}
