package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/store/memory"
)

func TestPasswordHashing(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("hash format: %s", h)
	}
	if err := VerifyPassword(h, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPassword(h, "wrong"); !errors.Is(err, ErrMismatch) {
		t.Fatalf("wrong password: %v", err)
	}
	if h2, _ := HashPassword("correct horse battery staple"); h2 == h {
		t.Fatal("salt not random")
	}
	for _, bad := range []string{"", "$bcrypt$x", "$argon2id$v=19$m=1,t=1,p=1$!!$!!"} {
		if err := VerifyPassword(bad, "x"); err == nil {
			t.Errorf("malformed hash %q accepted", bad)
		}
	}
}

func TestPolicy(t *testing.T) {
	p := Policy{MinLength: 12}
	for pw, ok := range map[string]bool{
		"short":                       false,
		"Password123":                 false,
		"changeme123":                 false,
		"ada@example.com":             false,
		"a perfectly fine passphrase": true,
	} {
		if err := p.Check(pw, "ada@example.com"); (err == nil) != ok {
			t.Errorf("%q: %v", pw, err)
		}
	}
}

func TestTokens(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	iss := NewIssuer(s, "https://tenarium.test/", "tenarium", time.Minute)
	if err := iss.Init(ctx); err != nil {
		t.Fatal(err)
	}
	tok, _, err := iss.Sign("user-1", "ada@example.com", "Ada", "tenant-1", []string{"owner"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := iss.Verify(tok)
	if err != nil || c.Subject != "user-1" || c.TenantID != "tenant-1" || c.Roles[0] != "owner" || c.Issuer != "https://tenarium.test" {
		t.Fatalf("verify: %+v %v", c, err)
	}

	// A second replica sharing the store verifies the same token.
	other := NewIssuer(s, "https://tenarium.test", "tenarium", time.Minute)
	if err := other.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := other.Verify(tok); err != nil {
		t.Fatalf("replica verify: %v", err)
	}

	// After rotation old tokens still verify and new ones use the new key.
	if err := iss.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := iss.Verify(tok); err != nil {
		t.Fatalf("old token after rotation: %v", err)
	}

	if _, err := iss.Verify("not-a-jwt"); !errors.Is(err, ErrForeignToken) {
		t.Fatalf("garbage: %v", err)
	}
	foreign := NewIssuer(memory.New(), "https://other.test", "tenarium", time.Minute)
	_ = foreign.Init(ctx)
	ftok, _, _ := foreign.Sign("x", "", "", "", nil)
	if _, err := iss.Verify(ftok); !errors.Is(err, ErrForeignToken) {
		t.Fatalf("other issuer: %v", err)
	}
	// Same issuer name, different keys: a forgery, not a foreign token.
	forger := NewIssuer(memory.New(), "https://tenarium.test", "tenarium", time.Minute)
	_ = forger.Init(ctx)
	forged, _, _ := forger.Sign("admin", "", "", "", []string{"admin"})
	if _, err := iss.Verify(forged); err == nil || errors.Is(err, ErrForeignToken) {
		t.Fatalf("forged token: %v", err)
	}

	expired := NewIssuer(s, "https://tenarium.test", "tenarium", time.Minute)
	_ = expired.Init(ctx)
	expired.now = func() time.Time { return time.Now().Add(-time.Hour) }
	old, _, _ := expired.Sign("u", "", "", "", nil)
	if _, err := iss.Verify(old); err == nil {
		t.Fatal("expired token accepted")
	}
	if !strings.Contains(string(iss.JWKS()), `"kty":"EC"`) || !strings.Contains(string(iss.Discovery()), "jwks.json") {
		t.Fatal("jwks/discovery")
	}
}

func TestOpaqueTokens(t *testing.T) {
	a, ha := NewToken()
	b, _ := NewToken()
	if a == b || HashToken(a) != ha || len(a) < 40 {
		t.Fatal("tokens")
	}
}
