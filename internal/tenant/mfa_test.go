package tenant

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/identity"
	"github.com/AimTune/tenarium/internal/store/memory"
)

func TestMFADisableAndRegenerate(t *testing.T) {
	ctx := context.Background()
	svc, _ := newUserService(t, memory.New(), nil, nil)
	now := time.Unix(1_800_000_000, 0).UTC()
	svc.now = func() time.Time { return now }
	u, err := svc.CreateUser(ctx, UserInput{Email: "ann@example.com", Password: goodPassword, Roles: []string{"admin"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.DisableMFA(ctx, u.ID, "123456"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("disable without mfa: %v", err)
	}
	if _, err := svc.ConfirmTOTP(ctx, u.ID, "123456"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("confirm without enrollment: %v", err)
	}
	enr, err := svc.BeginTOTP(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	// A second enrollment replaces the unconfirmed one.
	enr2, _ := svc.BeginTOTP(ctx, u.ID)
	if enr2.Secret == enr.Secret {
		t.Fatal("secret reused")
	}
	code := func(secret string, offset int64) string {
		c, _ := identity.TOTPCode(secret, identity.TOTPStep(now)+offset)
		return c
	}
	if _, err := svc.ConfirmTOTP(ctx, u.ID, code(enr.Secret, 0)); !errors.Is(err, ErrInvalidOTP) {
		t.Fatalf("confirm with replaced secret: %v", err)
	}
	codes, err := svc.ConfirmTOTP(ctx, u.ID, code(enr2.Secret, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.DisableMFA(ctx, u.ID, ""); !errors.Is(err, ErrMFARequired) {
		t.Fatalf("disable without code: %v", err)
	}
	fresh, err := svc.RegenerateRecoveryCodes(ctx, u.ID, codes[0])
	if err != nil || len(fresh) != 10 {
		t.Fatalf("regenerate: %v %v", fresh, err)
	}
	if err := svc.DisableMFA(ctx, u.ID, codes[1]); !errors.Is(err, ErrInvalidOTP) {
		t.Fatalf("old recovery code still valid: %v", err)
	}
	if err := svc.DisableMFA(ctx, u.ID, code(enr2.Secret, 1)); err != nil {
		t.Fatal(err)
	}
	if st, _ := svc.MFAStatus(ctx, u.ID); st.Enabled || st.Pending {
		t.Fatalf("status after disable: %+v", st)
	}
	if _, err := svc.Login(ctx, "ann@example.com", goodPassword, ""); err != nil {
		t.Fatalf("login after disable: %v", err)
	}
}
