package tenant

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/identity"
	"github.com/AimTune/tenarium/internal/store/memory"
	"github.com/AimTune/tenarium/pkg/sdk"
)

var anyLink = regexp.MustCompile(`/ui/#/(magic|confirm-email)/([A-Za-z0-9_.-]+)`)

func (m *captureMailer) last(t *testing.T, tag string) (sdk.Message, string) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.sent) - 1; i >= 0; i-- {
		if m.sent[i].Tag == tag {
			mm := anyLink.FindStringSubmatch(m.sent[i].Text)
			if mm == nil {
				return m.sent[i], ""
			}
			return m.sent[i], mm[2]
		}
	}
	t.Fatalf("no %s email", tag)
	return sdk.Message{}, ""
}

func TestMagicLinks(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	svc, mailer := newUserService(t, s, &UserOptions{MagicLinkTTL: 15 * time.Minute}, nil)
	u, _ := svc.CreateUser(ctx, UserInput{Email: "ann@example.com", Password: goodPassword, Roles: []string{"admin"}})

	if err := svc.RequestMagicLink(ctx, "nobody@example.com", ""); err != nil || len(mailer.sent) != 0 {
		t.Fatalf("unknown address: %v, %d emails", err, len(mailer.sent))
	}
	if err := svc.RequestMagicLink(ctx, "ann@example.com", ""); err != nil {
		t.Fatal(err)
	}
	_, token := mailer.last(t, tokenMagicLink)
	if _, err := svc.SignInWithMagicLink(ctx, token+"x", ""); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("tampered: %v", err)
	}
	pair, err := svc.SignInWithMagicLink(ctx, token, "")
	if err != nil || pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatalf("sign in: %+v %v", pair, err)
	}
	if _, err := svc.SignInWithMagicLink(ctx, token, ""); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("reused: %v", err)
	}
	if got, _ := svc.GetUser(ctx, u.ID); !got.EmailVerified {
		t.Fatal("email not marked verified")
	}

	// With 2FA the link needs a code, and survives a request without one.
	enr, _ := svc.BeginTOTP(ctx, u.ID)
	code := func() string { c, _ := identity.TOTPCode(enr.Secret, identity.TOTPStep(time.Now())); return c }
	recovery, err := svc.ConfirmTOTP(ctx, u.ID, code())
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.RequestMagicLink(ctx, "ann@example.com", ""); err != nil {
		t.Fatal(err)
	}
	_, token = mailer.last(t, tokenMagicLink)
	if _, err := svc.SignInWithMagicLink(ctx, token, ""); !errors.Is(err, ErrMFARequired) {
		t.Fatalf("without code: %v", err)
	}
	// The TOTP code was just spent on enrollment; use a recovery code.
	if _, err := svc.SignInWithMagicLink(ctx, token, recovery[0]); err != nil {
		t.Fatalf("with code: %v", err)
	}

	off, _ := newUserService(t, memory.New(), nil, nil)
	if err := off.RequestMagicLink(ctx, "ann@example.com", ""); !errors.Is(err, ErrMagicLinksDisabled) {
		t.Fatalf("disabled: %v", err)
	}
}

func TestEmailChange(t *testing.T) {
	ctx := context.Background()
	svc, mailer := newUserService(t, memory.New(), nil, nil)
	u, _ := svc.CreateUser(ctx, UserInput{Email: "ann@example.com", Password: goodPassword, Roles: []string{"admin"}})
	if _, err := svc.CreateUser(ctx, UserInput{Email: "taken@example.com", Password: goodPassword, Roles: []string{"admin"}}); err != nil {
		t.Fatal(err)
	}

	if err := svc.RequestEmailChange(ctx, u.ID, "new@example.com", "wrong password!!"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	var ve *ValidationError
	if err := svc.RequestEmailChange(ctx, u.ID, "taken@example.com", goodPassword); !errors.As(err, &ve) {
		t.Fatalf("taken address: %v", err)
	}
	if err := svc.RequestEmailChange(ctx, u.ID, "not an email", goodPassword); !errors.As(err, &ve) {
		t.Fatalf("invalid address: %v", err)
	}
	if err := svc.RequestEmailChange(ctx, u.ID, "new@example.com", goodPassword); err != nil {
		t.Fatal(err)
	}
	msg, token := mailer.last(t, tokenEmailChange)
	if msg.To[0] != "new@example.com" {
		t.Fatalf("confirmation sent to %v", msg.To)
	}
	if got, _ := svc.GetUser(ctx, u.ID); got.Email != "ann@example.com" {
		t.Fatal("email changed before confirmation")
	}
	got, err := svc.ConfirmEmailChange(ctx, token)
	if err != nil || got.Email != "new@example.com" || !got.EmailVerified {
		t.Fatalf("confirm: %+v %v", got, err)
	}
	notice, _ := mailer.last(t, noticeEmailChanged)
	if notice.To[0] != "ann@example.com" || !strings.Contains(notice.Text, "new@example.com") {
		t.Fatalf("notice: %+v", notice)
	}
	if _, err := svc.ConfirmEmailChange(ctx, token); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("reused: %v", err)
	}
}

func TestBreachedPasswordCheck(t *testing.T) {
	ctx := context.Background()
	breached := map[string]bool{"correct horse battery staple": true}
	failing := false
	svc, _ := newUserService(t, memory.New(), &UserOptions{BreachCheck: func(_ context.Context, pw string) (bool, error) {
		if failing {
			return false, errors.New("service down")
		}
		return breached[pw], nil
	}}, nil)
	var ve *ValidationError
	if _, err := svc.CreateUser(ctx, UserInput{Email: "a@example.com", Password: "correct horse battery staple"}); !errors.As(err, &ve) {
		t.Fatalf("breached password accepted: %v", err)
	}
	if _, err := svc.CreateUser(ctx, UserInput{Email: "a@example.com", Password: goodPassword}); err != nil {
		t.Fatal(err)
	}
	failing = true
	if _, err := svc.CreateUser(ctx, UserInput{Email: "b@example.com", Password: "correct horse battery staple"}); err != nil {
		t.Fatalf("outage should fail open: %v", err)
	}
}

func TestSessionList(t *testing.T) {
	ctx := context.Background()
	svc, _ := newUserService(t, memory.New(), nil, nil)
	u, _ := svc.CreateUser(ctx, UserInput{Email: "ann@example.com", Password: goodPassword, Roles: []string{"admin"}})
	phone := WithClient(ctx, ClientInfo{UserAgent: "Phone", IP: "198.51.100.7"})
	p1, err := svc.SignIn(phone, LoginInput{Email: "ann@example.com", Password: goodPassword})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SignIn(WithClient(ctx, ClientInfo{UserAgent: "Laptop"}), LoginInput{Email: "ann@example.com", Password: goodPassword}); err != nil {
		t.Fatal(err)
	}
	ss, err := svc.ListSessions(ctx, u.ID)
	if err != nil || len(ss) != 2 {
		t.Fatalf("sessions: %+v %v", ss, err)
	}
	var phoneID string
	for _, x := range ss {
		if x.UserAgent == "Phone" && x.IP == "198.51.100.7" {
			phoneID = x.ID
		}
	}
	if phoneID == "" {
		t.Fatalf("client info not recorded: %+v", ss)
	}
	if err := svc.RevokeSession(ctx, u.ID, phoneID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Refresh(ctx, p1.RefreshToken); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("revoked session refreshed: %v", err)
	}
	if ss, _ := svc.ListSessions(ctx, u.ID); len(ss) != 1 || ss[0].UserAgent != "Laptop" {
		t.Fatalf("after revoke: %+v", ss)
	}
}

func TestSocialSession(t *testing.T) {
	ctx := context.Background()
	svc, _ := newUserService(t, memory.New(), nil, nil)
	id := SocialIdentity{Provider: "google", Subject: "123", Email: "new@example.com", Name: "New"}
	if _, err := svc.SocialSession(ctx, id, ""); !errors.Is(err, ErrSSORejected) {
		t.Fatalf("unknown user without auto-create: %v", err)
	}
	id.AutoCreate = true
	// Created users have no roles yet, so they need a tenant to sign in to.
	if _, err := svc.SocialSession(ctx, id, ""); !errors.Is(err, ErrTenantRequired) {
		t.Fatalf("auto-created: %v", err)
	}
	u, err := svc.GetUser(ctx, "new@example.com")
	if err != nil || !u.EmailVerified || u.Attributes["social_provider"] != "google" {
		t.Fatalf("created user: %+v %v", u, err)
	}

	admin, _ := svc.CreateUser(ctx, UserInput{Email: "admin@example.com", Password: goodPassword, Roles: []string{"admin"}})
	if pair, err := svc.SocialSession(ctx, SocialIdentity{Provider: "github", Email: "admin@example.com"}, ""); err != nil || pair.AccessToken == "" {
		t.Fatalf("existing user: %+v %v", pair, err)
	}
	enr, _ := svc.BeginTOTP(ctx, admin.ID)
	c, _ := identity.TOTPCode(enr.Secret, identity.TOTPStep(time.Now()))
	if _, err := svc.ConfirmTOTP(ctx, admin.ID, c); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SocialSession(ctx, SocialIdentity{Provider: "github", Email: "admin@example.com"}, ""); !errors.Is(err, ErrMFARequired) {
		t.Fatalf("two-factor user: %v", err)
	}
	if _, err := svc.DisableUser(ctx, admin.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SocialSession(ctx, SocialIdentity{Provider: "github", Email: "admin@example.com"}, ""); !errors.Is(err, ErrSSORejected) {
		t.Fatalf("disabled user: %v", err)
	}
}
