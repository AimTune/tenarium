package tenant

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/identity"
	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/internal/store/memory"
	"github.com/AimTune/tenarium/pkg/sdk"
)

// captureMailer records sent messages.
type captureMailer struct {
	mu   sync.Mutex
	sent []sdk.Message
}

func (m *captureMailer) Name() string { return "capture" }
func (m *captureMailer) Send(_ context.Context, msg sdk.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, msg)
	return nil
}

var linkToken = regexp.MustCompile(`/ui/#/(accept|reset)/([A-Za-z0-9_-]+)`)

// lastToken extracts the token from the last email with the given tag.
func (m *captureMailer) lastToken(t *testing.T, tag string) string {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.sent) - 1; i >= 0; i-- {
		if m.sent[i].Tag == tag {
			if mm := linkToken.FindStringSubmatch(m.sent[i].Text); mm != nil {
				return mm[2]
			}
		}
	}
	t.Fatalf("no %s email", tag)
	return ""
}

func newUserService(t *testing.T, s store.Store, opts *UserOptions, hooks HookRunner) (*Service, *captureMailer) {
	t.Helper()
	mailer := &captureMailer{}
	if opts == nil {
		opts = &UserOptions{}
	}
	opts.Mailer = mailer
	opts.Log = discard
	if opts.Issuer == nil {
		opts.Issuer = identity.NewIssuer(s, "https://tenarium.test", "tenarium", time.Minute)
		if err := opts.Issuer.Init(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	return NewService(s, Options{Users: opts, Hooks: hooks}), mailer
}

const goodPassword = "a long enough passphrase"

func TestInvitationFlowActivatesMemberships(t *testing.T) {
	ctx := sdk.WithPrincipal(context.Background(), &sdk.Principal{Subject: "admin", Authenticator: "test"})
	s := memory.New()
	svc, mailer := newUserService(t, s, nil, nil)
	a, _ := svc.Create(ctx, CreateInput{Slug: "a", Name: "A", Limits: map[string]int64{MetricMembers: 5}})
	b, _ := svc.Create(ctx, CreateInput{Slug: "b", Name: "B"})

	// Adding an unknown email creates an invited user and emails them once.
	m1, err := svc.AddMember(ctx, "a", MemberInput{Email: "ada@example.com", Role: "owner", Name: "Ada"})
	if err != nil || m1.Status != sdk.MemberInvited || m1.UserID == "" || m1.InvitedBy != "test:admin" {
		t.Fatalf("invite: %+v %v", m1, err)
	}
	m2, err := svc.AddMember(ctx, "b", MemberInput{Email: "ADA@example.com", Role: "member"})
	if err != nil || m2.UserID != m1.UserID {
		t.Fatalf("same user in second tenant: %+v %v", m2, err)
	}
	if n := len(mailer.sent); n != 1 {
		t.Fatalf("%d invitation emails, want 1", n)
	}
	if _, err := svc.AddMember(ctx, "a", MemberInput{Email: "ada@example.com", Role: "member"}); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("duplicate membership: %v", err)
	}
	if _, err := svc.AddMember(ctx, "a", MemberInput{Email: "x@example.com", Role: "god"}); err == nil {
		t.Fatal("unknown role accepted")
	}

	// Accepting sets the password, activates the user and all memberships.
	token := mailer.lastToken(t, "invitation")
	if _, err := svc.AcceptInvitation(ctx, token, "short", ""); err == nil {
		t.Fatal("weak password accepted")
	}
	u, err := svc.AcceptInvitation(ctx, token, goodPassword, "Ada L.")
	if !errors.Is(err, ErrInvalidToken) {
		// The first, failed attempt consumed the token: tokens are single-use.
		t.Fatalf("token reused after failed attempt: %+v %v", u, err)
	}
	if err := svc.ResendInvitation(ctx, m1.UserID); err != nil {
		t.Fatal(err)
	}
	u, err = svc.AcceptInvitation(ctx, mailer.lastToken(t, "invitation"), goodPassword, "Ada L.")
	if err != nil || u.Status != sdk.UserActive || !u.EmailVerified || u.Name != "Ada L." {
		t.Fatalf("accept: %+v %v", u, err)
	}
	ms, _ := svc.UserMemberships(ctx, u.ID)
	for _, m := range ms {
		if m.Status != sdk.MemberActive {
			t.Fatalf("membership not activated: %+v", m)
		}
	}
	// A new member for an active user is active immediately, without email.
	before := len(mailer.sent)
	c, _ := svc.Create(ctx, CreateInput{Slug: "c", Name: "C"})
	if m, err := svc.AddMember(ctx, c.ID, MemberInput{UserID: u.ID, Role: "viewer"}); err != nil || m.Status != sdk.MemberActive {
		t.Fatalf("existing user: %+v %v", m, err)
	}
	if len(mailer.sent) != before {
		t.Fatal("email sent for an active user")
	}
	_ = a
	_ = b
}

func TestLoginRefreshAndLockout(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	svc, _ := newUserService(t, s, &UserOptions{MaxFailures: 3, LockFor: time.Hour}, nil)
	org, _ := svc.Create(ctx, CreateInput{Slug: "org", Name: "Org"})
	admin, err := svc.CreateUser(ctx, UserInput{Email: "root@example.com", Password: goodPassword, Roles: []string{"admin"}})
	if err != nil || admin.Status != sdk.UserActive {
		t.Fatalf("create admin: %+v %v", admin, err)
	}
	member, _ := svc.CreateUser(ctx, UserInput{Email: "bob@example.com", Password: goodPassword})
	if _, err := svc.AddMember(ctx, org.ID, MemberInput{UserID: member.ID, Role: "admin"}); err != nil {
		t.Fatal(err)
	}

	// Platform login requires platform roles.
	if _, err := svc.Login(ctx, "bob@example.com", goodPassword, ""); !errors.Is(err, ErrTenantRequired) {
		t.Fatalf("platform login without roles: %v", err)
	}
	pair, err := svc.Login(ctx, "BOB@example.com", goodPassword, "org")
	if err != nil || pair.TenantID != org.ID || pair.RefreshToken == "" {
		t.Fatalf("tenant login: %+v %v", pair, err)
	}
	claims, err := svc.userOpts.Issuer.Verify(pair.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	p, err := svc.TokenPrincipal(ctx, claims)
	if err != nil || p.TenantID != org.ID || p.Roles[0] != "admin" {
		t.Fatalf("principal: %+v %v", p, err)
	}
	if _, err := svc.Login(ctx, "root@example.com", goodPassword, ""); err != nil {
		t.Fatalf("admin login: %v", err)
	}

	// Refresh rotates; replaying the old refresh token kills the session.
	next, err := svc.Refresh(ctx, pair.RefreshToken)
	if err != nil || next.RefreshToken == pair.RefreshToken {
		t.Fatalf("refresh: %v", err)
	}
	if _, err := svc.Refresh(ctx, pair.RefreshToken); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("replay: %v", err)
	}
	if _, err := svc.Refresh(ctx, next.RefreshToken); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("session must be revoked after replay: %v", err)
	}

	// Demotion takes effect on the next request, not at token expiry.
	ms, _ := svc.UserMemberships(ctx, member.ID)
	viewer := "viewer"
	if _, err := svc.UpdateMember(ctx, org.ID, ms[0].ID, MemberUpdate{Role: &viewer}); err != nil {
		t.Fatal(err)
	}
	if p, _ := svc.TokenPrincipal(ctx, claims); p.Roles[0] != "viewer" {
		t.Fatalf("roles not current: %v", p.Roles)
	}
	if _, err := svc.Suspend(ctx, org.ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.TokenPrincipal(ctx, claims); err == nil {
		t.Fatal("token for a suspended tenant still works")
	}

	// Wrong passwords lock the account; the right one then fails too.
	for range 3 {
		if _, err := svc.Login(ctx, "root@example.com", "wrong password!!", ""); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("wrong password: %v", err)
		}
	}
	if _, err := svc.Login(ctx, "root@example.com", goodPassword, ""); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("locked account: %v", err)
	}
	if _, err := svc.Login(ctx, "nobody@example.com", goodPassword, ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown user: %v", err)
	}
}

func TestDisableDeleteAndPasswordReset(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	svc, mailer := newUserService(t, s, nil, nil)
	u, _ := svc.CreateUser(ctx, UserInput{Email: "eve@example.com", Password: goodPassword, Roles: []string{"admin"}})
	pair, _ := svc.Login(ctx, "eve@example.com", goodPassword, "")
	claims, _ := svc.userOpts.Issuer.Verify(pair.AccessToken)

	if _, err := svc.DisableUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.TokenPrincipal(ctx, claims); err == nil {
		t.Fatal("disabled user's access token still works")
	}
	if _, err := svc.Refresh(ctx, pair.RefreshToken); err == nil {
		t.Fatal("disabled user's refresh token still works")
	}
	if _, err := svc.Login(ctx, "eve@example.com", goodPassword, ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("disabled login: %v", err)
	}
	if err := svc.RequestPasswordReset(ctx, "eve@example.com"); err != nil || len(mailer.sent) != 0 {
		t.Fatalf("reset for disabled user must be silent: %v %d", err, len(mailer.sent))
	}
	if _, err := svc.EnableUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}

	if err := svc.RequestPasswordReset(ctx, "unknown@example.com"); err != nil || len(mailer.sent) != 0 {
		t.Fatal("reset for unknown email must be silent")
	}
	if err := svc.RequestPasswordReset(ctx, "eve@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := svc.ResetPassword(ctx, mailer.lastToken(t, "password_reset"), "another long passphrase"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Login(ctx, "eve@example.com", "another long passphrase", ""); err != nil {
		t.Fatalf("login with new password: %v", err)
	}
	if err := svc.ChangePassword(ctx, u.ID, "wrong", "yet another passphrase"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("change with wrong current password: %v", err)
	}

	org, _ := svc.Create(ctx, CreateInput{Slug: "o", Name: "O"})
	_, _ = svc.AddMember(ctx, org.ID, MemberInput{UserID: u.ID, Role: "member"})
	if err := svc.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if ms, _ := svc.ListMembers(ctx, org.ID); len(ms) != 0 {
		t.Fatal("memberships survived user deletion")
	}
	evts := eventTypes(t, s)
	if evts[len(evts)-1] != sdk.EventUserDeleted || evts[len(evts)-2] != sdk.EventMemberRemoved {
		t.Fatalf("delete events: %v", evts[len(evts)-3:])
	}
}

// fakeDirectory is an external directory that can verify passwords.
type fakeDirectory struct {
	mu        sync.Mutex
	users     map[string]sdk.User
	passwords map[string]string
	invited   []string
	failNext  bool
}

func (d *fakeDirectory) Name() string { return "fake" }
func (d *fakeDirectory) CreateUser(_ context.Context, u sdk.User) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failNext {
		d.failNext = false
		return "", errors.New("directory down")
	}
	id := "ext-" + u.Email
	d.users[id] = u
	return id, nil
}
func (d *fakeDirectory) UpdateUser(_ context.Context, u sdk.User) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.users[u.ExternalID] = u
	return nil
}
func (d *fakeDirectory) DeleteUser(_ context.Context, u sdk.User) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.users, u.ExternalID)
	return nil
}
func (d *fakeDirectory) SetPassword(_ context.Context, u sdk.User, pw string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.passwords[u.ExternalID] = pw
	return nil
}
func (d *fakeDirectory) VerifyPassword(_ context.Context, u sdk.User, pw string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.passwords[u.ExternalID] != pw {
		return errors.New("bad password")
	}
	return nil
}
func (d *fakeDirectory) SendInvitation(_ context.Context, u sdk.User) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.invited = append(d.invited, u.Email)
	return nil
}

func TestExternalDirectory(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	dir := &fakeDirectory{users: map[string]sdk.User{}, passwords: map[string]string{}}
	svc, mailer := newUserService(t, s, &UserOptions{Directory: dir, DirectoryName: "kc"}, nil)

	u, err := svc.CreateUser(ctx, UserInput{Email: "kim@example.com", Name: "Kim"})
	if err != nil || u.ExternalID != "ext-kim@example.com" || u.Directory != "kc" {
		t.Fatalf("create: %+v %v", u, err)
	}
	if len(dir.invited) != 1 || len(mailer.sent) != 0 {
		t.Fatal("directory should send its own invitation")
	}
	if err := svc.SetUserPassword(ctx, u.ID, goodPassword); err != nil {
		t.Fatal(err)
	}
	if got, _ := svc.GetUser(ctx, u.ID); got.Status != sdk.UserActive {
		t.Fatalf("setting a password activates: %+v", got)
	}
	if _, err := svc.Login(ctx, "kim@example.com", goodPassword, "kim-org"); err == nil {
		t.Fatal("login to unknown tenant")
	}
	if _, err := svc.UpdateUser(ctx, u.ID, UserUpdate{Name: ptr("Kim L.")}, nil); err != nil || dir.users[u.ExternalID].Name != "Kim L." {
		t.Fatalf("update not pushed to directory: %v", err)
	}

	// An external principal (e.g. a Keycloak token) gets linked to the user.
	p := &sdk.Principal{Subject: u.ExternalID, Authenticator: "kc/jwt"}
	if err := svc.LinkExternalPrincipal(ctx, p); err != nil || p.Claims["tenarium_user_id"] != u.ID {
		t.Fatalf("link: %+v %v", p, err)
	}
	_, _ = svc.DisableUser(ctx, u.ID)
	if err := svc.LinkExternalPrincipal(ctx, &sdk.Principal{Subject: u.ExternalID}); err == nil {
		t.Fatal("disabled external user accepted")
	}

	// A directory failure leaves nothing behind locally.
	dir.failNext = true
	if _, err := svc.CreateUser(ctx, UserInput{Email: "fail@example.com"}); err == nil {
		t.Fatal("directory failure ignored")
	}
	if _, err := svc.GetUser(ctx, "fail@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("local user created despite directory failure")
	}
}

func TestUserHooks(t *testing.T) {
	ctx := context.Background()
	hooks := hookFunc(func(_ context.Context, req *sdk.HookRequest) error {
		if req.Point != sdk.HookBeforeUserCreate {
			return nil
		}
		if !strings.HasSuffix(req.User.Email, "@acme.io") {
			return sdk.Reject("only acme.io addresses")
		}
		req.User.Attributes = map[string]string{"source": "hook"}
		req.User.Status = sdk.UserActive // must be ignored
		return nil
	})
	svc, _ := newUserService(t, memory.New(), nil, hooks)
	if _, err := svc.CreateUser(ctx, UserInput{Email: "x@evil.com"}); err == nil {
		t.Fatal("hook rejection ignored")
	}
	u, err := svc.CreateUser(ctx, UserInput{Email: "x@acme.io"})
	if err != nil || u.Attributes["source"] != "hook" || u.Status != sdk.UserInvited {
		t.Fatalf("hook mutation: %+v %v", u, err)
	}
}
