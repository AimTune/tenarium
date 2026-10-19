package external

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/AimTune/tenarium/pkg/extplugin"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

// memdir is the directory-and-mailer conformance plugin. The TypeScript and
// Python SDKs ship the same plugin (examples/directory.ts and
// examples/directory.py); exerciseDirectory checks all three:
//
//   - directory "memdir" (verifies passwords, sends invitations), mailer
//     "memmail";
//   - create_user returns "ext-" + lower(email), the same ID for a known
//     email;
//   - update_user, set_password and send_invitation of an unknown
//     external_id fail with not_found; delete_user is idempotent;
//   - set_password for emails ending in "@sso.example" is unsupported;
//   - verify_password of an unknown user or a wrong password fails with
//     invalid_credentials;
//   - send fails without recipients (no code);
//   - GET /outbox returns {"invited": [email...], "sent": [{to, subject, tag}]}.
type memdir struct {
	mu      sync.Mutex
	users   map[string]*memUser
	invited []string
	sent    []outboxMessage
}

type memUser struct {
	email, name, password string
}

type outboxMessage struct {
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	Tag     string   `json:"tag"`
}

func (*memdir) Manifest() sdk.Manifest {
	return sdk.Manifest{ID: "memdir", Name: "Memory directory", Version: "1.0.0"}
}

func (m *memdir) Init(_ context.Context, r sdk.Registrar) error {
	m.users = map[string]*memUser{}
	r.UserDirectory(memDirectory{m})
	r.Mailer(memMailer{m})
	r.Route("GET /outbox", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"invited": m.invited, "sent": m.sent})
	}))
	return nil
}

type memDirectory struct{ m *memdir }

func (memDirectory) Name() string { return "memdir" }

func (d memDirectory) CreateUser(_ context.Context, u sdk.User) (string, error) {
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	email := strings.ToLower(u.Email)
	id := "ext-" + email
	if _, ok := d.m.users[id]; !ok {
		d.m.users[id] = &memUser{email: email, name: u.Name}
	}
	return id, nil
}

func (d memDirectory) lookup(u sdk.User) (*memUser, error) {
	rec, ok := d.m.users[u.ExternalID]
	if !ok {
		return nil, sdk.ErrNotFound
	}
	return rec, nil
}

func (d memDirectory) UpdateUser(_ context.Context, u sdk.User) error {
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	rec, err := d.lookup(u)
	if err != nil {
		return err
	}
	rec.email, rec.name = strings.ToLower(u.Email), u.Name
	return nil
}

func (d memDirectory) DeleteUser(_ context.Context, u sdk.User) error {
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	delete(d.m.users, u.ExternalID)
	return nil
}

func (d memDirectory) SetPassword(_ context.Context, u sdk.User, password string) error {
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	rec, err := d.lookup(u)
	if err != nil {
		return err
	}
	if strings.HasSuffix(rec.email, "@sso.example") {
		return sdk.ErrUnsupported
	}
	rec.password = password
	return nil
}

func (d memDirectory) VerifyPassword(_ context.Context, u sdk.User, password string) error {
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	rec, err := d.lookup(u)
	if err != nil || rec.password == "" || rec.password != password {
		return extplugin.ErrInvalidCredentials
	}
	return nil
}

func (d memDirectory) SendInvitation(_ context.Context, u sdk.User) error {
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	rec, err := d.lookup(u)
	if err != nil {
		return err
	}
	d.m.invited = append(d.m.invited, rec.email)
	return nil
}

type memMailer struct{ m *memdir }

func (memMailer) Name() string { return "memmail" }

func (ml memMailer) Send(_ context.Context, msg sdk.Message) error {
	if len(msg.To) == 0 {
		return errors.New("no recipients")
	}
	ml.m.mu.Lock()
	defer ml.m.mu.Unlock()
	ml.m.sent = append(ml.m.sent, outboxMessage{To: msg.To, Subject: msg.Subject, Tag: msg.Tag})
	return nil
}

// exerciseDirectory checks a running memdir plugin registered into reg
// through the host-side adapters.
func exerciseDirectory(t *testing.T, reg *sdktest.Registrar) {
	t.Helper()
	ctx := context.Background()

	dir := reg.Directory
	if dir == nil || reg.MailerImpl == nil {
		t.Fatalf("directory %v, mailer %v not registered", dir, reg.MailerImpl)
	}
	if dir.Name() != "memdir" || reg.MailerImpl.Name() != "memmail" {
		t.Fatalf("names: %q %q", dir.Name(), reg.MailerImpl.Name())
	}
	verifier, ok := dir.(sdk.PasswordVerifier)
	if !ok {
		t.Fatal("directory does not verify passwords")
	}
	inviter, ok := dir.(sdk.InvitationSender)
	if !ok {
		t.Fatal("directory does not send invitations")
	}

	u := sdk.User{ID: "u1", Email: "Alice@Example.com", Name: "Alice", Status: sdk.UserInvited, Directory: "memdir"}
	id, err := dir.CreateUser(ctx, u)
	if err != nil || id != "ext-alice@example.com" {
		t.Fatalf("create: %q %v", id, err)
	}
	if again, err := dir.CreateUser(ctx, u); err != nil || again != id {
		t.Fatalf("create is not idempotent: %q %v", again, err)
	}
	u.ExternalID = id
	u.Name = "Alice B"
	if err := dir.UpdateUser(ctx, u); err != nil {
		t.Fatalf("update: %v", err)
	}
	if err := dir.UpdateUser(ctx, sdk.User{ID: "u9", Email: "x@example.com", ExternalID: "missing"}); !errors.Is(err, sdk.ErrNotFound) {
		t.Fatalf("update of unknown user: want ErrNotFound, got %v", err)
	}

	if err := dir.SetPassword(ctx, u, "correct horse"); err != nil {
		t.Fatalf("set password: %v", err)
	}
	if err := verifier.VerifyPassword(ctx, u, "correct horse"); err != nil {
		t.Fatalf("verify good password: %v", err)
	}
	err = verifier.VerifyPassword(ctx, u, "wrong")
	if !errors.Is(err, extplugin.ErrInvalidCredentials) {
		t.Fatalf("verify bad password: want ErrInvalidCredentials, got %v", err)
	}
	if strings.Contains(err.Error(), "wrong") || strings.Contains(err.Error(), "correct horse") {
		t.Fatalf("error leaks the password: %v", err)
	}

	sso := sdk.User{ID: "u2", Email: "bob@sso.example", Status: sdk.UserInvited}
	if sso.ExternalID, err = dir.CreateUser(ctx, sso); err != nil {
		t.Fatal(err)
	}
	if err := dir.SetPassword(ctx, sso, "pw"); !errors.Is(err, sdk.ErrUnsupported) {
		t.Fatalf("set password on SSO user: want ErrUnsupported, got %v", err)
	}

	if err := inviter.SendInvitation(ctx, u); err != nil {
		t.Fatalf("send invitation: %v", err)
	}
	if err := inviter.SendInvitation(ctx, sdk.User{ExternalID: "missing"}); !errors.Is(err, sdk.ErrNotFound) {
		t.Fatalf("invite unknown user: want ErrNotFound, got %v", err)
	}

	msg := sdk.Message{To: []string{"alice@example.com"}, Subject: "Welcome", Text: "hi", HTML: "<p>hi</p>", Tag: "invitation"}
	if err := reg.MailerImpl.Send(ctx, msg); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := reg.MailerImpl.Send(ctx, sdk.Message{Subject: "nobody"}); err == nil ||
		errors.Is(err, sdk.ErrNotFound) || errors.Is(err, sdk.ErrUnsupported) {
		t.Fatalf("send without recipients: want a plain error, got %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/outbox", nil)
	req = req.WithContext(sdk.WithPrincipal(req.Context(), &sdk.Principal{Subject: "admin"}))
	reg.Mux.ServeHTTP(rec, req)
	var outbox struct {
		Invited []string        `json:"invited"`
		Sent    []outboxMessage `json:"sent"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &outbox); err != nil {
		t.Fatalf("outbox: %d %s", rec.Code, rec.Body)
	}
	if len(outbox.Invited) != 1 || outbox.Invited[0] != "alice@example.com" {
		t.Fatalf("invited: %v", outbox.Invited)
	}
	if len(outbox.Sent) != 1 || outbox.Sent[0].Subject != "Welcome" || outbox.Sent[0].Tag != "invitation" ||
		len(outbox.Sent[0].To) != 1 || outbox.Sent[0].To[0] != "alice@example.com" {
		t.Fatalf("sent: %+v", outbox.Sent)
	}

	if err := dir.DeleteUser(ctx, u); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := dir.DeleteUser(ctx, u); err != nil {
		t.Fatalf("delete is not idempotent: %v", err)
	}
	if err := verifier.VerifyPassword(ctx, u, "correct horse"); !errors.Is(err, extplugin.ErrInvalidCredentials) {
		t.Fatalf("verify deleted user: want ErrInvalidCredentials, got %v", err)
	}
}

// TestDirectoryConformance runs the Go memdir plugin through extplugin's
// handler and exercises it through the host adapters.
func TestDirectoryConformance(t *testing.T) {
	srv := httptest.NewServer(extplugin.NewHandler(&memdir{}, "s3cret", discard))
	defer srv.Close()
	reg := sdktest.NewRegistrar(map[string]any{"url": srv.URL, "secret": "s3cret"})
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	exerciseDirectory(t, reg)

	// No calls reach a plugin that is not (or no longer) verified.
	p.ready.Store(false)
	if _, err := reg.Directory.CreateUser(context.Background(), sdk.User{Email: "a@b.c"}); !errors.Is(err, errNotReady) {
		t.Fatalf("call to unready plugin: %v", err)
	}
	if err := reg.MailerImpl.Send(context.Background(), sdk.Message{To: []string{"a@b.c"}}); !errors.Is(err, errNotReady) {
		t.Fatalf("call to unready plugin: %v", err)
	}
}

// basicDirectory has neither optional capability.
type basicDirectory struct{}

func (basicDirectory) Name() string { return "basic" }
func (basicDirectory) CreateUser(context.Context, sdk.User) (string, error) {
	return "", nil // invalid: the host must refuse an empty ID
}
func (basicDirectory) UpdateUser(context.Context, sdk.User) error          { return nil }
func (basicDirectory) DeleteUser(context.Context, sdk.User) error          { return nil }
func (basicDirectory) SetPassword(context.Context, sdk.User, string) error { return sdk.ErrUnsupported }

type basicPlugin struct{}

func (basicPlugin) Manifest() sdk.Manifest { return sdk.Manifest{ID: "basic"} }
func (basicPlugin) Init(_ context.Context, r sdk.Registrar) error {
	r.UserDirectory(basicDirectory{})
	return nil
}

func TestDirectoryOptionalCapabilities(t *testing.T) {
	srv := httptest.NewServer(extplugin.NewHandler(basicPlugin{}, "", discard))
	defer srv.Close()
	reg := sdktest.NewRegistrar(map[string]any{"url": srv.URL, "secret": "x"})
	if err := (&Plugin{}).Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if reg.MailerImpl != nil {
		t.Fatal("mailer registered although none was declared")
	}
	if _, ok := reg.Directory.(sdk.PasswordVerifier); ok {
		t.Fatal("directory claims to verify passwords")
	}
	if _, ok := reg.Directory.(sdk.InvitationSender); ok {
		t.Fatal("directory claims to send invitations")
	}
	if err := reg.Directory.SetPassword(context.Background(), sdk.User{}, "pw"); !errors.Is(err, sdk.ErrUnsupported) {
		t.Fatalf("want ErrUnsupported, got %v", err)
	}
	if _, err := reg.Directory.CreateUser(context.Background(), sdk.User{Email: "a@b.c"}); err == nil {
		t.Fatal("empty external id accepted")
	}
}

// rawRemote answers /init with init and every other call with status and
// reply, to check the host against replies the Go helper never produces.
func rawRemote(t *testing.T, init string, status int, reply string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/init":
			_, _ = w.Write([]byte(init))
		default:
			w.WriteHeader(status)
			_, _ = w.Write([]byte(reply))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDirectoryDeclarationValidation(t *testing.T) {
	for _, tc := range []struct {
		name, init string
		ok         bool
	}{
		{"default names", `{"protocol":1,"manifest":{"id":"x"},"user_directory":{},"mailer":{}}`, true},
		{"control char", `{"protocol":1,"manifest":{"id":"x"},"user_directory":{"name":"a\u0000b"}}`, false},
		{"whitespace", `{"protocol":1,"manifest":{"id":"x"},"mailer":{"name":" m"}}`, false},
		{"too long", `{"protocol":1,"manifest":{"id":"x"},"mailer":{"name":"` + strings.Repeat("m", 200) + `"}}`, false},
		{"wrong type", `{"protocol":1,"manifest":{"id":"x"},"user_directory":true}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := rawRemote(t, tc.init, 204, "")
			reg := sdktest.NewRegistrar(map[string]any{"url": srv.URL, "secret": "x"})
			err := (&Plugin{}).Init(context.Background(), reg)
			if (err == nil) != tc.ok {
				t.Fatalf("init error %v, want ok=%v", err, tc.ok)
			}
			if tc.ok && (reg.Directory.Name() != reg.Instance || reg.MailerImpl.Name() != reg.Instance) {
				t.Fatalf("names do not default to the instance: %q %q", reg.Directory.Name(), reg.MailerImpl.Name())
			}
		})
	}
}

func TestDirectoryErrorMapping(t *testing.T) {
	const init = `{"protocol":1,"manifest":{"id":"x"},"user_directory":{"verify_password":true},"mailer":{}}`
	for _, tc := range []struct {
		status int
		reply  string
		want   error // nil: an error matching none of the sentinels
	}{
		{404, `{"error":"no such user","code":"not_found"}`, sdk.ErrNotFound},
		{501, `{"error":"nope","code":"unsupported"}`, sdk.ErrUnsupported},
		{403, `{"error":"bad password","code":"invalid_credentials"}`, extplugin.ErrInvalidCredentials},
		{403, `{"error":"no","code":"forbidden"}`, sdk.ErrForbidden},
		{500, `{"code":"not_found"}`, sdk.ErrNotFound},
		// The status alone is never interpreted: a 404 without a code is
		// an unknown endpoint, not a missing user.
		{404, `404 page not found`, nil},
		{500, `{"error":"boom","code":"something_new"}`, nil},
	} {
		srv := rawRemote(t, init, tc.status, tc.reply)
		reg := sdktest.NewRegistrar(map[string]any{"url": srv.URL, "secret": "x"})
		if err := (&Plugin{}).Init(context.Background(), reg); err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		errs := []error{
			reg.Directory.UpdateUser(ctx, sdk.User{}),
			reg.Directory.(sdk.PasswordVerifier).VerifyPassword(ctx, sdk.User{}, "pw"),
			reg.MailerImpl.Send(ctx, sdk.Message{}),
		}
		_, err := reg.Directory.CreateUser(ctx, sdk.User{})
		errs = append(errs, err)
		for i, err := range errs {
			switch {
			case err == nil:
				t.Fatalf("%d %s call %d: no error", tc.status, tc.reply, i)
			case tc.want != nil && !errors.Is(err, tc.want):
				t.Fatalf("%d %s call %d: want %v, got %v", tc.status, tc.reply, i, tc.want, err)
			case tc.want == nil && extplugin.ErrorCode(err) != "":
				t.Fatalf("%d %s call %d: unexpected sentinel in %v", tc.status, tc.reply, i, err)
			}
		}
	}
}

func TestCreateUserValidatesExternalID(t *testing.T) {
	const init = `{"protocol":1,"manifest":{"id":"x"},"user_directory":{}}`
	for _, reply := range []string{`{}`, `{"external_id":""}`, `{"external_id":"a\nb"}`, `{"external_id":7}`,
		`{"external_id":"` + strings.Repeat("x", 600) + `"}`, `not json`} {
		srv := rawRemote(t, init, 200, reply)
		reg := sdktest.NewRegistrar(map[string]any{"url": srv.URL, "secret": "x"})
		if err := (&Plugin{}).Init(context.Background(), reg); err != nil {
			t.Fatal(err)
		}
		if id, err := reg.Directory.CreateUser(context.Background(), sdk.User{Email: "a@b.c"}); err == nil {
			t.Fatalf("reply %s accepted as %q", reply, id)
		}
	}
}
