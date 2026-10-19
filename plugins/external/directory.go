package external

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/AimTune/tenarium/pkg/extplugin"
	"github.com/AimTune/tenarium/pkg/sdk"
)

// maxNameLen and maxExternalIDLen bound identifiers a plugin hands back to
// Tenarium (directory and mailer names, external user IDs).
const (
	maxNameLen       = 128
	maxExternalIDLen = 512
)

// validServices checks the user directory and mailer declared in an init
// response, defaulting their names to the instance name.
func (p *Plugin) validServices(resp *extplugin.InitResponse) error {
	if d := resp.UserDirectory; d != nil {
		if d.Name == "" {
			d.Name = p.instance
		}
		if err := validIdentifier(d.Name, maxNameLen); err != nil {
			return fmt.Errorf("plugin declared an invalid user directory name: %w", err)
		}
	}
	if m := resp.Mailer; m != nil {
		if m.Name == "" {
			m.Name = p.instance
		}
		if err := validIdentifier(m.Name, maxNameLen); err != nil {
			return fmt.Errorf("plugin declared an invalid mailer name: %w", err)
		}
	}
	return nil
}

// validIdentifier accepts non-empty, valid UTF-8 strings without control
// characters or surrounding whitespace, of at most max bytes.
func validIdentifier(s string, max int) error {
	switch {
	case s == "":
		return errors.New("empty")
	case len(s) > max:
		return fmt.Errorf("longer than %d bytes", max)
	case !utf8.ValidString(s):
		return errors.New("not valid UTF-8")
	case strings.TrimSpace(s) != s:
		return errors.New("surrounding whitespace")
	case strings.IndexFunc(s, unicode.IsControl) >= 0:
		return errors.New("contains control characters")
	}
	return nil
}

// newDirectory returns the remote directory adapter implementing exactly
// the optional interfaces the plugin declared, since Tenarium detects
// sdk.PasswordVerifier and sdk.InvitationSender by type assertion.
func newDirectory(p *Plugin, spec extplugin.DirectorySpec) sdk.UserDirectory {
	d := &directory{p: p, name: spec.Name}
	switch {
	case spec.VerifyPassword && spec.SendInvitation:
		return verifyingInvitingDirectory{d}
	case spec.VerifyPassword:
		return verifyingDirectory{d}
	case spec.SendInvitation:
		return invitingDirectory{d}
	default:
		return d
	}
}

// directory is an sdk.UserDirectory served by the plugin on /directory/{op}.
type directory struct {
	p    *Plugin
	name string
}

var _ sdk.UserDirectory = (*directory)(nil)

func (d *directory) Name() string { return d.name }

func (d *directory) op(ctx context.Context, op string, u sdk.User, password string, out any) error {
	err := d.p.call(ctx, "/directory/"+op, extplugin.DirectoryRequest{User: u, Password: password}, out)
	if err != nil {
		return fmt.Errorf("external directory %s: %w", op, err)
	}
	return nil
}

func (d *directory) CreateUser(ctx context.Context, u sdk.User) (string, error) {
	var out extplugin.CreateUserResponse
	if err := d.op(ctx, extplugin.DirCreateUser, u, "", &out); err != nil {
		return "", err
	}
	if err := validIdentifier(out.ExternalID, maxExternalIDLen); err != nil {
		return "", fmt.Errorf("external directory create_user: invalid external_id: %w", err)
	}
	return out.ExternalID, nil
}

func (d *directory) UpdateUser(ctx context.Context, u sdk.User) error {
	return d.op(ctx, extplugin.DirUpdateUser, u, "", nil)
}

func (d *directory) DeleteUser(ctx context.Context, u sdk.User) error {
	return d.op(ctx, extplugin.DirDeleteUser, u, "", nil)
}

func (d *directory) SetPassword(ctx context.Context, u sdk.User, password string) error {
	return d.op(ctx, extplugin.DirSetPassword, u, password, nil)
}

func (d *directory) verifyPassword(ctx context.Context, u sdk.User, password string) error {
	return d.op(ctx, extplugin.DirVerifyPassword, u, password, nil)
}

func (d *directory) sendInvitation(ctx context.Context, u sdk.User) error {
	return d.op(ctx, extplugin.DirSendInvitation, u, "", nil)
}

type verifyingDirectory struct{ *directory }

func (v verifyingDirectory) VerifyPassword(ctx context.Context, u sdk.User, password string) error {
	return v.verifyPassword(ctx, u, password)
}

type invitingDirectory struct{ *directory }

func (i invitingDirectory) SendInvitation(ctx context.Context, u sdk.User) error {
	return i.sendInvitation(ctx, u)
}

type verifyingInvitingDirectory struct{ *directory }

func (v verifyingInvitingDirectory) VerifyPassword(ctx context.Context, u sdk.User, password string) error {
	return v.verifyPassword(ctx, u, password)
}

func (v verifyingInvitingDirectory) SendInvitation(ctx context.Context, u sdk.User) error {
	return v.sendInvitation(ctx, u)
}

// mailer is an sdk.Mailer served by the plugin on /mailer/send.
type mailer struct {
	p    *Plugin
	name string
}

var _ sdk.Mailer = (*mailer)(nil)

func (m *mailer) Name() string { return m.name }

func (m *mailer) Send(ctx context.Context, msg sdk.Message) error {
	if err := m.p.call(ctx, "/mailer/send", msg, nil); err != nil {
		return fmt.Errorf("external mailer: %w", err)
	}
	return nil
}
