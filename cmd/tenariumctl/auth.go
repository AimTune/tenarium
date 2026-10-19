package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"text/tabwriter"

	"github.com/AimTune/tenarium/pkg/client"
)

const loginHelp = `Sign in and store credentials in a profile (default: the current profile).

With --email, the password is read from stdin: pass --password-stdin to pipe
it (e.g. from a secret manager). On a terminal you are prompted; echo is
turned off where 'stty' is available, otherwise the input is visible.
The access and refresh tokens are stored in the profile and refreshed
automatically.

With --api-key instead of --email, the key is verified and stored.

Examples:
  tenariumctl login --url https://tenarium.example.com --email admin@example.com
  echo "$PASSWORD" | tenariumctl login --url http://localhost:8080 --email ada@example.com --tenant acme --password-stdin
  tenariumctl --profile ci login --url http://localhost:8080 --api-key "$KEY"`

func cmdLogin(a *app, path string, args []string) error {
	fs := a.newFlags(path, "--url URL (--email EMAIL [--tenant T] [--password-stdin] | --api-key KEY)", loginHelp)
	email := fs.String("email", "", "user email")
	tenant := fs.String("tenant", "", "tenant ID or slug to sign in to (default: platform session)")
	pwStdin := fs.Bool("password-stdin", false, "read the password from stdin without prompting")
	if _, err := a.parse(fs, args, 0, 0); err != nil {
		return err
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	name := a.profileName()
	prev := cfg.Profiles[name]
	base := a.g.url
	if base == "" && prev != nil {
		base = prev.URL
	}
	if base == "" {
		base = a.env("TENARIUM_URL")
	}
	if base == "" {
		return usagef(path, "--url is required")
	}
	if (*email == "") == (a.g.apiKey == "") {
		return usagef(path, "pass exactly one of --email or --api-key")
	}
	c, err := client.New(base, client.WithUserAgent("tenariumctl/"+version))
	if err != nil {
		return err
	}
	p := &profile{URL: c.BaseURL()}
	if a.g.apiKey != "" {
		me, err := c.With(client.WithAPIKey(a.g.apiKey)).Me(a.ctx)
		if err != nil {
			return err
		}
		p.APIKey = a.g.apiKey
		cfg.Profiles[name], cfg.CurrentProfile = p, name
		if err := a.saveConfig(); err != nil {
			return err
		}
		return a.done(fmt.Sprintf("Logged in to %s as %s (profile %q).", p.URL, me.Subject, name),
			map[string]any{"profile": name, "url": p.URL, "subject": me.Subject})
	}
	pw, err := a.readSecret("Password", *pwStdin)
	if err != nil {
		return err
	}
	pair, err := c.Auth.Login(a.ctx, client.LoginRequest{Email: *email, Password: pw, Tenant: *tenant})
	if err != nil {
		return err
	}
	p.Email, p.Tenant, p.Tokens = *email, *tenant, &pair
	cfg.Profiles[name], cfg.CurrentProfile = p, name
	if err := a.saveConfig(); err != nil {
		return err
	}
	return a.done(fmt.Sprintf("Logged in to %s as %s (profile %q).", p.URL, *email, name),
		map[string]any{"profile": name, "url": p.URL, "email": *email, "tenant_id": pair.TenantID})
}

func cmdLogout(a *app, path string, args []string) error {
	fs := a.newFlags(path, "", "Revoke the profile's session and remove its stored credentials.")
	if _, err := a.parse(fs, args, 0, 0); err != nil {
		return err
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	name := a.profileName()
	p := cfg.Profiles[name]
	if p == nil || (p.Tokens == nil && p.APIKey == "") {
		return fmt.Errorf("profile %q has no stored credentials", name)
	}
	if p.Tokens != nil && p.Tokens.RefreshToken != "" {
		c, err := client.New(p.URL, client.WithUserAgent("tenariumctl/"+version))
		if err == nil {
			err = c.Auth.Logout(a.ctx, p.Tokens.RefreshToken)
		}
		if err != nil {
			fmt.Fprintf(a.errOut, "warning: could not revoke the session: %v\n", err)
		}
	}
	p.Tokens, p.APIKey = nil, ""
	if err := a.saveConfig(); err != nil {
		return err
	}
	return a.done(fmt.Sprintf("Logged out (profile %q).", name), map[string]any{"profile": name})
}

func cmdMe(a *app, path string, args []string) error {
	fs := a.newFlags(path, "", "Show the authenticated caller.")
	if _, err := a.parse(fs, args, 0, 0); err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	me, err := c.Me(a.ctx)
	if err != nil {
		return err
	}
	return a.print(me, func(w *tabwriter.Writer) {
		fmt.Fprintln(w, "SUBJECT\tKIND\tAUTHENTICATOR\tTENANT\tROLES")
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", me.Subject, me.Kind, me.Authenticator, dash(me.TenantID), dash(strings.Join(me.Roles, ",")))
	})
}

// readSecret reads one line from stdin. On a terminal it prompts first and
// tries to disable echo with stty (Unix); fromStdin skips the prompt.
func (a *app) readSecret(prompt string, fromStdin bool) (string, error) {
	if !fromStdin {
		if f, ok := a.rawIn.(*os.File); ok && isTerminal(f) {
			restore := disableEcho(f)
			if restore != nil {
				fmt.Fprintf(a.errOut, "%s: ", prompt)
				defer func() { restore(); fmt.Fprintln(a.errOut) }()
			} else {
				fmt.Fprintf(a.errOut, "%s (input is visible; use --password-stdin to pipe it): ", prompt)
			}
		}
	}
	line, err := a.in.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return "", errors.New("empty password on stdin")
	}
	return line, nil
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// disableEcho turns terminal echo off using stty and returns a function
// restoring it, or nil if that is not possible.
func disableEcho(f *os.File) func() {
	if runtime.GOOS == "windows" {
		return nil
	}
	stty := func(arg string) error {
		cmd := exec.Command("stty", arg)
		cmd.Stdin = f
		return cmd.Run()
	}
	if stty("-echo") != nil {
		return nil
	}
	return func() { _ = stty("echo") }
}
