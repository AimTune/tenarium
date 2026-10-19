// Package smtp is an sdk.Mailer that delivers email through an SMTP relay
// (Postmark, SES, Mailgun, a corporate relay or Mailpit in development).
//
//	plugins:
//	  - id: smtp
//	    config:
//	      host: smtp.example.com
//	      username: apikey
//	      password: ${SMTP_PASSWORD}
//	      from: "Acme <no-reply@acme.io>"
//
// Connections use STARTTLS by default and refuse to continue if the server
// does not offer it. Set tls to "implicit" for SMTPS (port 465), or to
// "none" together with allow_insecure for local development servers.
package smtp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func init() {
	sdk.Register("smtp", func() sdk.Plugin { return &Plugin{} })
}

// TLS modes.
const (
	TLSStartTLS = "starttls"
	TLSImplicit = "implicit"
	TLSNone     = "none"
)

type Config struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	// From is the sender, e.g. "Acme <no-reply@acme.io>".
	From    string `json:"from"`
	ReplyTo string `json:"reply_to"`
	// TLS is "starttls" (default), "implicit" or "none".
	TLS string `json:"tls"`
	// AllowInsecure must be set to use tls: none.
	AllowInsecure      bool   `json:"allow_insecure"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
	Timeout            string `json:"timeout"`
	// HeloName is the name sent with EHLO; net/smtp uses "localhost".
	HeloName string `json:"helo_name"`
	// Headers are added to every message, e.g. List-Unsubscribe.
	Headers map[string]string `json:"headers"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "host": {"type": "string", "minLength": 1},
    "port": {"type": "integer", "minimum": 1, "maximum": 65535},
    "username": {"type": "string"},
    "password": {"type": "string"},
    "from": {"type": "string", "minLength": 1},
    "reply_to": {"type": "string"},
    "tls": {"enum": ["starttls", "implicit", "none"]},
    "allow_insecure": {"type": "boolean"},
    "insecure_skip_verify": {"type": "boolean"},
    "timeout": {"type": "string"},
    "helo_name": {"type": "string"},
    "headers": {"type": "object", "additionalProperties": {"type": "string"}}
  },
  "required": ["host", "from"],
  "additionalProperties": false
}`)

// ErrInvalidMessage is returned by Send for messages that cannot be sent
// safely, such as bad recipients or header values containing line breaks.
var ErrInvalidMessage = errors.New("smtp: invalid message")

// reserved headers are set by the plugin and cannot be configured.
var reserved = []string{
	"Bcc", "Cc", "Content-Transfer-Encoding", "Content-Type", "Date", "From",
	"Message-Id", "Mime-Version", "Reply-To", "Return-Path", "Sender",
	"Subject", "To", "X-Tenarium-Tag",
}

type Plugin struct {
	cfg     Config
	from    *mail.Address
	replyTo *mail.Address
	domain  string
	timeout time.Duration
	headers [][2]string
	now     func() time.Time
	// next holds the configuration applied by Reconfigure.
	next atomic.Pointer[Plugin]
}

var (
	_ sdk.Mailer        = (*Plugin)(nil)
	_ sdk.HealthChecker = (*Plugin)(nil)
	_ sdk.Reconfigurer  = (*Plugin)(nil)
)

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "smtp",
		Name:         "SMTP",
		Version:      "0.1.0",
		Description:  "Sends email through an SMTP server.",
		ConfigSchema: configSchema,
	}
}

func (p *Plugin) Init(_ context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	if err := p.validate(); err != nil {
		return err
	}
	p.now = time.Now
	r.Mailer(p)
	return nil
}

func (p *Plugin) validate() error {
	c := &p.cfg
	if c.Host == "" {
		return errors.New("host is required")
	}
	if hasLineBreak(c.Host) || hasLineBreak(c.HeloName) {
		return errors.New("host and helo_name must not contain line breaks")
	}
	switch c.TLS {
	case "":
		c.TLS = TLSStartTLS
	case TLSStartTLS, TLSImplicit:
	case TLSNone:
		if !c.AllowInsecure {
			return errors.New(`tls "none" sends mail and credentials in clear text; set allow_insecure: true to permit it`)
		}
		if c.Username != "" && !isLoopback(c.Host) {
			return errors.New(`tls "none" with authentication is only allowed for localhost`)
		}
	default:
		return fmt.Errorf("tls must be starttls, implicit or none, got %q", c.TLS)
	}
	if c.Port == 0 {
		c.Port = 587
		if c.TLS == TLSImplicit {
			c.Port = 465
		}
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("port %d out of range", c.Port)
	}

	var err error
	if c.From == "" {
		return errors.New("from is required")
	}
	if p.from, err = parseAddress(c.From); err != nil {
		return fmt.Errorf("from: %w", err)
	}
	p.domain = p.from.Address[strings.LastIndexByte(p.from.Address, '@')+1:]
	if c.ReplyTo != "" {
		if p.replyTo, err = parseAddress(c.ReplyTo); err != nil {
			return fmt.Errorf("reply_to: %w", err)
		}
	}

	p.timeout = 15 * time.Second
	if c.Timeout != "" {
		if p.timeout, err = time.ParseDuration(c.Timeout); err != nil {
			return fmt.Errorf("timeout: %w", err)
		}
		if p.timeout <= 0 {
			return errors.New("timeout must be positive")
		}
	}

	p.headers = nil
	for _, k := range slices.Sorted(maps.Keys(c.Headers)) {
		if !validHeaderName(k) {
			return fmt.Errorf("headers: invalid header name %q", k)
		}
		name := textproto.CanonicalMIMEHeaderKey(k)
		if slices.Contains(reserved, name) {
			return fmt.Errorf("headers: %s is set by the plugin", name)
		}
		v := c.Headers[k]
		if hasLineBreak(v) {
			return fmt.Errorf("headers: %s must not contain line breaks", name)
		}
		p.headers = append(p.headers, [2]string{name, mime.QEncoding.Encode("utf-8", v)})
	}
	return nil
}

func (p *Plugin) Name() string { return "smtp" }

// Send delivers m to all of its recipients in one SMTP transaction.
func (p *Plugin) Send(ctx context.Context, m sdk.Message) error {
	if n := p.next.Load(); n != nil {
		return n.Send(ctx, m)
	}
	rcpts, err := parseRecipients(m.To)
	if err != nil {
		return err
	}
	msg, err := p.build(m, rcpts)
	if err != nil {
		return err
	}
	return p.session(ctx, func(c *smtp.Client) error {
		if p.cfg.Username != "" {
			if ok, _ := c.Extension("AUTH"); !ok {
				return errors.New("server does not support AUTH")
			}
			if err := c.Auth(smtp.PlainAuth("", p.cfg.Username, p.cfg.Password, p.cfg.Host)); err != nil {
				return fmt.Errorf("auth: %w", err)
			}
		}
		if err := c.Mail(p.from.Address); err != nil {
			return fmt.Errorf("MAIL FROM: %w", err)
		}
		for _, a := range rcpts {
			if err := c.Rcpt(a.Address); err != nil {
				return fmt.Errorf("RCPT TO <%s>: %w", a.Address, err)
			}
		}
		w, err := c.Data()
		if err != nil {
			return fmt.Errorf("DATA: %w", err)
		}
		if _, err := w.Write(msg); err != nil {
			return fmt.Errorf("DATA: %w", err)
		}
		if err := w.Close(); err != nil {
			return fmt.Errorf("DATA: %w", err)
		}
		return nil
	})
}

// Health connects, greets the server and negotiates TLS without sending.
func (p *Plugin) Health(ctx context.Context) error {
	if n := p.next.Load(); n != nil {
		return n.Health(ctx)
	}
	return p.session(ctx, func(*smtp.Client) error { return nil })
}

// session opens a connection, negotiates TLS, runs fn and quits. Every
// network operation is bounded by the configured timeout and by ctx.
func (p *Plugin) session(ctx context.Context, fn func(*smtp.Client) error) error {
	addr := net.JoinHostPort(p.cfg.Host, strconv.Itoa(p.cfg.Port))
	d := &net.Dialer{Timeout: p.timeout}
	var (
		conn net.Conn
		err  error
	)
	if p.cfg.TLS == TLSImplicit {
		conn, err = (&tls.Dialer{NetDialer: d, Config: p.tlsConfig()}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return wrap(ctx, "dial", err)
	}
	deadline := time.Now().Add(p.timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	// Unblock any pending read or write as soon as ctx is done.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	c, err := smtp.NewClient(conn, p.cfg.Host)
	if err != nil {
		conn.Close()
		return wrap(ctx, "greeting", err)
	}
	defer c.Close()
	helo := p.cfg.HeloName
	if helo == "" {
		helo = "localhost"
	}
	if err := c.Hello(helo); err != nil {
		return wrap(ctx, "EHLO", err)
	}
	if p.cfg.TLS == TLSStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("smtp: server does not offer STARTTLS; refusing to send in clear text")
		}
		if err := c.StartTLS(p.tlsConfig()); err != nil {
			return wrap(ctx, "STARTTLS", err)
		}
	}
	if err := fn(c); err != nil {
		return wrap(ctx, "", err)
	}
	if err := c.Quit(); err != nil {
		return wrap(ctx, "QUIT", err)
	}
	return nil
}

func (p *Plugin) tlsConfig() *tls.Config {
	return &tls.Config{
		ServerName:         p.cfg.Host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: p.cfg.InsecureSkipVerify, //nolint:gosec // opt-in for self-signed dev servers
	}
}

// wrap prefixes err with the failed step and reports ctx cancellation in
// preference to the resulting I/O error.
func wrap(ctx context.Context, op string, err error) error {
	var ne net.Error
	switch {
	case ctx.Err() != nil:
		err = fmt.Errorf("%w (%w)", context.Cause(ctx), err)
	case errors.As(err, &ne) && ne.Timeout() && deadlinePassed(ctx):
		// The conn deadline equals ctx's deadline and can fire a moment
		// before ctx itself reports it.
		err = fmt.Errorf("%w (%w)", context.DeadlineExceeded, err)
	}
	if op == "" {
		return fmt.Errorf("smtp: %w", err)
	}
	return fmt.Errorf("smtp %s: %w", op, err)
}

func deadlinePassed(ctx context.Context) bool {
	dl, ok := ctx.Deadline()
	return ok && !time.Now().Before(dl)
}

// build renders m as an RFC 5322 message with CRLF line endings.
func (p *Plugin) build(m sdk.Message, rcpts []*mail.Address) ([]byte, error) {
	if hasLineBreak(m.Subject) || hasLineBreak(m.Tag) {
		return nil, fmt.Errorf("%w: subject and tag must not contain line breaks", ErrInvalidMessage)
	}
	var b bytes.Buffer
	h := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }

	h("Date", p.now().Format(time.RFC1123Z))
	h("Message-ID", "<"+rand.Text()+"@"+p.domain+">")
	h("From", p.from.String())
	to := make([]string, len(rcpts))
	for i, a := range rcpts {
		to[i] = a.String()
	}
	h("To", strings.Join(to, ",\r\n "))
	if p.replyTo != nil {
		h("Reply-To", p.replyTo.String())
	}
	h("Subject", mime.QEncoding.Encode("utf-8", m.Subject))
	if m.Tag != "" {
		h("X-Tenarium-Tag", mime.QEncoding.Encode("utf-8", m.Tag))
	}
	for _, kv := range p.headers {
		h(kv[0], kv[1])
	}
	h("MIME-Version", "1.0")

	switch {
	case m.HTML != "" && m.Text != "":
		mw := multipart.NewWriter(&b)
		h("Content-Type", mime.FormatMediaType("multipart/alternative", map[string]string{"boundary": mw.Boundary()}))
		b.WriteString("\r\n")
		for _, part := range []struct{ typ, body string }{{"text/plain", m.Text}, {"text/html", m.HTML}} {
			w, err := mw.CreatePart(textproto.MIMEHeader{
				"Content-Type":              {part.typ + "; charset=utf-8"},
				"Content-Transfer-Encoding": {"quoted-printable"},
			})
			if err != nil {
				return nil, err
			}
			if err := writeQP(w, part.body); err != nil {
				return nil, err
			}
		}
		if err := mw.Close(); err != nil {
			return nil, err
		}
	default:
		typ, body := "text/plain", m.Text
		if m.Text == "" && m.HTML != "" {
			typ, body = "text/html", m.HTML
		}
		h("Content-Type", typ+"; charset=utf-8")
		h("Content-Transfer-Encoding", "quoted-printable")
		b.WriteString("\r\n")
		if err := writeQP(&b, body); err != nil {
			return nil, err
		}
	}
	return b.Bytes(), nil
}

func writeQP(w io.Writer, s string) error {
	qp := quotedprintable.NewWriter(w)
	if _, err := io.WriteString(qp, s); err != nil {
		return err
	}
	return qp.Close()
}

func parseRecipients(to []string) ([]*mail.Address, error) {
	if len(to) == 0 {
		return nil, fmt.Errorf("%w: no recipients", ErrInvalidMessage)
	}
	out := make([]*mail.Address, 0, len(to))
	for _, s := range to {
		a, err := parseAddress(s)
		if err != nil {
			return nil, fmt.Errorf("%w: recipient %q: %w", ErrInvalidMessage, s, err)
		}
		out = append(out, a)
	}
	return out, nil
}

func parseAddress(s string) (*mail.Address, error) {
	if hasLineBreak(s) {
		return nil, errors.New("must not contain line breaks")
	}
	return mail.ParseAddress(s)
}

func hasLineBreak(s string) bool { return strings.ContainsAny(s, "\r\n") }

func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= ' ' || c > '~' || c == ':' {
			return false
		}
	}
	return true
}

func isLoopback(host string) bool {
	// Matches the hosts net/smtp.PlainAuth accepts without TLS.
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// Reconfigure applies new server settings (host, credentials, sender, ...)
// without a restart; messages already being sent finish with the old ones.
func (p *Plugin) Reconfigure(_ context.Context, decode func(v any) error) error {
	n := &Plugin{now: p.now}
	if err := decode(&n.cfg); err != nil {
		return err
	}
	if err := n.validate(); err != nil {
		return err
	}
	p.next.Store(n)
	return nil
}
