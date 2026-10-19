package smtp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

// received is a message captured by fakeServer.
type received struct {
	From     string
	To       []string
	Data     []byte
	TLS      bool
	Username string
	Password string
}

// fakeServer speaks just enough SMTP for net/smtp: EHLO, STARTTLS,
// AUTH PLAIN, MAIL, RCPT, DATA, RSET, NOOP and QUIT.
type fakeServer struct {
	t        *testing.T
	ln       net.Listener
	starttls bool
	auth     bool
	silent   bool // accept connections but never answer
	tlsCfg   *tls.Config

	mu       sync.Mutex
	messages []received
	sessions int
}

func newFakeServer(t *testing.T, configure func(*fakeServer)) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeServer{t: t, ln: ln, tlsCfg: &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}}}
	if configure != nil {
		configure(s)
	}
	t.Cleanup(func() { ln.Close() })
	go s.serve()
	return s
}

func (s *fakeServer) port() int { return s.ln.Addr().(*net.TCPAddr).Port }

func (s *fakeServer) received() []received {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]received(nil), s.messages...)
}

func (s *fakeServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.sessions++
		s.mu.Unlock()
		if s.silent {
			go func() { _, _ = io.Copy(io.Discard, conn); conn.Close() }()
			continue
		}
		go s.handle(conn)
	}
}

func (s *fakeServer) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	tp := textproto.NewConn(conn)
	reply := func(format string, args ...any) { _ = tp.PrintfLine(format, args...) }
	var (
		isTLS bool
		cur   received
	)
	reply("220 fake ESMTP ready")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "EHLO", "HELO":
			ext := []string{"250-fake", "250-8BITMIME"}
			if s.starttls && !isTLS {
				ext = append(ext, "250-STARTTLS")
			}
			if s.auth {
				ext = append(ext, "250-AUTH PLAIN")
			}
			ext = append(ext, "250 SIZE 10240000")
			for _, l := range ext {
				reply("%s", l)
			}
		case "STARTTLS":
			if !s.starttls || isTLS {
				reply("502 not supported")
				continue
			}
			reply("220 go ahead")
			tc := tls.Server(conn, s.tlsCfg)
			if err := tc.Handshake(); err != nil {
				return
			}
			conn, isTLS = tc, true
			tp = textproto.NewConn(tc)
			cur = received{}
		case "AUTH":
			mech, ir, _ := strings.Cut(arg, " ")
			if !s.auth || mech != "PLAIN" {
				reply("504 unsupported")
				continue
			}
			raw, err := base64.StdEncoding.DecodeString(ir)
			parts := strings.Split(string(raw), "\x00")
			if err != nil || len(parts) != 3 {
				reply("501 malformed")
				continue
			}
			cur.Username, cur.Password = parts[1], parts[2]
			reply("235 ok")
		case "MAIL":
			cur.From = trimPath(arg)
			reply("250 ok")
		case "RCPT":
			cur.To = append(cur.To, trimPath(arg))
			reply("250 ok")
		case "DATA":
			reply("354 send it")
			data, err := tp.ReadDotBytes()
			if err != nil {
				return
			}
			cur.Data, cur.TLS = data, isTLS
			s.mu.Lock()
			s.messages = append(s.messages, cur)
			s.mu.Unlock()
			cur = received{Username: cur.Username, Password: cur.Password}
			reply("250 queued")
		case "RSET", "NOOP":
			reply("250 ok")
		case "QUIT":
			reply("221 bye")
			return
		default:
			reply("500 unknown command")
		}
	}
}

func trimPath(arg string) string {
	_, rest, _ := strings.Cut(arg, ":")
	addr, _, _ := strings.Cut(rest, " ")
	return strings.Trim(addr, "<>")
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fake smtp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"localhost"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// newMailer initialises the plugin with cfg and returns the registered
// mailer.
func newMailer(t *testing.T, cfg map[string]any) *Plugin {
	t.Helper()
	reg := sdktest.NewRegistrar(cfg)
	if err := (&Plugin{}).Init(context.Background(), reg); err != nil {
		t.Fatalf("Init: %v", err)
	}
	p, ok := reg.MailerImpl.(*Plugin)
	if !ok {
		t.Fatalf("registered mailer is %T", reg.MailerImpl)
	}
	return p
}

func baseConfig(s *fakeServer, extra map[string]any) map[string]any {
	cfg := map[string]any{
		"host":                 "127.0.0.1",
		"port":                 s.port(),
		"from":                 "Acme <no-reply@acme.io>",
		"insecure_skip_verify": true,
		"timeout":              "5s",
	}
	for k, v := range extra {
		cfg[k] = v
	}
	return cfg
}

func TestSendStartTLSMultipart(t *testing.T) {
	s := newFakeServer(t, func(s *fakeServer) { s.starttls, s.auth = true, true })
	p := newMailer(t, baseConfig(s, map[string]any{
		"username": "apikey",
		"password": "s3cret",
		"reply_to": "Support <support@acme.io>",
		"headers":  map[string]any{"list-unsubscribe": "<https://acme.io/unsub>"},
	}))
	if p.Name() != "smtp" {
		t.Fatalf("Name = %q", p.Name())
	}

	text := "Hallo Jürgen,\nplease click the link below to set your password. This line is long enough to need a soft line break in quoted-printable."
	html := `<p>Hallo <b>Jürgen</b>, <a href="https://acme.io/x?a=1&b=2">set password</a></p>`
	err := p.Send(context.Background(), sdk.Message{
		To:      []string{"Jürgen Müller <jm@example.com>", "ops@example.com"},
		Subject: "Grüße from Acme",
		Text:    text,
		HTML:    html,
		Tag:     "invitation",
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	msgs := s.received()
	if len(msgs) != 1 {
		t.Fatalf("got %d messages", len(msgs))
	}
	r := msgs[0]
	if !r.TLS {
		t.Error("message was not sent over STARTTLS")
	}
	if r.Username != "apikey" || r.Password != "s3cret" {
		t.Errorf("auth = %q/%q", r.Username, r.Password)
	}
	if r.From != "no-reply@acme.io" {
		t.Errorf("MAIL FROM = %q", r.From)
	}
	if strings.Join(r.To, ",") != "jm@example.com,ops@example.com" {
		t.Errorf("RCPT TO = %v", r.To)
	}

	msg, err := mail.ReadMessage(strings.NewReader(string(r.Data)))
	if err != nil {
		t.Fatal(err)
	}
	dec := new(mime.WordDecoder)
	subject, err := dec.DecodeHeader(msg.Header.Get("Subject"))
	if err != nil || subject != "Grüße from Acme" {
		t.Errorf("Subject = %q (%v), raw %q", subject, err, msg.Header.Get("Subject"))
	}
	if raw := msg.Header.Get("Subject"); !strings.HasPrefix(raw, "=?utf-8?q?") {
		t.Errorf("Subject not Q-encoded: %q", raw)
	}
	from, err := msg.Header.AddressList("From")
	if err != nil || len(from) != 1 || from[0].Name != "Acme" || from[0].Address != "no-reply@acme.io" {
		t.Errorf("From = %v (%v)", from, err)
	}
	to, err := msg.Header.AddressList("To")
	if err != nil || len(to) != 2 || to[0].Name != "Jürgen Müller" || to[1].Address != "ops@example.com" {
		t.Errorf("To = %v (%v)", to, err)
	}
	if rt := msg.Header.Get("Reply-To"); rt != `"Support" <support@acme.io>` {
		t.Errorf("Reply-To = %q", rt)
	}
	if id := msg.Header.Get("Message-ID"); !strings.HasPrefix(id, "<") || !strings.HasSuffix(id, "@acme.io>") {
		t.Errorf("Message-ID = %q", id)
	}
	if _, err := msg.Header.Date(); err != nil {
		t.Errorf("Date: %v", err)
	}
	if tag := msg.Header.Get("X-Tenarium-Tag"); tag != "invitation" {
		t.Errorf("X-Tenarium-Tag = %q", tag)
	}
	if lu := msg.Header.Get("List-Unsubscribe"); lu != "<https://acme.io/unsub>" {
		t.Errorf("List-Unsubscribe = %q", lu)
	}
	if v := msg.Header.Get("MIME-Version"); v != "1.0" {
		t.Errorf("MIME-Version = %q", v)
	}

	mt, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/alternative" {
		t.Fatalf("Content-Type = %q (%v)", msg.Header.Get("Content-Type"), err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	want := []struct{ typ, body string }{
		{"text/plain", text},
		{"text/html", html},
	}
	for _, w := range want {
		part, err := mr.NextPart()
		if err != nil {
			t.Fatalf("part %s: %v", w.typ, err)
		}
		if ct := part.Header.Get("Content-Type"); ct != w.typ+"; charset=utf-8" {
			t.Errorf("part Content-Type = %q", ct)
		}
		// multipart.Reader decodes quoted-printable transparently.
		body, err := io.ReadAll(part)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != w.body {
			t.Errorf("%s body = %q, want %q", w.typ, body, w.body)
		}
	}
	if _, err := mr.NextPart(); err != io.EOF {
		t.Errorf("expected exactly two parts, got %v", err)
	}
	// ReadDotBytes normalises CRLF to LF.
	for _, l := range strings.Split(string(r.Data), "\n") {
		if len(l) > 998 {
			t.Errorf("line too long: %d", len(l))
		}
	}
}

func TestSendTextOnlyPlain(t *testing.T) {
	s := newFakeServer(t, func(s *fakeServer) { s.auth = true })
	p := newMailer(t, baseConfig(s, map[string]any{
		"tls": "none", "allow_insecure": true, "username": "u", "password": "p",
	}))
	if err := p.Send(context.Background(), sdk.Message{To: []string{"a@example.com"}, Subject: "Hi", Text: "plain body"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	r := s.received()[0]
	if r.TLS || r.Username != "u" {
		t.Errorf("TLS=%v user=%q", r.TLS, r.Username)
	}
	msg, err := mail.ReadMessage(strings.NewReader(string(r.Data)))
	if err != nil {
		t.Fatal(err)
	}
	if ct := msg.Header.Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	if msg.Header.Get("Subject") != "Hi" || msg.Header.Get("X-Tenarium-Tag") != "" {
		t.Errorf("headers = %v", msg.Header)
	}
	body, _ := io.ReadAll(msg.Body)
	// The DATA terminator adds a final line break.
	if strings.TrimRight(string(body), "\r\n") != "plain body" {
		t.Errorf("body = %q", body)
	}
}

func TestStartTLSRequired(t *testing.T) {
	s := newFakeServer(t, nil) // no STARTTLS advertised
	p := newMailer(t, baseConfig(s, nil))
	err := p.Send(context.Background(), sdk.Message{To: []string{"a@example.com"}, Subject: "x", Text: "x"})
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("err = %v", err)
	}
	if len(s.received()) != 0 {
		t.Fatal("message was sent without TLS")
	}
	if err := p.Health(context.Background()); err == nil {
		t.Fatal("Health succeeded without STARTTLS")
	}
}

func TestImplicitTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeServer{t: t, tlsCfg: &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}}}
	s.ln = tls.NewListener(ln, s.tlsCfg)
	t.Cleanup(func() { s.ln.Close() })
	go s.serve()

	cfg := baseConfig(s, map[string]any{"tls": "implicit"})
	cfg["port"] = ln.Addr().(*net.TCPAddr).Port
	p := newMailer(t, cfg)
	if err := p.Send(context.Background(), sdk.Message{To: []string{"a@example.com"}, Subject: "x", Text: "x"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(s.received()) != 1 {
		t.Fatal("message not received")
	}

	cfg["insecure_skip_verify"] = false
	p = newMailer(t, cfg)
	if err := p.Health(context.Background()); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
}

func TestHealth(t *testing.T) {
	s := newFakeServer(t, func(s *fakeServer) { s.starttls = true })
	p := newMailer(t, baseConfig(s, nil))
	if err := p.Health(context.Background()); err != nil {
		t.Fatalf("Health: %v", err)
	}
	if len(s.received()) != 0 {
		t.Fatal("Health sent a message")
	}
}

func TestHeaderInjectionRejected(t *testing.T) {
	s := newFakeServer(t, func(s *fakeServer) { s.starttls = true })
	p := newMailer(t, baseConfig(s, nil))
	for name, m := range map[string]sdk.Message{
		"subject":    {To: []string{"a@example.com"}, Subject: "hi\r\nBcc: victim@example.com", Text: "x"},
		"subject-lf": {To: []string{"a@example.com"}, Subject: "hi\nBcc: victim@example.com", Text: "x"},
		"recipient":  {To: []string{"a@example.com\r\nBcc: victim@example.com"}, Subject: "x", Text: "x"},
		"tag":        {To: []string{"a@example.com"}, Subject: "x", Text: "x", Tag: "t\r\nX-Evil: 1"},
		"bad-rcpt":   {To: []string{"not an address"}, Subject: "x", Text: "x"},
		"no-rcpt":    {Subject: "x", Text: "x"},
	} {
		if err := p.Send(context.Background(), m); !errors.Is(err, ErrInvalidMessage) {
			t.Errorf("%s: err = %v, want ErrInvalidMessage", name, err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions != 0 {
		t.Errorf("invalid messages opened %d connections", s.sessions)
	}
}

func TestContextCancellation(t *testing.T) {
	s := newFakeServer(t, func(s *fakeServer) { s.silent = true })
	p := newMailer(t, baseConfig(s, map[string]any{"timeout": "30s"}))
	m := sdk.Message{To: []string{"a@example.com"}, Subject: "x", Text: "x"}

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	err := p.Send(ctx, m)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("cancel: err = %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("cancel took %v", d)
	}

	ctx, cancel = context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start = time.Now()
	if err := p.Health(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("deadline: err = %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("deadline took %v", d)
	}
}

func TestConfiguredTimeout(t *testing.T) {
	s := newFakeServer(t, func(s *fakeServer) { s.silent = true })
	p := newMailer(t, baseConfig(s, map[string]any{"timeout": "200ms"}))
	start := time.Now()
	err := p.Send(context.Background(), sdk.Message{To: []string{"a@example.com"}, Subject: "x", Text: "x"})
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Errorf("err = %v, want timeout", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("timeout took %v", d)
	}
}

func TestConfigValidation(t *testing.T) {
	cases := map[string]map[string]any{
		"missing host":         {"from": "a@acme.io"},
		"missing from":         {"host": "smtp.acme.io"},
		"bad from":             {"host": "smtp.acme.io", "from": "not an address"},
		"bad reply_to":         {"host": "smtp.acme.io", "from": "a@acme.io", "reply_to": "nope"},
		"none without opt-in":  {"host": "localhost", "from": "a@acme.io", "tls": "none"},
		"none auth remote":     {"host": "smtp.acme.io", "from": "a@acme.io", "tls": "none", "allow_insecure": true, "username": "u"},
		"unknown tls":          {"host": "smtp.acme.io", "from": "a@acme.io", "tls": "ssl"},
		"bad port":             {"host": "smtp.acme.io", "from": "a@acme.io", "port": 70000},
		"bad timeout":          {"host": "smtp.acme.io", "from": "a@acme.io", "timeout": "soon"},
		"negative timeout":     {"host": "smtp.acme.io", "from": "a@acme.io", "timeout": "-1s"},
		"reserved header":      {"host": "smtp.acme.io", "from": "a@acme.io", "headers": map[string]any{"bcc": "x@y.z"}},
		"header injection":     {"host": "smtp.acme.io", "from": "a@acme.io", "headers": map[string]any{"X-A": "1\r\nBcc: x@y.z"}},
		"bad header name":      {"host": "smtp.acme.io", "from": "a@acme.io", "headers": map[string]any{"X A": "1"}},
		"unknown field":        {"host": "smtp.acme.io", "from": "a@acme.io", "ssl": true},
		"from with line break": {"host": "smtp.acme.io", "from": "a@acme.io\r\nBcc: x@y.z"},
	}
	for name, cfg := range cases {
		reg := sdktest.NewRegistrar(cfg)
		if err := (&Plugin{}).Init(context.Background(), reg); err == nil {
			t.Errorf("%s: Init succeeded", name)
		}
		if reg.MailerImpl != nil {
			t.Errorf("%s: mailer registered", name)
		}
	}

	ok := map[string]map[string]any{
		"defaults":       {"host": "smtp.acme.io", "from": "Acme <a@acme.io>"},
		"implicit":       {"host": "smtp.acme.io", "from": "a@acme.io", "tls": "implicit"},
		"none local":     {"host": "localhost", "from": "a@acme.io", "tls": "none", "allow_insecure": true, "username": "u"},
		"none anonymous": {"host": "mailpit", "from": "a@acme.io", "tls": "none", "allow_insecure": true},
	}
	for name, cfg := range ok {
		p := newMailer(t, cfg)
		switch name {
		case "defaults":
			if p.cfg.Port != 587 || p.cfg.TLS != TLSStartTLS || p.timeout != 15*time.Second {
				t.Errorf("defaults: port=%d tls=%q timeout=%v", p.cfg.Port, p.cfg.TLS, p.timeout)
			}
		case "implicit":
			if p.cfg.Port != 465 {
				t.Errorf("implicit: port=%d", p.cfg.Port)
			}
		}
	}
}

// TestMailpit sends through a real server, e.g.:
//
//	docker run -d -p 1025:1025 -p 8025:8025 axllent/mailpit
//	TENARIUM_TEST_SMTP_ADDR=127.0.0.1:1025 go test ./plugins/smtp/ -run Mailpit
func TestMailpit(t *testing.T) {
	addr := os.Getenv("TENARIUM_TEST_SMTP_ADDR")
	if addr == "" {
		t.Skip("TENARIUM_TEST_SMTP_ADDR not set")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	pn, _ := strconv.Atoi(port)
	p := newMailer(t, map[string]any{
		"host": host, "port": pn, "from": "Tenarium <no-reply@tenarium.test>",
		"tls": "none", "allow_insecure": true,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.Health(ctx); err != nil {
		t.Fatalf("Health: %v", err)
	}
	err = p.Send(ctx, sdk.Message{
		To:      []string{"Jürgen <jm@example.com>"},
		Subject: "Grüße " + time.Now().Format(time.RFC3339),
		Text:    "Hallo!",
		HTML:    "<p>Hallo!</p>",
		Tag:     "integration_test",
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
}
