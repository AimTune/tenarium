package siem

import (
	"cmp"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SyslogConfig configures the syslog sink.
type SyslogConfig struct {
	// Address is host:port of the collector.
	Address string `json:"address"`
	// Network is "tcp" (default), "tls" or "udp".
	Network string `json:"network"`
	// Format of the message: "json" (default) or "cef".
	Format string `json:"format"`
	// Framing for tcp/tls: "octet_counting" (default, RFC 6587/5425) or
	// "non_transparent" (newline-terminated).
	Framing string `json:"framing"`
	// Facility defaults to 13 (log audit).
	Facility *int `json:"facility"`
	// Severity of regular events, default 6 (informational). Failed
	// operations are sent with 4 (warning).
	Severity *int `json:"severity"`
	// AppName defaults to "tenarium".
	AppName string `json:"app_name"`
	// Hostname defaults to the machine's host name.
	Hostname string `json:"hostname"`
	// SDID is the structured data ID carrying key fields, default
	// "tenarium@32473" (32473 is the example enterprise number of RFC
	// 5612; use your own if you have one). "-" disables structured data.
	SDID string     `json:"sd_id"`
	TLS  *TLSConfig `json:"tls"`
}

type syslogSink struct {
	cfg      SyslogConfig
	facility int
	severity int
	timeout  time.Duration
	tls      *tls.Config
	pid      string

	mu   sync.Mutex
	conn net.Conn
	// closed is set by close; the sink then no longer dials.
	closed bool
	// dial is replaceable in tests.
	dial func(ctx context.Context) (net.Conn, error)
}

func newSyslogSink(c SyslogConfig, timeout time.Duration) (*syslogSink, error) {
	host, port, err := net.SplitHostPort(c.Address)
	if err != nil || host == "" || port == "" {
		return nil, fmt.Errorf("address must be host:port, got %q", c.Address)
	}
	c.Network = cmp.Or(c.Network, "tcp")
	switch c.Network {
	case "tcp", "tls", "udp":
	default:
		return nil, fmt.Errorf("network must be tcp, tls or udp, got %q", c.Network)
	}
	c.Format = cmp.Or(c.Format, "json")
	if c.Format != "json" && c.Format != "cef" {
		return nil, fmt.Errorf("format must be json or cef, got %q", c.Format)
	}
	c.Framing = cmp.Or(c.Framing, "octet_counting")
	if c.Framing != "octet_counting" && c.Framing != "non_transparent" {
		return nil, fmt.Errorf("framing must be octet_counting or non_transparent, got %q", c.Framing)
	}
	s := &syslogSink{facility: 13, severity: 6, timeout: timeout, pid: strconv.Itoa(os.Getpid())}
	if c.Facility != nil {
		if *c.Facility < 0 || *c.Facility > 23 {
			return nil, fmt.Errorf("facility must be 0-23, got %d", *c.Facility)
		}
		s.facility = *c.Facility
	}
	if c.Severity != nil {
		if *c.Severity < 0 || *c.Severity > 7 {
			return nil, fmt.Errorf("severity must be 0-7, got %d", *c.Severity)
		}
		s.severity = *c.Severity
	}
	c.AppName = cmp.Or(c.AppName, "tenarium")
	if !printableASCII(c.AppName, 48) {
		return nil, fmt.Errorf("app_name must be 1-48 printable ASCII characters, got %q", c.AppName)
	}
	if c.Hostname == "" {
		c.Hostname, _ = os.Hostname()
		c.Hostname = cmp.Or(c.Hostname, "-")
		if !printableASCII(c.Hostname, 255) {
			c.Hostname = "-"
		}
	} else if !printableASCII(c.Hostname, 255) {
		return nil, fmt.Errorf("hostname must be 1-255 printable ASCII characters, got %q", c.Hostname)
	}
	c.SDID = cmp.Or(c.SDID, "tenarium@32473")
	if c.SDID != "-" {
		name, num, ok := strings.Cut(c.SDID, "@")
		if !ok || name == "" || num == "" || !printableASCII(c.SDID, 32) || strings.ContainsAny(c.SDID, `= ]"`) {
			return nil, fmt.Errorf("sd_id must look like name@enterprise-number, got %q", c.SDID)
		}
	}
	if c.Network == "tls" {
		tc, err := buildTLS(c.TLS)
		if err != nil {
			return nil, err
		}
		if tc == nil {
			tc = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		if tc.ServerName == "" {
			tc.ServerName = host
		}
		s.tls = tc
	} else if c.TLS != nil {
		return nil, errors.New("tls applies only to network tls")
	}
	s.cfg = c
	s.dial = s.defaultDial
	return s, nil
}

func printableASCII(s string, maxLen int) bool {
	if s == "" || len(s) > maxLen {
		return false
	}
	for i := range len(s) {
		if s[i] < 33 || s[i] > 126 {
			return false
		}
	}
	return true
}

func (s *syslogSink) defaultDial(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: s.timeout}
	switch s.cfg.Network {
	case "tls":
		td := tls.Dialer{NetDialer: &d, Config: s.tls}
		return td.DialContext(ctx, "tcp", s.cfg.Address)
	default:
		return d.DialContext(ctx, s.cfg.Network, s.cfg.Address)
	}
}

func (s *syslogSink) send(ctx context.Context, r Record) error {
	msg, err := s.format(r)
	if err != nil {
		return err
	}
	frame := msg
	if s.cfg.Network != "udp" {
		if s.cfg.Framing == "octet_counting" {
			frame = strconv.Itoa(len(msg)) + " " + msg
		} else {
			frame = msg + "\n"
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// One reconnect attempt: a pooled TCP connection may have been closed
	// by the collector since the last event.
	for attempt := 0; ; attempt++ {
		if s.conn == nil {
			if s.closed {
				return errors.New("syslog: sink closed (plugin stopped or reconfigured)")
			}
			c, err := s.dial(ctx)
			if err != nil {
				return fmt.Errorf("syslog: dial %s: %w", s.cfg.Address, err)
			}
			s.conn = c
		}
		deadline := time.Now().Add(s.timeout)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		_ = s.conn.SetWriteDeadline(deadline)
		_, err = s.conn.Write([]byte(frame))
		if err == nil {
			return nil
		}
		_ = s.conn.Close()
		s.conn = nil
		if attempt > 0 || ctx.Err() != nil {
			return fmt.Errorf("syslog: write: %w", err)
		}
	}
}

// format renders an RFC 5424 message (without transport framing).
func (s *syslogSink) format(r Record) (string, error) {
	sev := s.severity
	if r.Outcome == "failure" && sev > 4 {
		sev = 4
	}
	var msg string
	if s.cfg.Format == "cef" {
		msg = cef(r)
	} else {
		b, err := json.Marshal(r)
		if err != nil {
			return "", err
		}
		msg = string(b)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "<%d>1 %s %s %s %s %s ", s.facility*8+sev,
		r.Time.UTC().Format("2006-01-02T15:04:05.000000Z07:00"),
		s.cfg.Hostname, s.cfg.AppName, s.pid, msgID(r.Type))
	if s.cfg.SDID == "-" {
		b.WriteString("-")
	} else {
		b.WriteString("[" + s.cfg.SDID)
		for _, kv := range r.fields() {
			b.WriteString(" " + sdName(kv[0]) + `="` + sdEscape(kv[1]) + `"`)
		}
		b.WriteString("]")
	}
	b.WriteString(" ")
	b.WriteString(msg)
	return b.String(), nil
}

// msgID turns an event type into an RFC 5424 MSGID (1-32 printable ASCII).
func msgID(typ string) string {
	var b strings.Builder
	for i := range len(typ) {
		if c := typ[i]; c >= 33 && c <= 126 {
			b.WriteByte(c)
		}
		if b.Len() == 32 {
			break
		}
	}
	return cmp.Or(b.String(), "-")
}

// sdName makes a structured data parameter name (no '=', ' ', ']', '"').
func sdName(k string) string {
	return strings.Map(func(r rune) rune {
		if r < 33 || r > 126 || r == '=' || r == ']' || r == '"' {
			return '_'
		}
		return r
	}, k)
}

// sdEscape escapes a structured data parameter value (RFC 5424 6.3.3).
func sdEscape(v string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`).Replace(v)
}

// cef renders a record as an ArcSight Common Event Format line.
func cef(r Record) string {
	sev := "3"
	if r.Outcome == "failure" {
		sev = "7"
	}
	header := []string{"CEF:0", "Tenarium", "Tenarium", version, r.Type, r.Type, sev}
	for i := 1; i < len(header); i++ {
		header[i] = cefHeaderEscape(header[i])
	}
	ext := [][2]string{
		{"rt", strconv.FormatInt(r.Time.UnixMilli(), 10)},
		{"externalId", r.ID},
		{"cat", r.Type},
		{"outcome", r.Outcome},
		{"cn1Label", "sequence"}, {"cn1", strconv.FormatInt(r.Seq, 10)},
	}
	if r.Actor != "" {
		ext = append(ext, [2]string{"suser", r.Actor})
		if r.ActorID != "" {
			ext = append(ext, [2]string{"suid", r.ActorID})
		}
	}
	if r.TenantID != "" {
		ext = append(ext, [2]string{"cs1Label", "tenantId"}, [2]string{"cs1", r.TenantID})
	}
	if r.TenantSlug != "" {
		ext = append(ext, [2]string{"cs2Label", "tenantSlug"}, [2]string{"cs2", r.TenantSlug})
	}
	if r.Subject != "" {
		ext = append(ext, [2]string{"cs3Label", "subject"}, [2]string{"cs3", r.Subject})
	}
	if r.Source != "" {
		ext = append(ext, [2]string{"cs4Label", "source"}, [2]string{"cs4", r.Source})
	}
	if len(r.Data) > 0 {
		ext = append(ext, [2]string{"msg", string(r.Data)})
	}
	parts := make([]string, len(ext))
	for i, kv := range ext {
		parts[i] = kv[0] + "=" + cefExtEscape(kv[1])
	}
	return strings.Join(header, "|") + "|" + strings.Join(parts, " ")
}

func cefHeaderEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `|`, `\|`, "\r", " ", "\n", " ").Replace(s)
}

func cefExtEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\r\n", `\n`, "\n", `\n`, "\r", `\r`).Replace(s)
}

// health dials the collector (TCP/TLS), reusing an open connection.
func (s *syslogSink) health(ctx context.Context) error {
	if s.cfg.Network == "udp" {
		return nil // connectionless; nothing to check
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil || s.closed {
		return nil
	}
	c, err := s.dial(ctx)
	if err != nil {
		return err
	}
	s.conn = c
	return nil
}

func (s *syslogSink) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn = nil
	return err
}
