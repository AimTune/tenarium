package siem

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// maxResponse bounds response bodies read from sinks.
const maxResponse = 4 << 20

// buildTLS turns a TLSConfig into a *tls.Config. It returns nil when c is
// nil, meaning system defaults.
func buildTLS(c *TLSConfig) (*tls.Config, error) {
	if c == nil {
		return nil, nil
	}
	tc := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         c.ServerName,
		InsecureSkipVerify: c.InsecureSkipVerify, //nolint:gosec // explicit operator opt-in
	}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("tls.ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("tls.ca_file: no PEM certificates in %s", c.CAFile)
		}
		tc.RootCAs = pool
	}
	if (c.CertFile == "") != (c.KeyFile == "") {
		return nil, errors.New("tls.cert_file and tls.key_file must be set together")
	}
	if c.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("tls: client certificate: %w", err)
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	return tc, nil
}

// httpClient returns a client with the timeout and optional TLS settings.
func httpClient(timeout time.Duration, c *TLSConfig) (*http.Client, error) {
	tc, err := buildTLS(c)
	if err != nil {
		return nil, err
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if tc != nil {
		tr.TLSClientConfig = tc
	}
	return &http.Client{Timeout: timeout, Transport: tr}, nil
}

// parseBase validates an absolute http(s) base URL and strips trailing
// slashes.
func parseBase(field, raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("%s must be an absolute http(s) URL, got %q", field, raw)
	}
	return strings.TrimRight(raw, "/"), nil
}

// doRequest sends a request and returns the (bounded) response body. A
// non-2xx status is returned as an error that includes a body excerpt.
func doRequest(ctx context.Context, client *http.Client, method, u string, body []byte, header http.Header) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header.Set("User-Agent", "tenarium-siem/"+version)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return raw, fmt.Errorf("%s %s: %s: %s", method, redactURL(u), resp.Status, excerpt(raw))
	}
	return raw, nil
}

// redactURL drops credentials and the query from a URL for error messages.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<url>"
	}
	u.User, u.RawQuery = nil, ""
	return u.String()
}

func excerpt(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 512 {
		s = s[:512] + "..."
	}
	return s
}
