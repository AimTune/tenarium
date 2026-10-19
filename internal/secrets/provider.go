package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"strings"
	"time"
)

// KeyProvider wraps and unwraps data-encryption keys (DEKs) with a
// key-encryption key (KEK) that ideally never leaves a KMS.
//
// Implementations must be safe for concurrent use.
type KeyProvider interface {
	// Name is the provider tag written into ciphertexts ("local", "awskms",
	// "gcpkms", "vault", "azurekv"). Lower-case letters, digits, '-' or '_'.
	Name() string
	// Wrap encrypts dek with the provider's current (primary) key and returns
	// the id of the key that was used, which is stored in the ciphertext and
	// handed back to Unwrap.
	Wrap(ctx context.Context, dek []byte) (keyID string, wrapped []byte, err error)
	// Unwrap decrypts a DEK previously produced by Wrap with keyID.
	Unwrap(ctx context.Context, keyID string, wrapped []byte) ([]byte, error)
}

// dekContext is bound to every DEK wrap where the provider supports
// additional data / encryption context. DEKs are shared by many values, so
// the per-value aad cannot be used here; it is bound by the data AEAD.
const dekContext = "tenarium/secrets/dek/v1"

const (
	defaultHTTPTimeout = 30 * time.Second
	maxAttempts        = 3
	maxResponseBytes   = 1 << 20
)

// httpError is a non-2xx response from a KMS endpoint.
type httpError struct {
	provider string
	status   int
	body     string
}

func (e *httpError) Error() string {
	return fmt.Sprintf("secrets: %s: HTTP %d: %s", e.provider, e.status, e.body)
}

func retryable(err error) bool {
	var he *httpError
	if errors.As(err, &he) {
		return he.status == http.StatusTooManyRequests || he.status >= 500 ||
			// AWS reports throttling as 400 ThrottlingException.
			(he.status == http.StatusBadRequest && strings.Contains(he.body, "ThrottlingException"))
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return true
	}
	return errors.Is(err, io.ErrUnexpectedEOF)
}

// doJSON sends a request built by build (called once per attempt, so signed
// requests get a fresh signature) and decodes a JSON response into out.
// Throttling, 5xx and transport errors are retried with jittered backoff.
func doJSON(ctx context.Context, client *http.Client, provider string, build func() (*http.Request, error), out any) error {
	var err error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			d := time.Duration(100<<attempt)*time.Millisecond + time.Duration(rand.IntN(100))*time.Millisecond //nolint:gosec // jitter needs no cryptographic randomness
			t := time.NewTimer(d)
			select {
			case <-ctx.Done():
				t.Stop()
				return ctx.Err()
			case <-t.C:
			}
		}
		err = doOnce(ctx, client, provider, build, out)
		if err == nil || ctx.Err() != nil || !retryable(err) {
			return err
		}
	}
	return err
}

func doOnce(ctx context.Context, client *http.Client, provider string, build func() (*http.Request, error), out any) error {
	req, err := build()
	if err != nil {
		return err
	}
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("secrets: %s: %w", provider, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("secrets: %s: reading response: %w", provider, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := string(body)
		if len(msg) > 512 {
			msg = msg[:512]
		}
		return &httpError{provider: provider, status: resp.StatusCode, body: msg}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("secrets: %s: decoding response: %w", provider, err)
	}
	return nil
}

// jsonRequest builds a JSON POST request to url bound to ctx.
func jsonRequest(ctx context.Context, url string, payload any) (*http.Request, []byte, error) {
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			return nil, nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return req, body, nil
}

func httpClientOr(c *http.Client, timeout time.Duration) *http.Client {
	if c != nil {
		return c
	}
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	return &http.Client{Timeout: timeout}
}
