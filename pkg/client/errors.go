package client

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Error is a non-2xx API response. The server reports errors as
// {"error":{"code","message","field"}}.
type Error struct {
	// Status is the HTTP status code.
	Status int
	// Code is the machine-readable error code, e.g. "not_found",
	// "version_conflict", "quota_exceeded", "validation_failed".
	Code    string
	Message string
	// Field names the offending input field or, for quota errors, the metric.
	Field string
	// RequestID is the server's X-Request-ID, useful when reporting issues.
	RequestID string
	// RetryAfter is the server's Retry-After hint, if any.
	RetryAfter time.Duration
}

func (e *Error) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "tenarium: %d", e.Status)
	if e.Code != "" {
		b.WriteString(" " + e.Code)
	}
	if e.Message != "" {
		b.WriteString(": " + e.Message)
	}
	if e.Field != "" {
		b.WriteString(" (field " + e.Field + ")")
	}
	if e.RequestID != "" {
		b.WriteString(" [request " + e.RequestID + "]")
	}
	return b.String()
}

func parseError(resp *http.Response, raw []byte) *Error {
	e := &Error{Status: resp.StatusCode, RequestID: resp.Header.Get("X-Request-ID"), RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"))}
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Field   string `json:"field"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &body) == nil && body.Error.Code != "" {
		e.Code, e.Message, e.Field = body.Error.Code, body.Error.Message, body.Error.Field
		return e
	}
	e.Message = strings.TrimSpace(string(raw))
	if len(e.Message) > 200 {
		e.Message = e.Message[:200] + "..."
	}
	if e.Message == "" {
		e.Message = http.StatusText(resp.StatusCode)
	}
	return e
}

func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(time.Until(t), 0)
	}
	return 0
}

// AsError returns the *Error in err's chain, if any.
func AsError(err error) (*Error, bool) {
	var e *Error
	ok := errors.As(err, &e)
	return e, ok
}

func hasStatus(err error, status int) bool {
	e, ok := AsError(err)
	return ok && e.Status == status
}

func hasCode(err error, code string) bool {
	e, ok := AsError(err)
	return ok && e.Code == code
}

// IsNotFound reports a 404 response.
func IsNotFound(err error) bool { return hasStatus(err, http.StatusNotFound) }

// IsConflict reports a 409 response (already exists, invalid transition).
func IsConflict(err error) bool { return hasStatus(err, http.StatusConflict) }

// IsVersionConflict reports a 412 response: the resource changed since the
// version passed to IfMatch.
func IsVersionConflict(err error) bool { return hasStatus(err, http.StatusPreconditionFailed) }

// IsQuotaExceeded reports a refused usage increment; Error.Field is the metric.
func IsQuotaExceeded(err error) bool { return hasCode(err, "quota_exceeded") }

// IsForbidden reports a 403 response.
func IsForbidden(err error) bool { return hasStatus(err, http.StatusForbidden) }

// IsUnauthorized reports a 401 response (missing, invalid or expired credentials).
func IsUnauthorized(err error) bool { return hasStatus(err, http.StatusUnauthorized) }

// IsValidation reports a 400 validation_failed response.
func IsValidation(err error) bool { return hasCode(err, "validation_failed") }

func newIdempotencyKey() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
