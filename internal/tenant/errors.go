package tenant

import (
	"errors"
	"fmt"
)

// ValidationError reports invalid input.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string { return e.Field + ": " + e.Message }

func invalid(field, format string, args ...any) error {
	return &ValidationError{Field: field, Message: fmt.Sprintf(format, args...)}
}

// ErrInvalidTransition is returned when an operation is not allowed in the
// current state (e.g. resuming an active tenant, deleting a plan in use).
var ErrInvalidTransition = errors.New("invalid state transition")

func transitionErr(op string, from any) error {
	return fmt.Errorf("%w: cannot %s a tenant in status %q", ErrInvalidTransition, op, from)
}

func stateErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidTransition, fmt.Sprintf(format, args...))
}

// QuotaError is returned when an operation would exceed a tenant limit.
type QuotaError struct {
	Metric  string
	Limit   int64
	Current int64
}

func (e *QuotaError) Error() string {
	return fmt.Sprintf("quota exceeded for %q: %d of %d used", e.Metric, e.Current, e.Limit)
}
