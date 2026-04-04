package natsauth

import (
	"errors"
	"fmt"
)

// Sentinel errors returned by Authenticate. Callers use errors.Is to map
// these to HTTP status codes (or whatever their framework requires).
//
// Suggested HTTP mapping:
//
//	ErrMissingToken, ErrMissingNKey, ErrInvalidNKey → 400
//	ErrTokenExpired, ErrInvalidToken                → 401
//	ErrAccessDenied                                 → 403
//	ErrSigningFailed, ErrPermissionLookup           → 500
var (
	ErrMissingToken     = errors.New("natsauth: sso_token is required")
	ErrMissingNKey      = errors.New("natsauth: nats_public_key is required")
	ErrInvalidNKey      = errors.New("natsauth: invalid nats_public_key format (must start with U)")
	ErrTokenExpired     = errors.New("natsauth: SSO token has expired")
	ErrInvalidToken     = errors.New("natsauth: invalid SSO token")
	ErrSigningFailed    = errors.New("natsauth: failed to sign NATS JWT")
	ErrPermissionLookup = errors.New("natsauth: failed to resolve permissions")

	// ErrAccessDenied is returned from PermissionsProvider.GetPermissions to
	// indicate that the user is not allowed to connect. Use NewAccessDeniedError
	// to include a reason.
	ErrAccessDenied = errors.New("natsauth: access denied")
)

// AccessDeniedError is an error with a reason message.
type AccessDeniedError struct {
	Reason string
}

func (e *AccessDeniedError) Error() string {
	return fmt.Sprintf("natsauth: access denied: %s", e.Reason)
}

// Unwrap lets errors.Is(err, ErrAccessDenied) work.
func (e *AccessDeniedError) Unwrap() error {
	return ErrAccessDenied
}

// NewAccessDeniedError creates an AccessDeniedError with a reason.
func NewAccessDeniedError(reason string) error {
	return &AccessDeniedError{Reason: reason}
}
