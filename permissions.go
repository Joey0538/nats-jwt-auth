package natsauth

import (
	"context"
	"errors"
	"fmt"
)

// UserClaims holds the validated identity extracted from the SSO token.
// This is passed to your PermissionsProvider so you can make decisions
// based on who the user is.
type UserClaims struct {
	Extra             map[string]interface{}
	Subject           string
	Email             string
	Name              string
	PreferredUsername string
	GivenName         string
	FamilyName        string
}

// Permissions defines what NATS subjects a user can publish and subscribe to.
// Your PermissionsProvider returns this after looking up the user's access rights.
type Permissions struct {
	// PubAllow is the list of NATS subjects this user can publish to
	// Wildcards supported: "chat.>" means any subject starting with chat.
	PubAllow []string

	// SubAllow is the list of NATS subjects this user can subscribe to
	SubAllow []string

	// PubDeny explicitly blocks publishing to these subjects (optional)
	PubDeny []string

	// SubDeny explicitly blocks subscribing to these subjects (optional)
	SubDeny []string
}

// ErrAccessDenied is returned from PermissionsProvider.GetPermissions to
// indicate that the user is not allowed to connect. The auth endpoint will
// respond with 403 Forbidden instead of 500 Internal Server Error.
//
// Use AccessDeniedError to include a reason:
//
//	return natsauth.Permissions{}, natsauth.NewAccessDeniedError("user is deactivated")
var ErrAccessDenied = errors.New("natsauth: access denied")

// AccessDeniedError is an error with a reason message that triggers a 403 response.
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
// The reason is returned to the client in the 403 response.
func NewAccessDeniedError(reason string) error {
	return &AccessDeniedError{Reason: reason}
}

// PermissionsProvider is the interface your team implements to control
// what each user is allowed to do in NATS.
//
// This is called on every POST /auth request (i.e. when a client first
// connects or when their JWT expires and they reconnect).
//
// Return ErrAccessDenied (or NewAccessDeniedError) to reject the user
// with a 403. Any other error returns a 500.
//
// Example implementations:
//   - Look up rooms a user belongs to from your DB
//   - Call an internal ACL/permissions service
//   - Return static permissions based on SSO roles
type PermissionsProvider interface {
	GetPermissions(ctx context.Context, user UserClaims) (Permissions, error)
}

// PermissionsProviderFunc is a convenience type so teams can pass a plain
// function instead of implementing a full interface.
//
// Usage:
//
//	natsauth.PermissionsProviderFunc(func(ctx context.Context, user natsauth.UserClaims) (natsauth.Permissions, error) {
//	    rooms, err := db.GetRoomsForUser(ctx, user.Subject)
//	    ...
//	})
type PermissionsProviderFunc func(ctx context.Context, user UserClaims) (Permissions, error)

// GetPermissions calls the underlying function.
func (f PermissionsProviderFunc) GetPermissions(ctx context.Context, user UserClaims) (Permissions, error) {
	return f(ctx, user)
}

// DefaultPermissionsProvider is used when a team does not provide their own.
// It gives every authenticated user access to chat.>, room.> and their own user subject.
// Fine for simple use cases — override this for production chat room logic.
type DefaultPermissionsProvider struct{}

// GetPermissions returns default permissions allowing chat.>, room.>, and user.<sub>.>.
func (DefaultPermissionsProvider) GetPermissions(_ context.Context, user UserClaims) (Permissions, error) {
	return Permissions{
		PubAllow: []string{
			"chat.>",
			"room.>",
			"user." + user.Subject + ".>",
		},
		SubAllow: []string{
			"chat.>",
			"room.>",
			"user." + user.Subject + ".>",
		},
	}, nil
}
