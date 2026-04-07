package natsauth

import "context"

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
	// PubAllow is the list of NATS subjects this user can publish to.
	// Wildcards supported: "chat.>" means any subject starting with chat.
	PubAllow []string

	// SubAllow is the list of NATS subjects this user can subscribe to.
	SubAllow []string

	// PubDeny explicitly blocks publishing to these subjects (optional).
	PubDeny []string

	// SubDeny explicitly blocks subscribing to these subjects (optional).
	SubDeny []string
}

// PermissionsProvider is the interface your team implements to control
// what each user is allowed to do in NATS.
//
// Called on every Authenticate call (i.e. when a client first connects
// or when their JWT expires and they reconnect).
//
// Return ErrAccessDenied (or NewAccessDeniedError) to reject the user.
// Any other error is treated as an internal failure.
//
// Example implementations:
//   - Look up rooms a user belongs to from your DB
//   - Call an internal ACL/permissions service
//   - Return static permissions based on SSO roles
type PermissionsProvider interface {
	GetPermissions(ctx context.Context, user *UserClaims) (Permissions, error)
}

// PermissionsProviderFunc is a convenience type so teams can pass a plain
// function instead of implementing a full interface.
type PermissionsProviderFunc func(ctx context.Context, user *UserClaims) (Permissions, error)

// GetPermissions calls the underlying function.
func (f PermissionsProviderFunc) GetPermissions(ctx context.Context, user *UserClaims) (Permissions, error) {
	return f(ctx, user)
}

// DefaultPermissionsProvider is used when a team does not provide their own.
// It gives every authenticated user access to chat.>, room.> and their own user subject.
type DefaultPermissionsProvider struct{}

// GetPermissions returns default permissions allowing chat.>, room.>, and user.<sub>.>.
func (DefaultPermissionsProvider) GetPermissions(_ context.Context, user *UserClaims) (Permissions, error) {
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
