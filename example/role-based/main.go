// Example: role-based permissions using SSO claims.
//
// Uses roles/groups from the OIDC token (stored in UserClaims.Extra)
// to determine which NATS subjects each user can access.
//
// Works with Keycloak realm roles, Okta groups, Auth0 roles, etc.
// The key name in Extra depends on your SSO provider's token format.
package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"time"

	natsauth "github.com/joey0538/nats-jwt-auth"
)

func main() {
	// Custom structured logger — JSON to stdout with source info
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slog.LevelDebug,
		AddSource: true,
	}))

	srv, err := natsauth.NewServer(context.Background(),
		natsauth.Config{
			OIDCIssuerURL:   os.Getenv("OIDC_ISSUER_URL"),
			OIDCAudience:    os.Getenv("OIDC_AUDIENCE"),
			NATSAccountSeed: os.Getenv("NATS_ACCOUNT_SEED"),
			NATSJWTExpiry:   30 * time.Minute,                       // shorter expiry for sensitive env
			OIDCVerifyAZP:   os.Getenv("OIDC_VERIFY_AZP") == "true", // Keycloak: verify azp instead of aud
		},

		// Override: custom logger
		natsauth.WithLogger(logger),

		// Override: role-based permissions from SSO claims
		natsauth.WithPermissionsProvider(&RoleBasedProvider{}),
	)
	if err != nil {
		log.Fatal(err)
	}
	if err := srv.Run(); err != nil {
		log.Fatal(err)
	}
}

// RoleBasedProvider implements PermissionsProvider as a full struct.
// Use this pattern when your permissions logic is complex enough
// to warrant its own type with methods.
type RoleBasedProvider struct{}

func (p *RoleBasedProvider) GetPermissions(_ context.Context, user natsauth.UserClaims) (natsauth.Permissions, error) {
	// Extract roles from SSO token.
	// The key depends on your provider:
	//   Keycloak:  user.Extra["realm_access"].(map)["roles"].([]any)
	//   Okta:      user.Extra["groups"].([]any)
	//   Auth0:     user.Extra["https://myapp.com/roles"].([]any)
	roles := extractRoles(user.Extra)

	// No roles at all → reject with 403 (not a 500)
	if len(roles) == 0 {
		return natsauth.Permissions{}, natsauth.NewAccessDeniedError("no roles assigned to user")
	}

	var pubAllow, subAllow []string

	// Everyone gets their personal inbox
	personal := fmt.Sprintf("user.%s.>", user.Subject)
	pubAllow = append(pubAllow, personal)
	subAllow = append(subAllow, personal)

	for _, role := range roles {
		switch role {
		case "admin":
			// Admins can pub/sub everything
			pubAllow = append(pubAllow, ">")
			subAllow = append(subAllow, ">")

		case "moderator":
			// Moderators can read all rooms but only publish to moderation subjects
			subAllow = append(subAllow, "room.>")
			pubAllow = append(pubAllow, "room.>", "moderation.>")

		case "user":
			// Regular users get standard room access
			subAllow = append(subAllow, "room.general", "room.announcements")
			pubAllow = append(pubAllow, "room.general")

		case "engineering":
			subAllow = append(subAllow, "room.engineering", "deploy.>")
			pubAllow = append(pubAllow, "room.engineering")

		case "disabled":
			// Explicitly blocked users — 403
			return natsauth.Permissions{}, natsauth.NewAccessDeniedError("account is disabled")
		}
	}

	return natsauth.Permissions{
		PubAllow: pubAllow,
		SubAllow: subAllow,
	}, nil
}

// extractRoles pulls role strings from OIDC Extra claims.
// Handles Keycloak's nested realm_access.roles format.
func extractRoles(extra map[string]interface{}) []string {
	var roles []string

	// Keycloak: { "realm_access": { "roles": ["user", "admin"] } }
	if ra, ok := extra["realm_access"].(map[string]interface{}); ok {
		if rawRoles, ok := ra["roles"].([]interface{}); ok {
			for _, r := range rawRoles {
				if s, ok := r.(string); ok {
					roles = append(roles, s)
				}
			}
		}
	}

	// Okta / Auth0: { "groups": ["engineering", "admin"] }
	if rawGroups, ok := extra["groups"].([]interface{}); ok {
		for _, g := range rawGroups {
			if s, ok := g.(string); ok {
				roles = append(roles, s)
			}
		}
	}

	return roles
}
