// Example: role-based permissions using SSO claims.
//
// Uses roles/groups from the OIDC token (stored in UserClaims.Extra)
// to determine which NATS subjects each user can access.
package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"time"

	natsauth "github.com/joey0538/nats-jwt-auth"
	"github.com/joey0538/nats-jwt-auth/echoserver"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slog.LevelDebug,
		AddSource: true,
	}))

	srv, err := echoserver.New(context.Background(),
		natsauth.Config{
			OIDCIssuerURL:   os.Getenv("OIDC_ISSUER_URL"),
			OIDCAudience:    os.Getenv("OIDC_AUDIENCE"),
			NATSAccountSeed: os.Getenv("NATS_ACCOUNT_SEED"),
			NATSJWTExpiry:   30 * time.Minute,
		},
		natsauth.WithLogger(logger),
		natsauth.WithPermissionsProvider(&RoleBasedProvider{}),
	)
	if err != nil {
		log.Fatal(err)
	}
	if err := srv.Run(); err != nil {
		log.Fatal(err)
	}
}

type RoleBasedProvider struct{}

func (p *RoleBasedProvider) GetPermissions(_ context.Context, user natsauth.UserClaims) (natsauth.Permissions, error) {
	roles := extractRoles(user.Extra)
	if len(roles) == 0 {
		return natsauth.Permissions{}, natsauth.NewAccessDeniedError("no roles assigned to user")
	}

	var pubAllow, subAllow []string

	personal := fmt.Sprintf("user.%s.>", user.Subject)
	pubAllow = append(pubAllow, personal)
	subAllow = append(subAllow, personal)

	for _, role := range roles {
		switch role {
		case "admin":
			pubAllow = append(pubAllow, ">")
			subAllow = append(subAllow, ">")
		case "moderator":
			subAllow = append(subAllow, "room.>")
			pubAllow = append(pubAllow, "room.>", "moderation.>")
		case "user":
			subAllow = append(subAllow, "room.general", "room.announcements")
			pubAllow = append(pubAllow, "room.general")
		case "engineering":
			subAllow = append(subAllow, "room.engineering", "deploy.>")
			pubAllow = append(pubAllow, "room.engineering")
		case "disabled":
			return natsauth.Permissions{}, natsauth.NewAccessDeniedError("account is disabled")
		}
	}

	return natsauth.Permissions{PubAllow: pubAllow, SubAllow: subAllow}, nil
}

func extractRoles(extra map[string]interface{}) []string {
	var roles []string
	if ra, ok := extra["realm_access"].(map[string]interface{}); ok {
		if rawRoles, ok := ra["roles"].([]interface{}); ok {
			for _, r := range rawRoles {
				if s, ok := r.(string); ok {
					roles = append(roles, s)
				}
			}
		}
	}
	if rawGroups, ok := extra["groups"].([]interface{}); ok {
		for _, g := range rawGroups {
			if s, ok := g.(string); ok {
				roles = append(roles, s)
			}
		}
	}
	return roles
}
