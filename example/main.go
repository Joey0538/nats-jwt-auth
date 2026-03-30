// Example: how a team uses the natsauth package in their own service.
//
// This shows the minimal code a team needs to write. Everything else
// (OIDC validation, NATS JWT signing, HTTP server) is handled by the library.
//
// Run:
//
//	OIDC_ISSUER_URL=https://sso.company.com/realms/chat \
//	OIDC_AUDIENCE=my-chat-app \
//	NATS_ACCOUNT_SEED=SA... \
//	go run ./example
//
// If your Keycloak puts the client_id in "azp" instead of "aud":
//
//	OIDC_VERIFY_AZP=true go run ./example
package main

import (
	"context"
	"fmt"
	"log"

	natsauth "github.com/joey0538/nats-jwt-auth"
)

func main() {
	// LoadConfig reads from env vars + optional .env file via Viper.
	// No manual os.Getenv needed — just set your env vars and go.
	cfg, err := natsauth.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}

	srv, err := natsauth.NewServer(context.Background(), cfg,
		// This is the only part each team customizes — the permissions logic.
		// Here we look up which chat rooms the user belongs to and grant
		// publish/subscribe access to those room subjects in NATS.
		natsauth.WithPermissionsProvider(
			natsauth.PermissionsProviderFunc(func(_ context.Context, user natsauth.UserClaims) (natsauth.Permissions, error) {
				// Replace this with your actual DB/service call:
				//   rooms, err := db.GetRoomsForUser(ctx, user.Subject)
				rooms := []string{
					"room.general",
					"room.engineering",
					fmt.Sprintf("user.%s.>", user.Subject), // personal inbox
				}

				// To reject a user with 403 Forbidden:
				//   return natsauth.Permissions{}, natsauth.NewAccessDeniedError("not allowed")
				// Any other error returns 500 Internal Server Error.

				return natsauth.Permissions{
					PubAllow: rooms,
					SubAllow: rooms,
				}, nil
			}),
		),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Blocks until SIGINT/SIGTERM
	if err := srv.Run(); err != nil {
		log.Fatal(err)
	}
}
