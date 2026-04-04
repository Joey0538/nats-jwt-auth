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
//	go run ./examples/basic
package main

import (
	"context"
	"fmt"
	"log"

	natsauth "github.com/joey0538/nats-jwt-auth"
	"github.com/joey0538/nats-jwt-auth/echoserver"
	"github.com/joey0538/nats-jwt-auth/viperconfig"
)

func main() {
	cfg, err := viperconfig.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}

	srv, err := echoserver.New(context.Background(), cfg,
		natsauth.WithPermissionsProvider(
			natsauth.PermissionsProviderFunc(func(_ context.Context, user natsauth.UserClaims) (natsauth.Permissions, error) {
				rooms := []string{
					"room.general",
					"room.engineering",
					fmt.Sprintf("user.%s.>", user.Subject),
				}
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

	if err := srv.Run(); err != nil {
		log.Fatal(err)
	}
}
