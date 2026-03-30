// Example: embedding natsauth into an existing Echo server.
//
// Use this pattern when your team already has an HTTP server and you
// want to add the /nats/auth endpoint alongside your other routes.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/labstack/echo/v4"

	natsauth "github.com/joey0538/nats-jwt-auth"
)

func main() {
	ctx := context.Background()

	srv, err := natsauth.NewServer(ctx,
		natsauth.Config{
			OIDCIssuerURL:   os.Getenv("OIDC_ISSUER_URL"),
			OIDCAudience:    os.Getenv("OIDC_AUDIENCE"),
			NATSAccountSeed: os.Getenv("NATS_ACCOUNT_SEED"),
			NATSJWTExpiry:   time.Hour,
			OIDCVerifyAZP:   os.Getenv("OIDC_VERIFY_AZP") == "true", // Keycloak: verify azp instead of aud
		},
		natsauth.WithPermissionsProvider(
			natsauth.PermissionsProviderFunc(func(_ context.Context, user natsauth.UserClaims) (natsauth.Permissions, error) {
				rooms := []string{"room.general", fmt.Sprintf("user.%s.>", user.Subject)}
				return natsauth.Permissions{PubAllow: rooms, SubAllow: rooms}, nil
			}),
		),
	)
	if err != nil {
		log.Fatalf("failed to create natsauth server: %v", err)
	}

	// Your existing Echo server
	e := echo.New()
	e.GET("/healthz", func(c echo.Context) error {
		return c.String(200, "ok")
	})

	// Mount natsauth routes under /nats prefix
	// This adds:
	//   POST /nats/auth    — the auth endpoint frontends call
	//   GET  /nats/health  — health check for the auth subsystem
	srv.MountOn(e, "/nats")

	log.Fatal(e.Start(":8080"))
}
