// Example: every possible override in one place.
//
// Demonstrates the full customization surface of the natsauth package.
package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	natsauth "github.com/joey0538/nats-jwt-auth"
	"github.com/joey0538/nats-jwt-auth/echoserver"
)

func main() {
	ctx := context.Background()

	cfg := natsauth.Config{
		Port:            "9090",
		OIDCIssuerURL:   os.Getenv("OIDC_ISSUER_URL"),
		OIDCAudience:    os.Getenv("OIDC_AUDIENCE"),
		NATSAccountSeed: os.Getenv("NATS_ACCOUNT_SEED"),
		NATSJWTExpiry:   15 * time.Minute,
		TLSSkipVerify:   os.Getenv("TLS_SKIP_VERIFY") == "true",
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	provider := &DBPermissionsProvider{}

	srv, err := echoserver.New(ctx, cfg,
		natsauth.WithLogger(logger),
		natsauth.WithPermissionsProvider(provider),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Mount into an existing Echo server
	e := echo.New()
	e.Use(middleware.Recover())
	e.GET("/api/v1/rooms", listRoomsHandler)
	e.GET("/healthz", func(c echo.Context) error {
		return c.String(200, "ok")
	})
	srv.MountOn(e, "/nats")

	log.Fatal(e.Start(":" + cfg.Port))
}

type DBPermissionsProvider struct{}

func (p *DBPermissionsProvider) GetPermissions(_ context.Context, user natsauth.UserClaims) (natsauth.Permissions, error) {
	// In production, query your DB here:
	//   rooms, err := p.db.GetRoomsForUser(ctx, user.Subject)
	rooms := []string{"room.general", "room.engineering"}

	personal := fmt.Sprintf("user.%s.>", user.Subject)
	subjects := make([]string, 0, len(rooms)+1)
	subjects = append(subjects, rooms...)
	subjects = append(subjects, personal)

	return natsauth.Permissions{
		PubAllow: subjects,
		SubAllow: subjects,
		PubDeny:  []string{"room.announcements", "$SYS.>"},
		SubDeny:  []string{"$SYS.>"},
	}, nil
}

func listRoomsHandler(c echo.Context) error {
	return c.JSON(200, []string{"general", "engineering"})
}
