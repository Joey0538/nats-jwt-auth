// Example: every possible override in one place.
//
// This file demonstrates the full customization surface of the natsauth package.
// In practice, you'd only use the overrides you need — this is a reference.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"log/slog"
	"os"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	natsauth "github.com/joey0538/nats-jwt-auth"
)

func main() {
	ctx := context.Background()

	// -----------------------------------------------------------------------
	// Override 1: Config
	//
	// Option A: LoadConfig() reads from env vars + .env files via Viper.
	//   cfg, err := natsauth.LoadConfig()
	//
	// Option B: Build Config manually for full control.
	// -----------------------------------------------------------------------
	cfg := natsauth.Config{
		Port:            "9090",                         // default: "8080"
		OIDCIssuerURL:   os.Getenv("OIDC_ISSUER_URL"),   // required
		OIDCAudience:    os.Getenv("OIDC_AUDIENCE"),     // required
		NATSAccountSeed: os.Getenv("NATS_ACCOUNT_SEED"), // required
		NATSJWTExpiry:   15 * time.Minute,               // default: 1h — shorter = more frequent re-auth

		// Keycloak often sets aud="account" and puts your client_id in "azp".
		// Set this to true to verify azp instead of aud.
		OIDCVerifyAZP: os.Getenv("OIDC_VERIFY_AZP") == "true",

		// Skip TLS cert verification for OIDC issuer (dev only — self-signed certs)
		TLSSkipVerify: os.Getenv("TLS_SKIP_VERIFY") == "true",
	}

	// -----------------------------------------------------------------------
	// Override 2: Logger
	//
	// Default: JSON logger to stdout.
	// Override with any *slog.Logger — text format, custom level, file output, etc.
	// -----------------------------------------------------------------------
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug, // see all logs including debug
	}))

	// -----------------------------------------------------------------------
	// Override 3: PermissionsProvider
	//
	// This is the main thing teams customize. Three patterns:
	//
	//   a) Inline function via PermissionsProviderFunc (quick & simple)
	//   b) Full struct implementing PermissionsProvider (complex logic, testable)
	//   c) DefaultPermissionsProvider (no override — allows chat.>, room.>, user.<sub>.>)
	//
	// Here we show pattern (b) with a DB-backed provider.
	// -----------------------------------------------------------------------
	var db *sql.DB // your database connection
	_ = db         // unused in this example — replace with your real DB

	provider := &DBPermissionsProvider{
		// db: db,
	}

	// -----------------------------------------------------------------------
	// Create server with all overrides
	// -----------------------------------------------------------------------
	srv, err := natsauth.NewServer(ctx, cfg,
		natsauth.WithLogger(logger),
		natsauth.WithPermissionsProvider(provider),
	)
	if err != nil {
		log.Fatal(err)
	}

	// -----------------------------------------------------------------------
	// Override 4: Run mode
	//
	// Option A: srv.Run() — standalone, blocks until SIGTERM.
	//   srv.Run()
	//
	// Option B: srv.MountOn(e, "/prefix") — embed into existing Echo server.
	//   This lets you add the auth endpoint alongside your other APIs.
	// -----------------------------------------------------------------------
	e := echo.New()
	e.Use(middleware.Recover())

	// Your team's existing routes
	e.GET("/api/v1/rooms", listRoomsHandler)
	e.GET("/healthz", func(c echo.Context) error {
		return c.String(200, "ok")
	})

	// Mount natsauth at /nats — adds:
	//   POST /nats/auth    — the auth endpoint
	//   GET  /nats/health  — auth subsystem health check
	srv.MountOn(e, "/nats")

	log.Fatal(e.Start(":" + cfg.Port))
}

// -----------------------------------------------------------------------
// DBPermissionsProvider — full struct implementing PermissionsProvider.
//
// This is the pattern for production use. It's testable (mock the DB),
// and can hold dependencies (DB conn, cache, config).
// -----------------------------------------------------------------------
type DBPermissionsProvider struct {
	// db *sql.DB  // your database connection
}

func (p *DBPermissionsProvider) GetPermissions(_ context.Context, user natsauth.UserClaims) (natsauth.Permissions, error) {
	// -----------------------------------------------------------------------
	// UserClaims fields available from the SSO token:
	//
	//   user.Subject          — unique ID (e.g. "1d85aa54-c9f5-4310-...")
	//   user.Email            — "alice@company.com"
	//   user.Name             — "Alice Engineer"
	//   user.PreferredUsername — "alice"
	//   user.GivenName        — "Alice"
	//   user.FamilyName       — "Engineer"
	//   user.Extra            — map of any other OIDC claims (roles, groups, etc.)
	// -----------------------------------------------------------------------

	// -----------------------------------------------------------------------
	// Error handling:
	//
	//   return natsauth.NewAccessDeniedError("reason") → 403 Forbidden
	//   return fmt.Errorf("db error: %w", err)         → 500 Internal Server Error
	// -----------------------------------------------------------------------

	// Example: block deactivated users with a 403
	// active, err := p.db.QueryRowContext(ctx,
	//     "SELECT active FROM users WHERE id = $1", user.Subject).Scan(&active)
	// if !active {
	//     return natsauth.Permissions{}, natsauth.NewAccessDeniedError("account is deactivated")
	// }

	// Example: look up rooms from your DB
	// rooms, err := p.db.QueryContext(ctx,
	//     "SELECT room_id FROM room_members WHERE user_id = $1", user.Subject)
	// if err != nil {
	//     return natsauth.Permissions{}, err  // generic error → 500
	// }

	// Simulated DB result
	rooms := []string{"room.general", "room.engineering"}

	// No rooms assigned → reject with 403 (not 500)
	if len(rooms) == 0 {
		return natsauth.Permissions{}, natsauth.NewAccessDeniedError("no rooms assigned")
	}
	subs := make([]string, 0, len(rooms)+1)
	pubs := make([]string, 0, len(rooms)+1)

	for _, room := range rooms {
		subs = append(subs, room)
		pubs = append(pubs, room)
	}

	// Everyone gets their personal inbox
	personal := fmt.Sprintf("user.%s.>", user.Subject)
	subs = append(subs, personal)
	pubs = append(pubs, personal)

	// -----------------------------------------------------------------------
	// Permissions fields:
	//
	//   PubAllow — subjects this user CAN publish to
	//   SubAllow — subjects this user CAN subscribe to
	//   PubDeny  — subjects explicitly BLOCKED from publishing (optional)
	//   SubDeny  — subjects explicitly BLOCKED from subscribing (optional)
	//
	// Deny takes precedence over Allow.
	// Supports NATS wildcards: "room.>" matches room.general, room.eng, etc.
	//                          "room.*" matches one level only.
	// -----------------------------------------------------------------------
	return natsauth.Permissions{
		PubAllow: pubs,
		SubAllow: subs,

		// Deny overrides — useful for blocking specific subjects even
		// when a wildcard Allow would match them.
		PubDeny: []string{
			"room.announcements", // read-only channel, nobody publishes
			"$SYS.>",             // block system subjects
		},
		SubDeny: []string{
			"$SYS.>", // block system subjects
		},
	}, nil
}

func listRoomsHandler(c echo.Context) error {
	return c.JSON(200, []string{"general", "engineering"})
}
