package main

import (
	"context"
	"log"
	"log/slog"
	"os"
	"time"

	natsauth "github.com/joey0538/nats-jwt-auth"
	"github.com/joey0538/nats-jwt-auth/viperconfig"
)

func main() {
	ctx := context.Background()

	cfg, err := viperconfig.LoadConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	oc := loadObsConfig()

	// Bring up observability first so everything below is traced/logged/metered.
	obs, m, err := initObservability(ctx, oc)
	if err != nil {
		log.Fatalf("observability: %v", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = obs.Shutdown(shutdownCtx)
	}()

	// Route the standard library / natsauth logs through the enriched SDK logger.
	slog.SetDefault(obs.Logger)

	auth, err := natsauth.NewAuthenticator(ctx, cfg)
	if err != nil {
		obs.Logger.Error("failed to initialize authenticator", "error", err)
		os.Exit(1)
	}

	// Readiness checks. TSSO is the only dependency with a live client in this
	// repository. When MongoDB / NATS clients are wired into the service, add
	// their checkers here — both accept an injected client behind an interface:
	//
	//	NewMongoChecker(mongoAdapter{client}, oc.ReadyTimeout)
	//	NewNATSChecker(natsConn)
	checkers := []Checker{
		NewTSSOChecker(cfg.OIDCIssuerURL, oc.ReadyTimeout),
	}

	application := &app{
		auth:    auth,
		metrics: m,
		health:  NewHealth(checkers...),
		logger:  obs.Logger,
	}

	if err := application.run(cfg.Port); err != nil {
		obs.Logger.Error("server error", "error", err)
		os.Exit(1)
	}
}
