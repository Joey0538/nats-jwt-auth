package natsauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/nats-io/nkeys"

	internaljwt "github.com/joey0538/nats-jwt-auth/internal/jwt"
	internaloidc "github.com/joey0538/nats-jwt-auth/internal/oidc"
)

// Server is the ready-to-run NATS auth HTTP server.
// Teams create one via NewServer() and call Run() to start it.
type Server struct {
	permissions PermissionsProvider
	validator   *internaloidc.Validator
	signer      *internaljwt.Signer
	echo        *echo.Echo
	logger      *slog.Logger
	cfg         Config
}

// Option is a functional option for customizing the server.
type Option func(*Server)

// WithPermissionsProvider lets teams plug in their own logic for
// determining what NATS subjects each user can access.
//
// If not provided, DefaultPermissionsProvider is used.
func WithPermissionsProvider(p PermissionsProvider) Option {
	return func(s *Server) {
		s.permissions = p
	}
}

// WithLogger lets teams bring their own slog.Logger.
func WithLogger(l *slog.Logger) Option {
	return func(s *Server) {
		s.logger = l
	}
}

// NewServer initializes the auth server with the given config and options.
// It connects to your OIDC provider at startup — fails fast if unreachable.
//
// Usage:
//
//	srv, err := natsauth.NewServer(ctx, natsauth.Config{
//	    OIDCIssuerURL:   "https://sso.company.com/realms/my-realm",
//	    OIDCAudience:    "my-chat-app",
//	    NATSAccountSeed: "SA...",
//	    NATSJWTExpiry:   time.Hour,
//	}, natsauth.WithPermissionsProvider(myProvider))
func NewServer(ctx context.Context, cfg Config, opts ...Option) (*Server, error) {
	cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	s := &Server{
		cfg:         cfg,
		permissions: DefaultPermissionsProvider{},
		logger:      slog.New(slog.NewJSONHandler(os.Stdout, nil)),
	}

	for _, opt := range opts {
		opt(s)
	}

	// Connect to OIDC provider — fetches JWKS keys for token verification
	validator, err := internaloidc.NewValidator(ctx, internaloidc.ValidatorConfig{
		IssuerURL:        cfg.OIDCIssuerURL,
		Audience:         cfg.OIDCAudience,
		TLSSkipVerify:    cfg.TLSSkipVerify,
		VerifyAZP:        cfg.OIDCVerifyAZP,
		DiscoveryTimeout: cfg.OIDCDiscoveryTimeout,
	})
	if err != nil {
		return nil, err
	}
	s.validator = validator

	// Load NATS account keypair for signing JWTs
	signer, err := internaljwt.NewSigner(cfg.NATSAccountSeed, cfg.NATSJWTExpiry)
	if err != nil {
		return nil, err
	}
	s.signer = signer

	// Wire up Echo
	s.echo = echo.New()
	s.echo.HideBanner = true
	s.echo.HidePort = true
	s.echo.Use(middleware.Recover())
	s.echo.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{"GET", "POST", "OPTIONS"},
		AllowHeaders: []string{"Content-Type", "Authorization"},
	}))
	s.echo.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogStatus:   true,
		LogURI:      true,
		LogMethod:   true,
		LogLatency:  true,
		LogError:    true,
		HandleError: true,
		LogValuesFunc: func(_ echo.Context, v middleware.RequestLoggerValues) error {
			s.logger.Info("request",
				"method", v.Method,
				"uri", v.URI,
				"status", v.Status,
				"latency_ms", v.Latency.Milliseconds(),
			)
			return nil
		},
	}))

	s.registerRoutes()

	return s, nil
}

// Run starts the HTTP server and blocks until SIGINT or SIGTERM.
// This is the typical usage for teams running this as a standalone service.
func (s *Server) Run() error {
	addr := fmt.Sprintf(":%s", s.cfg.Port)

	srvErr := make(chan error, 1)
	go func() {
		s.logger.Info("natsauth server starting", "addr", addr)
		srvErr <- s.echo.Start(addr)
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-srvErr:
		// Listener failed (e.g. port in use). If it's a graceful shutdown, fall through.
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("natsauth: listener failed: %w", err)
		}
	case <-quit:
		// Received shutdown signal — graceful shutdown.
	}

	s.logger.Info("shutting down gracefully...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return s.echo.Shutdown(ctx)
}

// MountOn embeds the auth routes into an existing Echo server under a prefix.
//
// Usage:
//
//	e := echo.New()
//	e.GET("/other-endpoint", myHandler)
//	srv.MountOn(e, "/nats")
func (s *Server) MountOn(e *echo.Echo, prefix string) {
	g := e.Group(prefix)
	g.POST("/auth", s.handleAuth)
	g.GET("/health", s.handleHealth)
}

func (s *Server) registerRoutes() {
	s.echo.POST("/auth", s.handleAuth)
	s.echo.GET("/health", s.handleHealth)
}

// -----------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------

type authRequest struct {
	SSOToken      string `json:"sso_token"`
	NATSPublicKey string `json:"nats_public_key"`
}

type authResponse struct {
	UserInfo *userInfoResp `json:"user"`
	NATSJwt  string        `json:"nats_jwt"`
}

type userInfoResp struct {
	Subject           string `json:"sub"`
	Email             string `json:"email"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
}

func (s *Server) handleAuth(c echo.Context) error {
	var req authRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.SSOToken == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "sso_token is required")
	}
	if req.NATSPublicKey == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "nats_public_key is required")
	}
	if !nkeys.IsValidPublicUserKey(req.NATSPublicKey) {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid nats_public_key format")
	}

	// Step 1: Validate SSO token
	oidcClaims, err := s.validator.Validate(c.Request().Context(), req.SSOToken)
	if err != nil {
		if errors.Is(err, internaloidc.ErrTokenExpired) {
			s.logger.Warn("SSO token expired", "error", err)
			return echo.NewHTTPError(http.StatusUnauthorized, "SSO token has expired, please re-login")
		}
		s.logger.Error("OIDC validation failed", "error", err)
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid SSO token")
	}

	userClaims := UserClaims{
		Subject:           oidcClaims.Subject,
		Email:             oidcClaims.Email,
		Name:              oidcClaims.Name,
		PreferredUsername: oidcClaims.PreferredUsername,
		GivenName:         oidcClaims.GivenName,
		FamilyName:        oidcClaims.FamilyName,
		Extra:             oidcClaims.Extra,
	}

	// Step 2: Ask the team's PermissionsProvider what this user can access
	perms, err := s.permissions.GetPermissions(c.Request().Context(), userClaims)
	if err != nil {
		if errors.Is(err, ErrAccessDenied) {
			s.logger.Warn("access denied", "error", err, "subject", userClaims.Subject)
			return echo.NewHTTPError(http.StatusForbidden, err.Error())
		}
		s.logger.Error("permissions lookup failed", "error", err, "subject", userClaims.Subject)
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to resolve permissions")
	}

	// Step 3: Sign the NATS JWT with the team's account private key
	natsJWT, err := s.signer.Sign(req.NATSPublicKey, userClaims.Subject, internaljwt.UserPermissions{
		PubAllow: perms.PubAllow,
		SubAllow: perms.SubAllow,
		PubDeny:  perms.PubDeny,
		SubDeny:  perms.SubDeny,
	})
	if err != nil {
		s.logger.Error("JWT signing failed", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to generate NATS token")
	}

	return c.JSON(http.StatusOK, authResponse{
		NATSJwt: natsJWT,
		UserInfo: &userInfoResp{
			Subject:           oidcClaims.Subject,
			Email:             oidcClaims.Email,
			Name:              oidcClaims.Name,
			PreferredUsername: oidcClaims.PreferredUsername,
			GivenName:         oidcClaims.GivenName,
			FamilyName:        oidcClaims.FamilyName,
		},
	})
}

func (s *Server) handleHealth(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}
