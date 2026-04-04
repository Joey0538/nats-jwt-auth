// Package echoserver provides a batteries-included Echo HTTP server
// wrapping the natsauth.Authenticator.
//
// Use this when you want a ready-to-run auth service. If you'd rather
// use your own HTTP framework, use natsauth.Authenticator directly.
package echoserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	natsauth "github.com/joey0538/nats-jwt-auth"
)

// Server wraps natsauth.Authenticator with an Echo HTTP server.
//
// Use [Server.Run] for a standalone server, or [Server.MountOn] to embed
// the auth routes into an existing Echo instance. These are mutually
// exclusive — use one or the other, not both.
type Server struct {
	auth *natsauth.Authenticator
	cfg  natsauth.Config
}

// New creates a Server backed by the given config and options.
//
// Usage:
//
//	srv, err := echoserver.New(ctx, cfg,
//	    natsauth.WithPermissionsProvider(myProvider),
//	)
//	srv.Run()           // standalone
//	srv.MountOn(e, "/") // or embed into existing Echo
func New(ctx context.Context, cfg natsauth.Config, opts ...natsauth.Option) (*Server, error) {
	auth, err := natsauth.NewAuthenticator(ctx, cfg, opts...)
	if err != nil {
		return nil, err
	}

	return &Server{
		auth: auth,
		cfg:  cfg,
	}, nil
}

// Authenticator returns the underlying Authenticator.
func (s *Server) Authenticator() *natsauth.Authenticator {
	return s.auth
}

// newEcho creates a fully configured Echo instance with standard middleware.
func (s *Server) newEcho() *echo.Echo {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{"GET", "POST", "OPTIONS"},
		AllowHeaders: []string{"Content-Type", "Authorization"},
	}))
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogStatus:   true,
		LogURI:      true,
		LogMethod:   true,
		LogLatency:  true,
		LogError:    true,
		HandleError: true,
		LogValuesFunc: func(_ echo.Context, v middleware.RequestLoggerValues) error {
			s.auth.Logger().Info("request",
				"method", v.Method,
				"uri", v.URI,
				"status", v.Status,
				"latency_ms", v.Latency.Milliseconds(),
			)
			return nil
		},
	}))
	return e
}

// Run starts a standalone HTTP server and blocks until SIGINT or SIGTERM.
// Do not call both Run and MountOn on the same Server.
func (s *Server) Run() error {
	e := s.newEcho()
	e.POST("/auth", s.handleAuth)
	e.GET("/health", s.handleHealth)

	addr := fmt.Sprintf(":%s", s.cfg.Port)

	srvErr := make(chan error, 1)
	go func() {
		s.auth.Logger().Info("natsauth server starting", "addr", addr)
		srvErr <- e.Start(addr)
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-srvErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("natsauth: listener failed: %w", err)
		}
	case <-quit:
	}

	s.auth.Logger().Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return e.Shutdown(ctx)
}

// MountOn embeds the auth routes into an existing Echo server under a prefix.
// Do not call both Run and MountOn on the same Server.
func (s *Server) MountOn(e *echo.Echo, prefix string) {
	g := e.Group(prefix)
	g.POST("/auth", s.handleAuth)
	g.GET("/health", s.handleHealth)
}

// -----------------------------------------------------------------------
// Echo handlers — thin adapters around Authenticator.Authenticate
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
	Subject          string `json:"sub"`
	Email            string `json:"email"`
	Name             string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	GivenName        string `json:"given_name"`
	FamilyName       string `json:"family_name"`
}

func (s *Server) handleAuth(c echo.Context) error {
	var req authRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	result, err := s.auth.Authenticate(c.Request().Context(), req.SSOToken, req.NATSPublicKey)
	if err != nil {
		return mapAuthError(err)
	}

	return c.JSON(http.StatusOK, authResponse{
		NATSJwt: result.NATSJWT,
		UserInfo: &userInfoResp{
			Subject:          result.User.Subject,
			Email:            result.User.Email,
			Name:             result.User.Name,
			PreferredUsername: result.User.PreferredUsername,
			GivenName:        result.User.GivenName,
			FamilyName:       result.User.FamilyName,
		},
	})
}

func (s *Server) handleHealth(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

func mapAuthError(err error) *echo.HTTPError {
	switch {
	case errors.Is(err, natsauth.ErrMissingToken),
		errors.Is(err, natsauth.ErrMissingNKey),
		errors.Is(err, natsauth.ErrInvalidNKey):
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	case errors.Is(err, natsauth.ErrTokenExpired):
		return echo.NewHTTPError(http.StatusUnauthorized, "SSO token has expired, please re-login")
	case errors.Is(err, natsauth.ErrInvalidToken):
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid SSO token")
	case errors.Is(err, natsauth.ErrAccessDenied):
		return echo.NewHTTPError(http.StatusForbidden, err.Error())
	default:
		return echo.NewHTTPError(http.StatusInternalServerError, "internal server error")
	}
}
