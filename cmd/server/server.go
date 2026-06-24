package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	natsauth "github.com/joey0538/nats-jwt-auth"
)

// app is the auth-service HTTP application: the framework-agnostic
// Authenticator core plus the operational concerns (metrics, health checks,
// structured logging) that make it Kubernetes-ready.
type app struct {
	auth    *natsauth.Authenticator
	metrics *metrics
	health  *Health
	logger  *slog.Logger
}

// run builds the Echo server, registers routes and middleware, and blocks until
// SIGINT/SIGTERM, then shuts down gracefully.
func (a *app) run(port string) error {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{"GET", "POST", "OPTIONS"},
		AllowHeaders: []string{"Content-Type", "Authorization"},
	}))
	e.Use(a.requestLogger())
	e.Use(a.httpMetrics())

	// Business API.
	e.POST("/auth", a.handleAuth)

	// Kubernetes probes (served on the main API port).
	e.GET("/healthz/live", a.handleLive)
	e.GET("/healthz/ready", a.handleReady)

	// Backward-compatible legacy health endpoint (unchanged static JSON).
	e.GET("/health", a.handleHealthLegacy)

	// Note: Prometheus /metrics is served by the o11y SDK on its own port
	// (METRICS_ADDR, default :2112), not here.

	addr := fmt.Sprintf(":%s", port)
	srvErr := make(chan error, 1)
	go func() {
		a.logger.Info("auth-service starting", "addr", addr)
		srvErr <- e.Start(addr)
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-srvErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("listener failed: %w", err)
		}
	case <-quit:
	}

	a.logger.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return e.Shutdown(ctx)
}

// handleLive is the liveness probe: it answers "is the process alive?" and does
// no dependency checks, so it stays cheap (<100ms) and a failing dependency can
// never trigger a pod restart.
func (a *app) handleLive(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "alive"})
}

// handleReady is the readiness probe: it runs every dependency check and returns
// 200 when all pass, or 503 with the failing dependency(ies) marked "failed".
func (a *app) handleReady(c echo.Context) error {
	report := a.health.Check(c.Request().Context())

	status := http.StatusOK
	overall := "ready"
	if !report.Healthy {
		status = http.StatusServiceUnavailable
		overall = "not_ready"
	}
	return c.JSON(status, map[string]any{
		"status": overall,
		"checks": report.Checks,
	})
}

// handleHealthLegacy preserves the original /health endpoint for backward
// compatibility — the same static JSON the echoserver returned.
func (a *app) handleHealthLegacy(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

// isProbePath reports whether a route is a health/probe endpoint. Probes are
// excluded from request metrics and logs so they don't drown out real traffic.
func isProbePath(route string) bool {
	return route == "/health" || strings.HasPrefix(route, "/healthz/")
}

// httpMetrics records the HTTP golden-signal metrics for every non-probe
// request, labelled by method, route template and response status.
func (a *app) httpMetrics() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()
			err := next(c)

			route := c.Path()
			if isProbePath(route) {
				return err
			}
			if route == "" {
				route = "unmatched"
			}
			a.metrics.recordHTTP(
				c.Request().Context(),
				c.Request().Method,
				route,
				statusFromResult(c, err),
				time.Since(start).Seconds(),
			)
			return err
		}
	}
}

// requestLogger emits one structured log line per non-probe request. Because
// slog.Default is the SDK logger, each line is enriched with traceId/spanId
// when a span is active.
func (a *app) requestLogger() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()
			err := next(c)
			if isProbePath(c.Path()) {
				return err
			}
			a.logger.InfoContext(c.Request().Context(), "request",
				"method", c.Request().Method,
				"uri", c.Request().RequestURI,
				"status", statusFromResult(c, err),
				"latency_ms", time.Since(start).Milliseconds(),
			)
			return err
		}
	}
}

// statusFromResult resolves the response status code, accounting for handlers
// that returned an echo.HTTPError before the response was committed.
func statusFromResult(c echo.Context, err error) int {
	if err == nil {
		return c.Response().Status
	}
	var he *echo.HTTPError
	if errors.As(err, &he) {
		return he.Code
	}
	return http.StatusInternalServerError
}
