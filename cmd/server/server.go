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
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	natsauth "github.com/joey0538/nats-jwt-auth"
)

// app is the auth-service HTTP application: the framework-agnostic
// Authenticator core plus the operational concerns (metrics, health checks,
// structured logging) that make it Kubernetes-ready.
type app struct {
	auth     *natsauth.Authenticator
	metrics  *metrics
	logger   *slog.Logger
	checkers []checker
}

// run builds the Echo server, registers routes and middleware, and blocks
// until SIGINT/SIGTERM, then shuts down gracefully.
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
	e.GET("/healthz/live", handleLive)
	e.GET("/healthz/ready", handleReady(a.checkers))

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

// isProbePath reports whether a route is a Kubernetes probe. Probes are
// excluded from request metrics and logs so they don't drown out real traffic.
func isProbePath(route string) bool {
	return strings.HasPrefix(route, "/healthz/")
}

// httpMetrics records auth_http_requests_total and
// auth_http_request_duration_seconds for every non-probe request, labelled by
// method, route template and response status.
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

			attrs := metric.WithAttributes(
				attribute.String("http.request.method", c.Request().Method),
				attribute.String("http.route", route),
				attribute.Int("http.response.status_code", statusFromResult(c, err)),
			)
			ctx := c.Request().Context()
			a.metrics.httpRequests.Add(ctx, 1, attrs)
			a.metrics.httpDuration.Record(ctx, time.Since(start).Seconds(), attrs)
			return err
		}
	}
}

// requestLogger emits one structured log line per non-probe request. Because
// slog.Default is the SDK logger, each line is automatically enriched with
// traceId/spanId when a span is active.
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
