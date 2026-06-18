package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
)

// checker is a single named readiness dependency. Check returns nil when the
// dependency is healthy, or an error describing why it is not. Add a new
// dependency by appending another checker — nothing else needs to change.
type checker struct {
	name  string
	check func(ctx context.Context) error
}

// handleLive is the Kubernetes liveness probe. It answers "is the process
// alive?" and therefore performs no dependency checks — a failing dependency
// must not cause the pod to be restarted. It returns 200 as long as the
// process can serve HTTP.
func handleLive(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "alive"})
}

// handleReady is the Kubernetes readiness probe. It answers "can this instance
// serve traffic right now?" by running every registered dependency check.
//
//	all checks pass  → 200 {"status":"ready",     "checks":{...}}
//	any check fails  → 503 {"status":"not_ready", "checks":{...}}
//
// A 503 makes Kubernetes stop routing traffic to the pod without restarting
// it, so the instance recovers automatically once its dependencies do.
func handleReady(checkers []checker) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		checks := make(map[string]string, len(checkers))
		ready := true

		for _, ch := range checkers {
			if err := ch.check(ctx); err != nil {
				checks[ch.name] = "unhealthy: " + err.Error()
				ready = false
				continue
			}
			checks[ch.name] = "ok"
		}

		status := http.StatusOK
		overall := "ready"
		if !ready {
			status = http.StatusServiceUnavailable
			overall = "not_ready"
		}

		return c.JSON(status, map[string]any{
			"status": overall,
			"checks": checks,
		})
	}
}

// newSSOChecker verifies the OIDC/SSO provider is reachable by fetching its
// discovery document. This is the auth-service's only hard runtime
// dependency: without it, no SSO token can be validated. The check is bounded
// by timeout so the probe can never hang.
func newSSOChecker(issuerURL string, timeout time.Duration) checker {
	url := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-configuration"
	return checker{
		name: "sso",
		check: func(ctx context.Context) error {
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return err
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("discovery returned status %d", resp.StatusCode)
			}
			return nil
		},
	}
}

// newNATSChecker is an extensibility stub. The auth-service currently signs
// NATS user JWTs offline using an account seed — there is no live NATS
// connection to probe. When a live NATS dependency is introduced, replace the
// body below with a real connection/RTT check and enable it via
// NATS_HEALTH_ENABLED. It is intentionally OFF by default so readiness never
// reports a dependency it does not actually verify.
func newNATSChecker() checker {
	return checker{
		name: "nats",
		check: func(_ context.Context) error {
			// TODO: ping the live NATS connection once one exists.
			return nil
		},
	}
}

// newMongoChecker is an extensibility stub. The auth-service does not use
// MongoDB today. When a Mongo dependency is added, replace the body with a
// real ping (e.g. client.Ping) and enable it via MONGO_HEALTH_ENABLED. OFF by
// default for the same honesty reason as the NATS stub.
func newMongoChecker() checker {
	return checker{
		name: "mongo",
		check: func(_ context.Context) error {
			// TODO: client.Ping(ctx, nil) once a Mongo dependency exists.
			return nil
		},
	}
}
