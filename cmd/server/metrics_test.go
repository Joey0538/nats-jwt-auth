package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestMetricsExposed verifies the application instruments surface on the SDK's
// Prometheus endpoint under their expected names, labels, and buckets.
func TestMetricsExposed(t *testing.T) {
	// Keep the test hermetic: no OTLP collector runs locally.
	t.Setenv("O11Y_TRACE_ENABLED", "false")
	t.Setenv("O11Y_LOG_ENABLED", "false")

	oc := obsConfig{
		ServiceName:      "auth-service-test",
		ServiceVersion:   "0.0.0",
		ServiceNamespace: "platform",
		Environment:      "testing",
		MetricsAddr:      "127.0.0.1:22112",
	}

	ctx := context.Background()
	obs, m, err := initObservability(ctx, oc)
	if err != nil {
		t.Fatalf("initObservability: %v", err)
	}
	defer func() { _ = obs.Shutdown(ctx) }()

	// Exercise every instrument once.
	m.recordHTTP(ctx, "POST", "/auth", 200, 0.012)
	m.recordAuthentication(ctx, "tsso", "success")
	m.recordTokenIssued(ctx, "nats")
	m.recordTokenValidation(ctx, "valid")

	body := scrapeMetrics(t, "http://127.0.0.1:22112/metrics")

	wantContains := []string{
		// names
		"auth_http_requests_total",
		"auth_http_request_duration_seconds",
		"auth_authentication_total",
		"auth_token_issued_total",
		"auth_token_validation_total",
		// spec labels
		`method="POST"`,
		`path="/auth"`,
		`status="200"`,
		`provider="tsso"`,
		`type="nats"`,
		// SRE-standard histogram bucket
		`le="0.01"`,
		// resource attribute became a constant label
		`service_name="auth-service-test"`,
	}
	for _, w := range wantContains {
		if !strings.Contains(body, w) {
			t.Errorf("metrics output missing %q", w)
		}
	}

	// The 0.005 bucket must NOT be present — the ticket's buckets start at 0.01.
	if strings.Contains(body, `le="0.005"`) {
		t.Error("unexpected le=\"0.005\" bucket; ticket buckets start at 0.01")
	}
}

func scrapeMetrics(t *testing.T, url string) string {
	t.Helper()
	var lastErr error
	for i := 0; i < 20; i++ {
		resp, err := http.Get(url) //nolint:gosec // fixed localhost test URL
		if err != nil {
			lastErr = err
			time.Sleep(50 * time.Millisecond)
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return string(b)
	}
	t.Fatalf("could not scrape %s: %v", url, lastErr)
	return ""
}
